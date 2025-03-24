// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build !nogcs
// +build !nogcs

package vfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/pkg/sftp"
	"github.com/rs/xid"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	defaultGCSPageSize = 5000
)

var (
	gcsDefaultFieldsSelection = []string{"Name", "Size", "Deleted", "Updated", "ContentType", "Metadata"}
)

// GCSFs is a Fs implementation for Google Cloud Storage.
type GCSFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath      string
	config         *GCSFsConfig
	svc            *storage.Client
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

func init() {
	version.AddFeature("+gcs")
}

// NewGCSFs returns an GCSFs object that allows to interact with Google Cloud Storage
func NewGCSFs(connectionID, localTempDir, mountPath string, config GCSFsConfig) (Fs, error) {
	if localTempDir == "" {
		localTempDir = getLocalTempDir()
	}

	var err error
	fs := &GCSFs{
		connectionID:   connectionID,
		localTempDir:   localTempDir,
		mountPath:      getMountPath(mountPath),
		config:         &config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
	if err = fs.config.validate(); err != nil {
		return fs, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if fs.config.AutomaticCredentials > 0 {
		fs.svc, err = storage.NewClient(ctx,
			storage.WithJSONReads(),
			option.WithUserAgent(version.GetVersionHash()),
		)
	} else {
		err = fs.config.Credentials.TryDecrypt()
		if err != nil {
			return fs, err
		}
		fs.svc, err = storage.NewClient(ctx,
			storage.WithJSONReads(),
			option.WithUserAgent(version.GetVersionHash()),
			option.WithCredentialsJSON([]byte(fs.config.Credentials.GetPayload())),
		)
	}
	return fs, err
}

// Name returns the name for the Fs implementation
func (fs *GCSFs) Name() string {
	return fmt.Sprintf("%s bucket %q", gcsfsName, fs.config.Bucket)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *GCSFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *GCSFs) Stat(name string) (os.FileInfo, error) {
	if name == "" || name == "/" || name == "." {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	}
	return fs.getObjectStat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs *GCSFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *GCSFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	r, w, err := createPipeFn(fs.localTempDir, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)
	if readMetadata > 0 {
		attrs, err := fs.headObject(name)
		if err != nil {
			r.Close()
			w.Close()
			return nil, nil, nil, err
		}
		p.setMetadata(attrs.Metadata)
	}
	bkt := fs.svc.Bucket(fs.config.Bucket)
	obj := bkt.Object(name)
	ctx, cancelFn := context.WithCancel(context.Background())
	objectReader, err := obj.NewRangeReader(ctx, offset, -1)
	if err == nil && offset > 0 && objectReader.Attrs.ContentEncoding == "gzip" {
		err = fmt.Errorf("range request is not possible for gzip content encoding, requested offset %d", offset)
		objectReader.Close()
	}
	if err != nil {
		r.Close()
		w.Close()
		cancelFn()
		return nil, nil, nil, err
	}
	go func() {
		defer cancelFn()
		defer objectReader.Close()

		n, err := io.Copy(w, objectReader)
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %+v", name, n, err)
		metric.GCSTransferCompleted(n, 1, err)
	}()
	return nil, p, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *GCSFs) Create(name string, flag, checks int) (File, PipeWriter, func(), error) {
	if checks&CheckParentDir != 0 {
		_, err := fs.Stat(path.Dir(name))
		if err != nil {
			return nil, nil, nil, err
		}
	}
	chunkSize := googleapi.DefaultUploadChunkSize
	if fs.config.UploadPartSize > 0 {
		chunkSize = int(fs.config.UploadPartSize) * 1024 * 1024
	}
	r, w, err := createPipeFn(fs.localTempDir, int64(chunkSize+1024*1024))
	if err != nil {
		return nil, nil, nil, err
	}
	var partialFileName string
	var attrs *storage.ObjectAttrs
	var statErr error

	bkt := fs.svc.Bucket(fs.config.Bucket)
	obj := bkt.Object(name)

	if flag == -1 {
		obj = obj.If(storage.Conditions{DoesNotExist: true})
	} else {
		attrs, statErr = fs.headObject(name)
		if statErr == nil {
			obj = obj.If(storage.Conditions{GenerationMatch: attrs.Generation})
		} else if fs.IsNotExist(statErr) {
			obj = obj.If(storage.Conditions{DoesNotExist: true})
		} else {
			fsLog(fs, logger.LevelWarn, "unable to set precondition for %q, stat err: %v", name, statErr)
		}
	}
	ctx, cancelFn := context.WithCancel(context.Background())

	var p PipeWriter
	var objectWriter *storage.Writer
	if checks&CheckResume != 0 {
		if statErr != nil {
			cancelFn()
			r.Close()
			w.Close()
			return nil, nil, nil, fmt.Errorf("unable to resume %q stat error: %w", name, statErr)
		}
		p = newPipeWriterAtOffset(w, attrs.Size)
		partialFileName = fs.getTempObject(name)
		partialObj := bkt.Object(partialFileName)
		partialObj = partialObj.If(storage.Conditions{DoesNotExist: true})
		objectWriter = partialObj.NewWriter(ctx)
	} else {
		p = NewPipeWriter(w)
		objectWriter = obj.NewWriter(ctx)
	}

	objectWriter.ChunkSize = chunkSize
	if fs.config.UploadPartMaxTime > 0 {
		objectWriter.ChunkRetryDeadline = time.Duration(fs.config.UploadPartMaxTime) * time.Second
	}
	fs.setWriterAttrs(objectWriter, flag, name)

	go func() {
		defer cancelFn()

		n, err := io.Copy(objectWriter, r)
		closeErr := objectWriter.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil && partialFileName != "" {
			partialObject := bkt.Object(partialFileName)
			partialObject = partialObject.If(storage.Conditions{GenerationMatch: objectWriter.Attrs().Generation})
			err = fs.composeObjects(ctx, obj, partialObject)
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, acl: %q, readed bytes: %v, err: %+v",
			name, fs.config.ACL, n, err)
		metric.GCSTransferCompleted(n, 0, err)
	}()

	if uploadMode&8 != 0 {
		return nil, p, nil, nil
	}
	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
func (fs *GCSFs) Rename(source, target string, checks int) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	if checks&CheckParentDir != 0 {
		_, err := fs.Stat(path.Dir(target))
		if err != nil {
			return -1, -1, err
		}
	}
	fi, err := fs.getObjectStat(source)
	if err != nil {
		return -1, -1, err
	}
	return fs.renameInternal(source, target, fi, 0, checks&CheckUpdateModTime != 0)
}

// Remove removes the named file or (empty) directory.
func (fs *GCSFs) Remove(name string, isDir bool) error {
	if isDir {
		hasContents, err := fs.hasContents(name)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("cannot remove non empty directory: %q", name)
		}
		if !strings.HasSuffix(name, "/") {
			name += "/"
		}
	}
	obj := fs.svc.Bucket(fs.config.Bucket).Object(name)
	attrs, statErr := fs.headObject(name)
	if statErr == nil {
		obj = obj.If(storage.Conditions{GenerationMatch: attrs.Generation})
	} else {
		fsLog(fs, logger.LevelWarn, "unable to set precondition for deleting %q, stat err: %v",
			name, statErr)
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	err := obj.Delete(ctx)
	if isDir && fs.IsNotExist(err) {
		// we can have directories without a trailing "/" (created using v2.1.0 and before)
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		err = fs.svc.Bucket(fs.config.Bucket).Object(strings.TrimSuffix(name, "/")).Delete(ctx)
	}
	metric.GCSDeleteObjectCompleted(err)
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *GCSFs) Mkdir(name string) error {
	_, err := fs.Stat(name)
	if !fs.IsNotExist(err) {
		return err
	}
	return fs.mkdirInternal(name)
}

// Symlink creates source as a symbolic link to target.
func (*GCSFs) Symlink(_, _ string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*GCSFs) Readlink(_ string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*GCSFs) Chown(_ string, _ int, _ int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*GCSFs) Chmod(_ string, _ os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (fs *GCSFs) Chtimes(name string, _, mtime time.Time, isUploading bool) error {
	if isUploading {
		return nil
	}
	obj := fs.svc.Bucket(fs.config.Bucket).Object(name)
	attrs, err := fs.headObject(name)
	if err != nil {
		return err
	}
	obj = obj.If(storage.Conditions{MetagenerationMatch: attrs.Metageneration})

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	metadata := attrs.Metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata[lastModifiedField] = strconv.FormatInt(mtime.UnixMilli(), 10)

	objectAttrsToUpdate := storage.ObjectAttrsToUpdate{
		Metadata: metadata,
	}
	_, err = obj.Update(ctx, objectAttrsToUpdate)

	return err
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (*GCSFs) Truncate(_ string, _ int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *GCSFs) ReadDir(dirname string) (DirLister, error) {
	// dirname must be already cleaned
	prefix := fs.getPrefix(dirname)
	query := &storage.Query{Prefix: prefix, Delimiter: "/"}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return nil, err
	}
	bkt := fs.svc.Bucket(fs.config.Bucket)

	return &gcsDirLister{
		bucket:   bkt,
		query:    query,
		timeout:  fs.ctxTimeout,
		prefix:   prefix,
		prefixes: make(map[string]bool),
	}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on GCS
func (*GCSFs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (*GCSFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return true
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// S3 uploads are already atomic, we don't need to upload to a temporary
// file
func (*GCSFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*GCSFs) IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if err == storage.ErrObjectNotExist || err == storage.ErrBucketNotExist {
		return true
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Code == http.StatusNotFound {
			return true
		}
	}
	return false
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*GCSFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Code == http.StatusForbidden || apiErr.Code == http.StatusUnauthorized {
			return true
		}
	}
	return false
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*GCSFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrVfsUnsupported)
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *GCSFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "", nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *GCSFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize(fs.config.KeyPrefix)
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *GCSFs) GetDirSize(dirname string) (int, int64, error) {
	prefix := fs.getPrefix(dirname)
	numFiles := 0
	size := int64(0)

	query := &storage.Query{Prefix: prefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return numFiles, size, err
	}

	iteratePage := func(nextPageToken string) (string, error) {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		bkt := fs.svc.Bucket(fs.config.Bucket)
		it := bkt.Objects(ctx, query)
		pager := iterator.NewPager(it, defaultGCSPageSize, nextPageToken)

		var objects []*storage.ObjectAttrs
		pageToken, err := pager.NextPage(&objects)
		if err != nil {
			return pageToken, err
		}
		for _, attrs := range objects {
			if !attrs.Deleted.IsZero() {
				continue
			}
			isDir := strings.HasSuffix(attrs.Name, "/") || attrs.ContentType == dirMimeType
			if isDir && attrs.Size == 0 {
				continue
			}
			numFiles++
			size += attrs.Size
		}
		return pageToken, nil
	}

	pageToken := ""
	for {
		pageToken, err = iteratePage(pageToken)
		if err != nil {
			metric.GCSListObjectsCompleted(err)
			return numFiles, size, err
		}
		fsLog(fs, logger.LevelDebug, "scan in progress for %q, files: %d, size: %d", dirname, numFiles, size)
		if pageToken == "" {
			break
		}
	}

	metric.GCSListObjectsCompleted(nil)
	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// GCS uploads are already atomic, we never call this method for GCS
func (*GCSFs) GetAtomicUploadPath(_ string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *GCSFs) GetRelativePath(name string) string {
	rel := path.Clean(name)
	if rel == "." {
		rel = ""
	}
	if !path.IsAbs(rel) {
		rel = "/" + rel
	}
	if fs.config.KeyPrefix != "" {
		if !strings.HasPrefix(rel, "/"+fs.config.KeyPrefix) {
			rel = "/"
		}
		rel = path.Clean("/" + strings.TrimPrefix(rel, "/"+fs.config.KeyPrefix))
	}
	if fs.mountPath != "" {
		rel = path.Join(fs.mountPath, rel)
	}
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root
func (fs *GCSFs) Walk(root string, walkFn filepath.WalkFunc) error {
	prefix := fs.getPrefix(root)

	query := &storage.Query{Prefix: prefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		walkFn(root, nil, err) //nolint:errcheck
		return err
	}

	iteratePage := func(nextPageToken string) (string, error) {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		bkt := fs.svc.Bucket(fs.config.Bucket)
		it := bkt.Objects(ctx, query)
		pager := iterator.NewPager(it, defaultGCSPageSize, nextPageToken)

		var objects []*storage.ObjectAttrs
		pageToken, err := pager.NextPage(&objects)
		if err != nil {
			walkFn(root, nil, err) //nolint:errcheck
			return pageToken, err
		}
		for _, attrs := range objects {
			if !attrs.Deleted.IsZero() {
				continue
			}
			name, isDir := fs.resolve(attrs.Name, prefix, attrs.ContentType)
			if name == "" {
				continue
			}
			objectModTime := attrs.Updated
			if val := getLastModified(attrs.Metadata); val > 0 {
				objectModTime = util.GetTimeFromMsecSinceEpoch(val)
			}
			err = walkFn(attrs.Name, NewFileInfo(name, isDir, attrs.Size, objectModTime, false), nil)
			if err != nil {
				return pageToken, err
			}
		}

		return pageToken, nil
	}

	pageToken := ""
	for {
		pageToken, err = iteratePage(pageToken)
		if err != nil {
			metric.GCSListObjectsCompleted(err)
			return err
		}
		if pageToken == "" {
			break
		}
	}

	walkFn(root, NewFileInfo(root, true, 0, time.Unix(0, 0), false), err) //nolint:errcheck
	metric.GCSListObjectsCompleted(err)
	return err
}

// Join joins any number of path elements into a single path
func (*GCSFs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (GCSFs) HasVirtualFolders() bool {
	return true
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *GCSFs) ResolvePath(virtualPath string) (string, error) {
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return fs.Join(fs.config.KeyPrefix, strings.TrimPrefix(virtualPath, "/")), nil
}

// CopyFile implements the FsFileCopier interface
func (fs *GCSFs) CopyFile(source, target string, srcInfo os.FileInfo) (int, int64, error) {
	numFiles := 1
	sizeDiff := srcInfo.Size()
	var conditions *storage.Conditions
	attrs, err := fs.headObject(target)
	if err == nil {
		sizeDiff -= attrs.Size
		numFiles = 0
		conditions = &storage.Conditions{GenerationMatch: attrs.Generation}
	} else {
		if !fs.IsNotExist(err) {
			return 0, 0, err
		}
		conditions = &storage.Conditions{DoesNotExist: true}
	}
	if err := fs.copyFileInternal(source, target, conditions, srcInfo, true); err != nil {
		return 0, 0, err
	}
	return numFiles, sizeDiff, nil
}

func (fs *GCSFs) resolve(name, prefix, contentType string) (string, bool) {
	result := strings.TrimPrefix(name, prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	if contentType == dirMimeType {
		isDir = true
	}
	return result, isDir
}

// getObjectStat returns the stat result
func (fs *GCSFs) getObjectStat(name string) (os.FileInfo, error) {
	attrs, err := fs.headObject(name)
	if err == nil {
		objSize := attrs.Size
		objectModTime := attrs.Updated
		if val := getLastModified(attrs.Metadata); val > 0 {
			objectModTime = util.GetTimeFromMsecSinceEpoch(val)
		}
		isDir := attrs.ContentType == dirMimeType || strings.HasSuffix(attrs.Name, "/")
		info := NewFileInfo(name, isDir, objSize, objectModTime, false)
		if !isDir {
			info.setMetadata(attrs.Metadata)
		}
		return info, nil
	}
	if !fs.IsNotExist(err) {
		return nil, err
	}
	// now check if this is a prefix (virtual directory)
	hasContents, err := fs.hasContents(name)
	if err != nil {
		return nil, err
	}
	if hasContents {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	}
	// finally check if this is an object with a trailing /
	attrs, err = fs.headObject(name + "/")
	if err != nil {
		return nil, err
	}
	objectModTime := attrs.Updated
	if val := getLastModified(attrs.Metadata); val > 0 {
		objectModTime = util.GetTimeFromMsecSinceEpoch(val)
	}
	return NewFileInfo(name, true, attrs.Size, objectModTime, false), nil
}

func (fs *GCSFs) setWriterAttrs(objectWriter *storage.Writer, flag int, name string) {
	var contentType string
	if flag == -1 {
		contentType = dirMimeType
	} else {
		contentType = mime.TypeByExtension(path.Ext(name))
	}
	if contentType != "" {
		objectWriter.ObjectAttrs.ContentType = contentType
	}
	if fs.config.StorageClass != "" {
		objectWriter.ObjectAttrs.StorageClass = fs.config.StorageClass
	}
	if fs.config.ACL != "" {
		objectWriter.PredefinedACL = fs.config.ACL
	}
}

func (fs *GCSFs) composeObjects(ctx context.Context, dst, partialObject *storage.ObjectHandle) error {
	fsLog(fs, logger.LevelDebug, "start object compose for partial file %q, destination %q",
		partialObject.ObjectName(), dst.ObjectName())
	composer := dst.ComposerFrom(dst, partialObject)
	if fs.config.StorageClass != "" {
		composer.StorageClass = fs.config.StorageClass
	}
	if fs.config.ACL != "" {
		composer.PredefinedACL = fs.config.ACL
	}
	contentType := mime.TypeByExtension(path.Ext(dst.ObjectName()))
	if contentType != "" {
		composer.ContentType = contentType
	}
	_, err := composer.Run(ctx)
	fsLog(fs, logger.LevelDebug, "object compose for %q finished, err: %v", dst.ObjectName(), err)

	delCtx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	errDelete := partialObject.Delete(delCtx)
	metric.GCSDeleteObjectCompleted(errDelete)
	fsLog(fs, logger.LevelDebug, "deleted partial file %q after composing with %q, err: %v",
		partialObject.ObjectName(), dst.ObjectName(), errDelete)
	return err
}

func (fs *GCSFs) copyFileInternal(source, target string, conditions *storage.Conditions,
	srcInfo os.FileInfo, updateModTime bool,
) error {
	src := fs.svc.Bucket(fs.config.Bucket).Object(source)
	dst := fs.svc.Bucket(fs.config.Bucket).Object(target)
	if conditions != nil {
		dst = dst.If(*conditions)
	} else {
		attrs, err := fs.headObject(target)
		if err == nil {
			dst = dst.If(storage.Conditions{GenerationMatch: attrs.Generation})
		} else if fs.IsNotExist(err) {
			dst = dst.If(storage.Conditions{DoesNotExist: true})
		} else {
			fsLog(fs, logger.LevelWarn, "unable to set precondition for copy, target %q, stat err: %v",
				target, err)
		}
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()

	copier := dst.CopierFrom(src)
	if fs.config.StorageClass != "" {
		copier.StorageClass = fs.config.StorageClass
	}
	if fs.config.ACL != "" {
		copier.PredefinedACL = fs.config.ACL
	}
	contentType := mime.TypeByExtension(path.Ext(source))
	if contentType != "" {
		copier.ContentType = contentType
	}
	metadata := getMetadata(srcInfo)
	if updateModTime && len(metadata) > 0 {
		delete(metadata, lastModifiedField)
	}
	if len(metadata) > 0 {
		copier.Metadata = metadata
	}
	_, err := copier.Run(ctx)
	metric.GCSCopyObjectCompleted(err)
	return err
}

func (fs *GCSFs) renameInternal(source, target string, srcInfo os.FileInfo, recursion int,
	updateModTime bool,
) (int, int64, error) {
	var numFiles int
	var filesSize int64

	if srcInfo.IsDir() {
		if renameMode == 0 {
			hasContents, err := fs.hasContents(source)
			if err != nil {
				return numFiles, filesSize, err
			}
			if hasContents {
				return numFiles, filesSize, fmt.Errorf("%w: cannot rename non empty directory: %q", ErrVfsUnsupported, source)
			}
		}
		if err := fs.mkdirInternal(target); err != nil {
			return numFiles, filesSize, err
		}
		if renameMode == 1 {
			files, size, err := doRecursiveRename(fs, source, target, fs.renameInternal, recursion, updateModTime)
			numFiles += files
			filesSize += size
			if err != nil {
				return numFiles, filesSize, err
			}
		}
	} else {
		if err := fs.copyFileInternal(source, target, nil, srcInfo, updateModTime); err != nil {
			return numFiles, filesSize, err
		}
		numFiles++
		filesSize += srcInfo.Size()
	}
	err := fs.Remove(source, srcInfo.IsDir())
	if fs.IsNotExist(err) {
		err = nil
	}
	return numFiles, filesSize, err
}

func (fs *GCSFs) mkdirInternal(name string) error {
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	_, w, _, err := fs.Create(name, -1, 0)
	if err != nil {
		return err
	}
	return w.Close()
}

func (fs *GCSFs) hasContents(name string) (bool, error) {
	result := false
	prefix := fs.getPrefix(name)
	query := &storage.Query{Prefix: prefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return result, err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	// if we have a dir object with a trailing slash it will be returned so we set the size to 2
	pager := iterator.NewPager(it, 2, "")

	var objects []*storage.ObjectAttrs
	_, err = pager.NextPage(&objects)
	if err != nil {
		metric.GCSListObjectsCompleted(err)
		return result, err
	}

	for _, attrs := range objects {
		name, _ := fs.resolve(attrs.Name, prefix, attrs.ContentType)
		// a dir object with a trailing slash will result in an empty name
		if name == "/" || name == "" {
			continue
		}
		result = true
		break
	}

	metric.GCSListObjectsCompleted(nil)
	return result, nil
}

func (fs *GCSFs) getPrefix(name string) string {
	prefix := ""
	if name != "" && name != "." && name != "/" {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	return prefix
}

func (fs *GCSFs) headObject(name string) (*storage.ObjectAttrs, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	bkt := fs.svc.Bucket(fs.config.Bucket)
	obj := bkt.Object(name)
	attrs, err := obj.Attrs(ctx)
	metric.GCSHeadObjectCompleted(err)
	return attrs, err
}

// GetMimeType returns the content type
func (fs *GCSFs) GetMimeType(name string) (string, error) {
	attrs, err := fs.headObject(name)
	if err != nil {
		return "", err
	}
	return attrs.ContentType, nil
}

// Close closes the fs
func (fs *GCSFs) Close() error {
	return nil
}

// GetAvailableDiskSize returns the available size for the specified path
func (*GCSFs) GetAvailableDiskSize(_ string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
}

func (*GCSFs) getTempObject(name string) string {
	dir := filepath.Dir(name)
	guid := xid.New().String()
	return filepath.Join(dir, ".sftpgo-partial."+guid+"."+filepath.Base(name))
}

type gcsDirLister struct {
	baseDirLister
	bucket        *storage.BucketHandle
	query         *storage.Query
	timeout       time.Duration
	nextPageToken string
	noMorePages   bool
	prefix        string
	prefixes      map[string]bool
	metricUpdated bool
}

func (l *gcsDirLister) resolve(name, contentType string) (string, bool) {
	result := strings.TrimPrefix(name, l.prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	if contentType == dirMimeType {
		isDir = true
	}
	return result, isDir
}

func (l *gcsDirLister) Next(limit int) ([]os.FileInfo, error) {
	if limit <= 0 {
		return nil, errInvalidDirListerLimit
	}
	if len(l.cache) >= limit {
		return l.returnFromCache(limit), nil
	}

	if l.noMorePages {
		if !l.metricUpdated {
			l.metricUpdated = true
			metric.GCSListObjectsCompleted(nil)
		}
		return l.returnFromCache(limit), io.EOF
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(l.timeout))
	defer cancelFn()

	it := l.bucket.Objects(ctx, l.query)
	paginator := iterator.NewPager(it, defaultGCSPageSize, l.nextPageToken)
	var objects []*storage.ObjectAttrs

	pageToken, err := paginator.NextPage(&objects)
	if err != nil {
		metric.GCSListObjectsCompleted(err)
		return l.cache, err
	}

	for _, attrs := range objects {
		if attrs.Prefix != "" {
			name, _ := l.resolve(attrs.Prefix, attrs.ContentType)
			if name == "" {
				continue
			}
			if _, ok := l.prefixes[name]; ok {
				continue
			}
			l.cache = append(l.cache, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
			l.prefixes[name] = true
		} else {
			name, isDir := l.resolve(attrs.Name, attrs.ContentType)
			if name == "" {
				continue
			}
			if !attrs.Deleted.IsZero() {
				continue
			}
			if isDir {
				// check if the dir is already included, it will be sent as blob prefix if it contains at least one item
				if _, ok := l.prefixes[name]; ok {
					continue
				}
				l.prefixes[name] = true
			}
			modTime := attrs.Updated
			if val := getLastModified(attrs.Metadata); val > 0 {
				modTime = util.GetTimeFromMsecSinceEpoch(val)
			}
			info := NewFileInfo(name, isDir, attrs.Size, modTime, false)
			info.setMetadata(attrs.Metadata)
			l.cache = append(l.cache, info)
		}
	}

	l.nextPageToken = pageToken
	l.noMorePages = (l.nextPageToken == "")

	return l.returnFromCache(limit), nil
}

func (l *gcsDirLister) Close() error {
	clear(l.prefixes)
	return l.baseDirLister.Close()
}
