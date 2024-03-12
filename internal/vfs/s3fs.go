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

//go:build !nos3
// +build !nos3

package vfs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	// using this mime type for directories improves compatibility with s3fs-fuse
	s3DirMimeType         = "application/x-directory"
	s3TransferBufferSize  = 256 * 1024
	s3CopyObjectThreshold = 500 * 1024 * 1024
)

var (
	s3DirMimeTypes    = []string{s3DirMimeType, "httpd/unix-directory"}
	s3DefaultPageSize = int32(5000)
)

// S3Fs is a Fs implementation for AWS S3 compatible object storages
type S3Fs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath  string
	config     *S3FsConfig
	svc        *s3.Client
	ctxTimeout time.Duration
}

func init() {
	version.AddFeature("+s3")
}

// NewS3Fs returns an S3Fs object that allows to interact with an s3 compatible
// object storage
func NewS3Fs(connectionID, localTempDir, mountPath string, s3Config S3FsConfig) (Fs, error) {
	if localTempDir == "" {
		localTempDir = getLocalTempDir()
	}
	fs := &S3Fs{
		connectionID: connectionID,
		localTempDir: localTempDir,
		mountPath:    getMountPath(mountPath),
		config:       &s3Config,
		ctxTimeout:   30 * time.Second,
	}
	if err := fs.config.validate(); err != nil {
		return fs, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithHTTPClient(
		getAWSHTTPClient(0, 30*time.Second, fs.config.SkipTLSVerify)),
	)
	if err != nil {
		return fs, fmt.Errorf("unable to get AWS config: %w", err)
	}
	if fs.config.Region != "" {
		awsConfig.Region = fs.config.Region
	}
	if !fs.config.AccessSecret.IsEmpty() {
		if err := fs.config.AccessSecret.TryDecrypt(); err != nil {
			return fs, err
		}
		awsConfig.Credentials = aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(fs.config.AccessKey, fs.config.AccessSecret.GetPayload(), ""))
	}

	fs.setConfigDefaults()

	if fs.config.RoleARN != "" {
		client := sts.NewFromConfig(awsConfig)
		creds := stscreds.NewAssumeRoleProvider(client, fs.config.RoleARN)
		awsConfig.Credentials = creds
	}
	fs.svc = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.AppID = fmt.Sprintf("SFTPGo-%s", version.Get().CommitHash)
		o.UsePathStyle = fs.config.ForcePathStyle
		if fs.config.Endpoint != "" {
			o.BaseEndpoint = aws.String(fs.config.Endpoint)
		}
	})
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *S3Fs) Name() string {
	return fmt.Sprintf("%s bucket %q", s3fsName, fs.config.Bucket)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *S3Fs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *S3Fs) Stat(name string) (os.FileInfo, error) {
	var result *FileInfo
	if name == "" || name == "/" || name == "." {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	}
	obj, err := fs.headObject(name)
	if err == nil {
		// Some S3 providers (like SeaweedFS) remove the trailing '/' from object keys.
		// So we check some common content types to detect if this is a "directory".
		isDir := util.Contains(s3DirMimeTypes, util.GetStringFromPointer(obj.ContentType))
		if util.GetIntFromPointer(obj.ContentLength) == 0 && !isDir {
			_, err = fs.headObject(name + "/")
			isDir = err == nil
		}
		return NewFileInfo(name, isDir, util.GetIntFromPointer(obj.ContentLength), util.GetTimeFromPointer(obj.LastModified), false), nil
	}
	if !fs.IsNotExist(err) {
		return result, err
	}
	// now check if this is a prefix (virtual directory)
	hasContents, err := fs.hasContents(name)
	if err == nil && hasContents {
		return NewFileInfo(name, true, 0, time.Unix(0, 0), false), nil
	} else if err != nil {
		return nil, err
	}
	// the requested file may still be a directory as a zero bytes key
	// with a trailing forward slash (created using mkdir).
	// S3 doesn't return content type when listing objects, so we have
	// create "dirs" adding a trailing "/" to the key
	return fs.getStatForDir(name)
}

func (fs *S3Fs) getStatForDir(name string) (os.FileInfo, error) {
	var result *FileInfo
	obj, err := fs.headObject(name + "/")
	if err != nil {
		return result, err
	}
	return NewFileInfo(name, true, util.GetIntFromPointer(obj.ContentLength), util.GetTimeFromPointer(obj.LastModified), false), nil
}

// Lstat returns a FileInfo describing the named file
func (fs *S3Fs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *S3Fs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
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

	ctx, cancelFn := context.WithCancel(context.Background())
	downloader := manager.NewDownloader(fs.svc, func(d *manager.Downloader) {
		d.Concurrency = fs.config.DownloadConcurrency
		d.PartSize = fs.config.DownloadPartSize
		if offset == 0 && fs.config.DownloadPartMaxTime > 0 {
			d.ClientOptions = append(d.ClientOptions, func(o *s3.Options) {
				o.HTTPClient = getAWSHTTPClient(fs.config.DownloadPartMaxTime, 100*time.Millisecond,
					fs.config.SkipTLSVerify)
			})
		}
	})

	var streamRange *string
	if offset > 0 {
		streamRange = aws.String(fmt.Sprintf("bytes=%v-", offset))
	}

	go func() {
		defer cancelFn()

		n, err := downloader.Download(ctx, w, &s3.GetObjectInput{
			Bucket: aws.String(fs.config.Bucket),
			Key:    aws.String(name),
			Range:  streamRange,
		})
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %+v", name, n, err)
		metric.S3TransferCompleted(n, 1, err)
	}()
	return nil, p, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *S3Fs) Create(name string, flag, checks int) (File, PipeWriter, func(), error) {
	if checks&CheckParentDir != 0 {
		_, err := fs.Stat(path.Dir(name))
		if err != nil {
			return nil, nil, nil, err
		}
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	var p PipeWriter
	if checks&CheckResume != 0 {
		p = newPipeWriterAtOffset(w, 0)
	} else {
		p = NewPipeWriter(w)
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	uploader := manager.NewUploader(fs.svc, func(u *manager.Uploader) {
		u.Concurrency = fs.config.UploadConcurrency
		u.PartSize = fs.config.UploadPartSize
		if fs.config.UploadPartMaxTime > 0 {
			u.ClientOptions = append(u.ClientOptions, func(o *s3.Options) {
				o.HTTPClient = getAWSHTTPClient(fs.config.UploadPartMaxTime, 100*time.Millisecond,
					fs.config.SkipTLSVerify)
			})
		}
	})

	go func() {
		defer cancelFn()

		var contentType string
		if flag == -1 {
			contentType = s3DirMimeType
		} else {
			contentType = mime.TypeByExtension(path.Ext(name))
		}
		_, err := uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket:       aws.String(fs.config.Bucket),
			Key:          aws.String(name),
			Body:         r,
			ACL:          types.ObjectCannedACL(fs.config.ACL),
			StorageClass: types.StorageClass(fs.config.StorageClass),
			ContentType:  util.NilIfEmpty(contentType),
		})
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, acl: %q, readed bytes: %d, err: %+v",
			name, fs.config.ACL, r.GetReadedBytes(), err)
		metric.S3TransferCompleted(r.GetReadedBytes(), 0, err)
	}()

	if checks&CheckResume != 0 {
		readCh := make(chan error, 1)

		go func() {
			n, err := fs.downloadToWriter(name, p)
			pw := p.(*pipeWriterAtOffset)
			pw.offset = 0
			pw.writeOffset = n
			readCh <- err
		}()

		err = <-readCh
		if err != nil {
			cancelFn()
			p.Close()
			fsLog(fs, logger.LevelDebug, "download before resume failed, writer closed and read cancelled")
			return nil, nil, nil, err
		}
	}

	if uploadMode&4 != 0 {
		return nil, p, nil, nil
	}
	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
func (fs *S3Fs) Rename(source, target string) (int, int64, error) {
	if source == target {
		return -1, -1, nil
	}
	_, err := fs.Stat(path.Dir(target))
	if err != nil {
		return -1, -1, err
	}
	fi, err := fs.Stat(source)
	if err != nil {
		return -1, -1, err
	}
	return fs.renameInternal(source, target, fi, 0)
}

// Remove removes the named file or (empty) directory.
func (fs *S3Fs) Remove(name string, isDir bool) error {
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
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.svc.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(name),
	})
	metric.S3DeleteObjectCompleted(err)
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *S3Fs) Mkdir(name string) error {
	_, err := fs.Stat(name)
	if !fs.IsNotExist(err) {
		return err
	}
	return fs.mkdirInternal(name)
}

// Symlink creates source as a symbolic link to target.
func (*S3Fs) Symlink(_, _ string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*S3Fs) Readlink(_ string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*S3Fs) Chown(_ string, _ int, _ int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*S3Fs) Chmod(_ string, _ os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (fs *S3Fs) Chtimes(_ string, _, _ time.Time, _ bool) error {
	return ErrVfsUnsupported
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (*S3Fs) Truncate(_ string, _ int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *S3Fs) ReadDir(dirname string) (DirLister, error) {
	// dirname must be already cleaned
	prefix := fs.getPrefix(dirname)
	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		MaxKeys:   &s3DefaultPageSize,
	})

	return &s3DirLister{
		paginator: paginator,
		timeout:   fs.ctxTimeout,
		prefix:    prefix,
		prefixes:  make(map[string]bool),
	}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on S3
func (*S3Fs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (*S3Fs) IsConditionalUploadResumeSupported(size int64) bool {
	return size <= resumeMaxSize
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// S3 uploads are already atomic, we don't need to upload to a temporary
// file
func (*S3Fs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*S3Fs) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		if re.Response != nil {
			return re.Response.StatusCode == http.StatusNotFound
		}
	}
	return false
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*S3Fs) IsPermission(err error) bool {
	if err == nil {
		return false
	}

	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		if re.Response != nil {
			return re.Response.StatusCode == http.StatusForbidden ||
				re.Response.StatusCode == http.StatusUnauthorized
		}
	}
	return false
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*S3Fs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrVfsUnsupported)
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *S3Fs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "", nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *S3Fs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize(fs.config.KeyPrefix)
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *S3Fs) GetDirSize(dirname string) (int, int64, error) {
	prefix := fs.getPrefix(dirname)
	numFiles := 0
	size := int64(0)

	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:  aws.String(fs.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: &s3DefaultPageSize,
	})

	for paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			metric.S3ListObjectsCompleted(err)
			return numFiles, size, err
		}
		for _, fileObject := range page.Contents {
			isDir := strings.HasSuffix(util.GetStringFromPointer(fileObject.Key), "/")
			objectSize := util.GetIntFromPointer(fileObject.Size)
			if isDir && objectSize == 0 {
				continue
			}
			numFiles++
			size += objectSize
		}
		fsLog(fs, logger.LevelDebug, "scan in progress for %q, files: %d, size: %d", dirname, numFiles, size)
	}

	metric.S3ListObjectsCompleted(nil)
	return numFiles, size, nil
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// S3 uploads are already atomic, we never call this method for S3
func (*S3Fs) GetAtomicUploadPath(_ string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *S3Fs) GetRelativePath(name string) string {
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
// directory in the tree, including root. The result are unordered
func (fs *S3Fs) Walk(root string, walkFn filepath.WalkFunc) error {
	prefix := fs.getPrefix(root)

	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:  aws.String(fs.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: &s3DefaultPageSize,
	})

	for paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			metric.S3ListObjectsCompleted(err)
			walkFn(root, NewFileInfo(root, true, 0, time.Unix(0, 0), false), err) //nolint:errcheck
			return err
		}
		for _, fileObject := range page.Contents {
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if name == "" {
				continue
			}
			err := walkFn(util.GetStringFromPointer(fileObject.Key),
				NewFileInfo(name, isDir, util.GetIntFromPointer(fileObject.Size),
					util.GetTimeFromPointer(fileObject.LastModified), false), nil)
			if err != nil {
				return err
			}
		}
	}

	metric.S3ListObjectsCompleted(nil)
	walkFn(root, NewFileInfo(root, true, 0, time.Unix(0, 0), false), nil) //nolint:errcheck
	return nil
}

// Join joins any number of path elements into a single path
func (*S3Fs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (*S3Fs) HasVirtualFolders() bool {
	return true
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *S3Fs) ResolvePath(virtualPath string) (string, error) {
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return fs.Join(fs.config.KeyPrefix, strings.TrimPrefix(virtualPath, "/")), nil
}

// CopyFile implements the FsFileCopier interface
func (fs *S3Fs) CopyFile(source, target string, srcSize int64) (int, int64, error) {
	numFiles := 1
	sizeDiff := srcSize
	attrs, err := fs.headObject(target)
	if err == nil {
		sizeDiff -= util.GetIntFromPointer(attrs.ContentLength)
		numFiles = 0
	} else {
		if !fs.IsNotExist(err) {
			return 0, 0, err
		}
	}
	if err := fs.copyFileInternal(source, target, srcSize); err != nil {
		return 0, 0, err
	}
	return numFiles, sizeDiff, nil
}

func (fs *S3Fs) resolve(name *string, prefix string) (string, bool) {
	result := strings.TrimPrefix(util.GetStringFromPointer(name), prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	return result, isDir
}

func (fs *S3Fs) setConfigDefaults() {
	if fs.config.UploadPartSize == 0 {
		fs.config.UploadPartSize = manager.DefaultUploadPartSize
	} else {
		if fs.config.UploadPartSize < 1024*1024 {
			fs.config.UploadPartSize *= 1024 * 1024
		}
	}
	if fs.config.UploadConcurrency == 0 {
		fs.config.UploadConcurrency = manager.DefaultUploadConcurrency
	}
	if fs.config.DownloadPartSize == 0 {
		fs.config.DownloadPartSize = manager.DefaultDownloadPartSize
	} else {
		if fs.config.DownloadPartSize < 1024*1024 {
			fs.config.DownloadPartSize *= 1024 * 1024
		}
	}
	if fs.config.DownloadConcurrency == 0 {
		fs.config.DownloadConcurrency = manager.DefaultDownloadConcurrency
	}
}

func (fs *S3Fs) copyFileInternal(source, target string, fileSize int64) error {
	contentType := mime.TypeByExtension(path.Ext(source))
	copySource := pathEscape(fs.Join(fs.config.Bucket, source))

	if fileSize > s3CopyObjectThreshold {
		fsLog(fs, logger.LevelDebug, "renaming file %q with size %d using multipart copy",
			source, fileSize)
		err := fs.doMultipartCopy(copySource, target, contentType, fileSize)
		metric.S3CopyObjectCompleted(err)
		return err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.svc.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:       aws.String(fs.config.Bucket),
		CopySource:   aws.String(copySource),
		Key:          aws.String(target),
		StorageClass: types.StorageClass(fs.config.StorageClass),
		ACL:          types.ObjectCannedACL(fs.config.ACL),
		ContentType:  util.NilIfEmpty(contentType),
	})

	metric.S3CopyObjectCompleted(err)
	return err
}

func (fs *S3Fs) renameInternal(source, target string, fi os.FileInfo, recursion int) (int, int64, error) {
	var numFiles int
	var filesSize int64

	if fi.IsDir() {
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
			files, size, err := doRecursiveRename(fs, source, target, fs.renameInternal, recursion)
			numFiles += files
			filesSize += size
			if err != nil {
				return numFiles, filesSize, err
			}
		}
	} else {
		if err := fs.copyFileInternal(source, target, fi.Size()); err != nil {
			return numFiles, filesSize, err
		}
		numFiles++
		filesSize += fi.Size()
	}
	err := fs.Remove(source, fi.IsDir())
	if fs.IsNotExist(err) {
		err = nil
	}
	return numFiles, filesSize, err
}

func (fs *S3Fs) mkdirInternal(name string) error {
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	_, w, _, err := fs.Create(name, -1, 0)
	if err != nil {
		return err
	}
	return w.Close()
}

func (fs *S3Fs) hasContents(name string) (bool, error) {
	prefix := fs.getPrefix(name)
	maxKeys := int32(2)
	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:  aws.String(fs.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: &maxKeys,
	})

	if paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		metric.S3ListObjectsCompleted(err)
		if err != nil {
			return false, err
		}

		for _, obj := range page.Contents {
			name, _ := fs.resolve(obj.Key, prefix)
			if name == "" || name == "/" {
				continue
			}
			return true, nil
		}
		return false, nil
	}

	metric.S3ListObjectsCompleted(nil)
	return false, nil
}

func (fs *S3Fs) doMultipartCopy(source, target, contentType string, fileSize int64) error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	res, err := fs.svc.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:       aws.String(fs.config.Bucket),
		Key:          aws.String(target),
		StorageClass: types.StorageClass(fs.config.StorageClass),
		ACL:          types.ObjectCannedACL(fs.config.ACL),
		ContentType:  util.NilIfEmpty(contentType),
	})
	if err != nil {
		return fmt.Errorf("unable to create multipart copy request: %w", err)
	}
	uploadID := util.GetStringFromPointer(res.UploadId)
	if uploadID == "" {
		return errors.New("unable to get multipart copy upload ID")
	}
	// We use 32 MB part size and copy 10 parts in parallel.
	// These values are arbitrary. We don't want to start too many goroutines
	maxPartSize := int64(32 * 1024 * 1024)
	if fileSize > int64(100*1024*1024*1024) {
		maxPartSize = int64(500 * 1024 * 1024)
	}
	guard := make(chan struct{}, 10)
	finished := false
	var completedParts []types.CompletedPart
	var partMutex sync.Mutex
	var wg sync.WaitGroup
	var hasError atomic.Bool
	var errOnce sync.Once
	var copyError error
	var partNumber int32
	var offset int64

	opCtx, opCancel := context.WithCancel(context.Background())
	defer opCancel()

	for partNumber = 1; !finished; partNumber++ {
		start := offset
		end := offset + maxPartSize
		if end >= fileSize {
			end = fileSize
			finished = true
		}
		offset = end

		guard <- struct{}{}
		if hasError.Load() {
			fsLog(fs, logger.LevelDebug, "previous multipart copy error, copy for part %d not started", partNumber)
			break
		}

		wg.Add(1)
		go func(partNum int32, partStart, partEnd int64) {
			defer func() {
				<-guard
				wg.Done()
			}()

			innerCtx, innerCancelFn := context.WithDeadline(opCtx, time.Now().Add(fs.ctxTimeout))
			defer innerCancelFn()

			partResp, err := fs.svc.UploadPartCopy(innerCtx, &s3.UploadPartCopyInput{
				Bucket:          aws.String(fs.config.Bucket),
				CopySource:      aws.String(source),
				Key:             aws.String(target),
				PartNumber:      &partNum,
				UploadId:        aws.String(uploadID),
				CopySourceRange: aws.String(fmt.Sprintf("bytes=%d-%d", partStart, partEnd-1)),
			})
			if err != nil {
				errOnce.Do(func() {
					fsLog(fs, logger.LevelError, "unable to copy part number %d: %+v", partNum, err)
					hasError.Store(true)
					copyError = fmt.Errorf("error copying part number %d: %w", partNum, err)
					opCancel()

					abortCtx, abortCancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
					defer abortCancelFn()

					_, errAbort := fs.svc.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
						Bucket:   aws.String(fs.config.Bucket),
						Key:      aws.String(target),
						UploadId: aws.String(uploadID),
					})
					if errAbort != nil {
						fsLog(fs, logger.LevelError, "unable to abort multipart copy: %+v", errAbort)
					}
				})
				return
			}

			partMutex.Lock()
			completedParts = append(completedParts, types.CompletedPart{
				ETag:       partResp.CopyPartResult.ETag,
				PartNumber: &partNum,
			})
			partMutex.Unlock()
		}(partNumber, start, end)
	}

	wg.Wait()
	close(guard)

	if copyError != nil {
		return copyError
	}
	sort.Slice(completedParts, func(i, j int) bool {
		getPartNumber := func(number *int32) int32 {
			if number == nil {
				return 0
			}
			return *number
		}

		return getPartNumber(completedParts[i].PartNumber) < getPartNumber(completedParts[j].PartNumber)
	})

	completeCtx, completeCancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer completeCancelFn()

	_, err = fs.svc.CompleteMultipartUpload(completeCtx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(fs.config.Bucket),
		Key:      aws.String(target),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to complete multipart upload: %w", err)
	}
	return nil
}

func (fs *S3Fs) getPrefix(name string) string {
	prefix := ""
	if name != "" && name != "." && name != "/" {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	return prefix
}

func (fs *S3Fs) headObject(name string) (*s3.HeadObjectOutput, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	obj, err := fs.svc.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(name),
	})
	metric.S3HeadObjectCompleted(err)
	return obj, err
}

// GetMimeType returns the content type
func (fs *S3Fs) GetMimeType(name string) (string, error) {
	obj, err := fs.headObject(name)
	if err != nil {
		return "", err
	}
	return util.GetStringFromPointer(obj.ContentType), nil
}

// Close closes the fs
func (*S3Fs) Close() error {
	return nil
}

// GetAvailableDiskSize returns the available size for the specified path
func (*S3Fs) GetAvailableDiskSize(_ string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
}

func (fs *S3Fs) downloadToWriter(name string, w PipeWriter) (int64, error) {
	fsLog(fs, logger.LevelDebug, "starting download before resuming upload, path %q", name)
	ctx, cancelFn := context.WithTimeout(context.Background(), preResumeTimeout)
	defer cancelFn()

	downloader := manager.NewDownloader(fs.svc, func(d *manager.Downloader) {
		d.Concurrency = fs.config.DownloadConcurrency
		d.PartSize = fs.config.DownloadPartSize
		if fs.config.DownloadPartMaxTime > 0 {
			d.ClientOptions = append(d.ClientOptions, func(o *s3.Options) {
				o.HTTPClient = getAWSHTTPClient(fs.config.DownloadPartMaxTime, 100*time.Millisecond,
					fs.config.SkipTLSVerify)
			})
		}
	})

	n, err := downloader.Download(ctx, w, &s3.GetObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(name),
	})
	fsLog(fs, logger.LevelDebug, "download before resuming upload completed, path %q size: %d, err: %+v",
		name, n, err)
	metric.S3TransferCompleted(n, 1, err)
	return n, err
}

type s3DirLister struct {
	baseDirLister
	paginator     *s3.ListObjectsV2Paginator
	timeout       time.Duration
	prefix        string
	prefixes      map[string]bool
	metricUpdated bool
}

func (l *s3DirLister) resolve(name *string) (string, bool) {
	result := strings.TrimPrefix(util.GetStringFromPointer(name), l.prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	return result, isDir
}

func (l *s3DirLister) Next(limit int) ([]os.FileInfo, error) {
	if limit <= 0 {
		return nil, errInvalidDirListerLimit
	}
	if len(l.cache) >= limit {
		return l.returnFromCache(limit), nil
	}
	if !l.paginator.HasMorePages() {
		if !l.metricUpdated {
			l.metricUpdated = true
			metric.S3ListObjectsCompleted(nil)
		}
		return l.returnFromCache(limit), io.EOF
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(l.timeout))
	defer cancelFn()

	page, err := l.paginator.NextPage(ctx)
	if err != nil {
		metric.S3ListObjectsCompleted(err)
		return l.cache, err
	}
	for _, p := range page.CommonPrefixes {
		// prefixes have a trailing slash
		name, _ := l.resolve(p.Prefix)
		if name == "" {
			continue
		}
		if _, ok := l.prefixes[name]; ok {
			continue
		}
		l.cache = append(l.cache, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
		l.prefixes[name] = true
	}
	for _, fileObject := range page.Contents {
		objectModTime := util.GetTimeFromPointer(fileObject.LastModified)
		objectSize := util.GetIntFromPointer(fileObject.Size)
		name, isDir := l.resolve(fileObject.Key)
		if name == "" || name == "/" {
			continue
		}
		if isDir {
			if _, ok := l.prefixes[name]; ok {
				continue
			}
			l.prefixes[name] = true
		}

		l.cache = append(l.cache, NewFileInfo(name, (isDir && objectSize == 0), objectSize, objectModTime, false))
	}
	return l.returnFromCache(limit), nil
}

func (l *s3DirLister) Close() error {
	return l.baseDirLister.Close()
}

func getAWSHTTPClient(timeout int, idleConnectionTimeout time.Duration, skipTLSVerify bool) *awshttp.BuildableClient {
	c := awshttp.NewBuildableClient().
		WithDialerOptions(func(d *net.Dialer) {
			d.Timeout = 8 * time.Second
		}).
		WithTransportOptions(func(tr *http.Transport) {
			tr.IdleConnTimeout = idleConnectionTimeout
			tr.WriteBufferSize = s3TransferBufferSize
			tr.ReadBufferSize = s3TransferBufferSize
			if skipTLSVerify {
				if tr.TLSClientConfig != nil {
					tr.TLSClientConfig.InsecureSkipVerify = skipTLSVerify
				} else {
					tr.TLSClientConfig = &tls.Config{
						MinVersion:         awshttp.DefaultHTTPTransportTLSMinVersion,
						InsecureSkipVerify: skipTLSVerify,
					}
				}
			}
		})
	if timeout > 0 {
		c = c.WithTimeout(time.Duration(timeout) * time.Second)
	}
	return c
}

// ideally we should simply use url.PathEscape:
//
// https://github.com/awsdocs/aws-doc-sdk-examples/blob/master/go/example_code/s3/s3_copy_object.go#L65
//
// but this cause issue with some vendors, see #483, the code below is copied from rclone
func pathEscape(in string) string {
	var u url.URL
	u.Path = in
	return strings.ReplaceAll(u.String(), "+", "%2B")
}
