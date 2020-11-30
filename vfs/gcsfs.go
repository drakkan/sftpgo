// +build !nogcs

package vfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/eikenb/pipeat"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/version"
)

var (
	gcsDefaultFieldsSelection = []string{"Name", "Size", "Deleted", "Updated", "ContentType"}
)

// GCSFs is a Fs implementation for Google Cloud Storage.
type GCSFs struct {
	connectionID   string
	localTempDir   string
	config         GCSFsConfig
	svc            *storage.Client
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

func init() {
	version.AddFeature("+gcs")
}

// NewGCSFs returns an GCSFs object that allows to interact with Google Cloud Storage
func NewGCSFs(connectionID, localTempDir string, config GCSFsConfig) (Fs, error) {
	var err error
	fs := &GCSFs{
		connectionID:   connectionID,
		localTempDir:   localTempDir,
		config:         config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
	if err = ValidateGCSFsConfig(&fs.config, fs.config.CredentialFile); err != nil {
		return fs, err
	}
	ctx := context.Background()
	if fs.config.AutomaticCredentials > 0 {
		fs.svc, err = storage.NewClient(ctx)
	} else if !fs.config.Credentials.IsEmpty() {
		if fs.config.Credentials.IsEncrypted() {
			err = fs.config.Credentials.Decrypt()
			if err != nil {
				return fs, err
			}
		}
		fs.svc, err = storage.NewClient(ctx, option.WithCredentialsJSON([]byte(fs.config.Credentials.GetPayload())))
	} else {
		var creds []byte
		creds, err = ioutil.ReadFile(fs.config.CredentialFile)
		if err != nil {
			return fs, err
		}
		secret := kms.NewEmptySecret()
		err = json.Unmarshal(creds, secret)
		if err != nil {
			return fs, err
		}
		err = secret.Decrypt()
		if err != nil {
			return fs, err
		}
		fs.svc, err = storage.NewClient(ctx, option.WithCredentialsJSON([]byte(secret.GetPayload())))
	}
	return fs, err
}

// Name returns the name for the Fs implementation
func (fs *GCSFs) Name() string {
	return fmt.Sprintf("GCSFs bucket %#v", fs.config.Bucket)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *GCSFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *GCSFs) Stat(name string) (os.FileInfo, error) {
	var result FileInfo
	var err error
	if name == "" || name == "." {
		err := fs.checkIfBucketExists()
		if err != nil {
			return result, err
		}
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	attrs, err := fs.headObject(name)
	if err == nil {
		objSize := attrs.Size
		objectModTime := attrs.Updated
		isDir := attrs.ContentType == dirMimeType || strings.HasSuffix(attrs.Name, "/")
		return NewFileInfo(name, isDir, objSize, objectModTime, false), nil
	}
	if !fs.IsNotExist(err) {
		return result, err
	}
	// now check if this is a prefix (virtual directory)
	hasContents, err := fs.hasContents(name)
	if err == nil && hasContents {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	} else if err != nil {
		return nil, err
	}
	// search a dir ending with "/" for backward compatibility
	return fs.getStatCompat(name)
}

func (fs *GCSFs) getStatCompat(name string) (os.FileInfo, error) {
	var result FileInfo
	prefix := fs.getPrefixForStat(name)
	query := &storage.Query{Prefix: prefix, Delimiter: "/"}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return nil, err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			metrics.GCSListObjectsCompleted(err)
			return result, err
		}
		if attrs.Prefix != "" {
			if fs.isEqual(attrs.Prefix, name) {
				result = NewFileInfo(name, true, 0, time.Now(), false)
				break
			}
		} else {
			if !attrs.Deleted.IsZero() {
				continue
			}
			if fs.isEqual(attrs.Name, name) {
				isDir := strings.HasSuffix(attrs.Name, "/")
				result = NewFileInfo(name, isDir, attrs.Size, attrs.Updated, false)
				break
			}
		}
	}
	metrics.GCSListObjectsCompleted(nil)
	if result.Name() == "" {
		err = errors.New("404 no such file or directory")
	}
	return result, err
}

// Lstat returns a FileInfo describing the named file
func (fs *GCSFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *GCSFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	bkt := fs.svc.Bucket(fs.config.Bucket)
	obj := bkt.Object(name)
	ctx, cancelFn := context.WithCancel(context.Background())
	objectReader, err := obj.NewRangeReader(ctx, offset, -1)
	if err == nil && offset > 0 && objectReader.Attrs.ContentEncoding == "gzip" {
		err = fmt.Errorf("Range request is not possible for gzip content encoding, requested offset %v", offset)
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
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", name, n, err)
		metrics.GCSTransferCompleted(n, 1, err)
	}()
	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *GCSFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)
	bkt := fs.svc.Bucket(fs.config.Bucket)
	obj := bkt.Object(name)
	ctx, cancelFn := context.WithCancel(context.Background())
	objectWriter := obj.NewWriter(ctx)
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
	go func() {
		defer cancelFn()

		n, err := io.Copy(objectWriter, r)
		closeErr := objectWriter.Close()
		if err == nil {
			err = closeErr
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %v", name, n, err)
		metrics.GCSTransferCompleted(n, 0, err)
	}()
	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a CopyObject call.
func (fs *GCSFs) Rename(source, target string) error {
	if source == target {
		return nil
	}
	fi, err := fs.Stat(source)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		hasContents, err := fs.hasContents(source)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("Cannot rename non empty directory: %#v", source)
		}
	}
	src := fs.svc.Bucket(fs.config.Bucket).Object(source)
	dst := fs.svc.Bucket(fs.config.Bucket).Object(target)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	copier := dst.CopierFrom(src)
	if fs.config.StorageClass != "" {
		copier.StorageClass = fs.config.StorageClass
	}
	var contentType string
	if fi.IsDir() {
		contentType = dirMimeType
	} else {
		contentType = mime.TypeByExtension(path.Ext(source))
	}
	if contentType != "" {
		copier.ContentType = contentType
	}
	_, err = copier.Run(ctx)
	metrics.GCSCopyObjectCompleted(err)
	if err != nil {
		return err
	}
	return fs.Remove(source, fi.IsDir())
}

// Remove removes the named file or (empty) directory.
func (fs *GCSFs) Remove(name string, isDir bool) error {
	if isDir {
		hasContents, err := fs.hasContents(name)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("Cannot remove non empty directory: %#v", name)
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	err := fs.svc.Bucket(fs.config.Bucket).Object(name).Delete(ctx)
	metrics.GCSDeleteObjectCompleted(err)
	if fs.IsNotExist(err) && isDir {
		name = name + "/"
		err = fs.svc.Bucket(fs.config.Bucket).Object(name).Delete(ctx)
		metrics.GCSDeleteObjectCompleted(err)
	}
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *GCSFs) Mkdir(name string) error {
	_, err := fs.Stat(name)
	if !fs.IsNotExist(err) {
		return err
	}
	_, w, _, err := fs.Create(name, -1)
	if err != nil {
		return err
	}
	return w.Close()
}

// Symlink creates source as a symbolic link to target.
func (*GCSFs) Symlink(source, target string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*GCSFs) Readlink(name string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*GCSFs) Chown(name string, uid int, gid int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*GCSFs) Chmod(name string, mode os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (*GCSFs) Chtimes(name string, atime, mtime time.Time) error {
	return ErrVfsUnsupported
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (*GCSFs) Truncate(name string, size int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *GCSFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	var result []os.FileInfo
	// dirname must be already cleaned
	prefix := fs.getPrefix(dirname)

	query := &storage.Query{Prefix: prefix, Delimiter: "/"}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return nil, err
	}

	prefixes := make(map[string]bool)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			metrics.GCSListObjectsCompleted(err)
			return result, err
		}
		if attrs.Prefix != "" {
			name, _ := fs.resolve(attrs.Prefix, prefix)
			if name == "" {
				continue
			}
			if _, ok := prefixes[name]; ok {
				continue
			}
			result = append(result, NewFileInfo(name, true, 0, time.Now(), false))
			prefixes[name] = true
		} else {
			name, isDir := fs.resolve(attrs.Name, prefix)
			if name == "" {
				continue
			}
			if !attrs.Deleted.IsZero() {
				continue
			}
			if attrs.ContentType == dirMimeType {
				isDir = true
			}
			if isDir {
				// check if the dir is already included, it will be sent as blob prefix if it contains at least one item
				if _, ok := prefixes[name]; ok {
					continue
				}
				prefixes[name] = true
			}
			fi := NewFileInfo(name, isDir, attrs.Size, attrs.Updated, false)
			result = append(result, fi)
		}
	}
	metrics.GCSListObjectsCompleted(nil)
	return result, nil
}

// IsUploadResumeSupported returns true if upload resume is supported.
// SFTP Resume is not supported on S3
func (*GCSFs) IsUploadResumeSupported() bool {
	return false
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
	if e, ok := err.(*googleapi.Error); ok {
		if e.Code == http.StatusNotFound {
			return true
		}
	}
	return strings.Contains(err.Error(), "404")
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*GCSFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*googleapi.Error); ok {
		if e.Code == http.StatusForbidden || e.Code == http.StatusUnauthorized {
			return true
		}
	}
	return strings.Contains(err.Error(), "403")
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*GCSFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *GCSFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *GCSFs) ScanRootDirContents() (int, int64, error) {
	numFiles := 0
	size := int64(0)
	query := &storage.Query{Prefix: fs.config.KeyPrefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return numFiles, size, err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()
	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			metrics.GCSListObjectsCompleted(err)
			return numFiles, size, err
		}
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
	metrics.GCSListObjectsCompleted(nil)
	return numFiles, size, err
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (*GCSFs) GetDirSize(dirname string) (int, int64, error) {
	return 0, 0, ErrVfsUnsupported
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// GCS uploads are already atomic, we never call this method for GCS
func (*GCSFs) GetAtomicUploadPath(name string) string {
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
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root
func (fs *GCSFs) Walk(root string, walkFn filepath.WalkFunc) error {
	prefix := ""
	if root != "" && root != "." {
		prefix = strings.TrimPrefix(root, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}

	query := &storage.Query{Prefix: prefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		walkFn(root, nil, err) //nolint:errcheck
		return err
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			walkFn(root, nil, err) //nolint:errcheck
			metrics.GCSListObjectsCompleted(err)
			return err
		}
		if !attrs.Deleted.IsZero() {
			continue
		}
		name, isDir := fs.resolve(attrs.Name, prefix)
		if name == "" {
			continue
		}
		if attrs.ContentType == dirMimeType {
			isDir = true
		}
		err = walkFn(attrs.Name, NewFileInfo(name, isDir, attrs.Size, attrs.Updated, false), nil)
		if err != nil {
			return err
		}
	}

	walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), err) //nolint:errcheck
	metrics.GCSListObjectsCompleted(err)
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
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return fs.Join(fs.config.KeyPrefix, strings.TrimPrefix(virtualPath, "/")), nil
}

func (fs *GCSFs) resolve(name string, prefix string) (string, bool) {
	result := strings.TrimPrefix(name, prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	return result, isDir
}

func (fs *GCSFs) isEqual(key string, virtualName string) bool {
	if key == virtualName {
		return true
	}
	if key == virtualName+"/" {
		return true
	}
	if key+"/" == virtualName {
		return true
	}
	return false
}

func (fs *GCSFs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	bkt := fs.svc.Bucket(fs.config.Bucket)
	_, err := bkt.Attrs(ctx)
	metrics.GCSHeadBucketCompleted(err)
	return err
}

func (fs *GCSFs) hasContents(name string) (bool, error) {
	result := false
	prefix := ""
	if name != "" && name != "." {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	query := &storage.Query{Prefix: prefix}
	err := query.SetAttrSelection(gcsDefaultFieldsSelection)
	if err != nil {
		return result, err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()
	bkt := fs.svc.Bucket(fs.config.Bucket)
	it := bkt.Objects(ctx, query)
	// if we have a dir object with a trailing slash it will be returned so we set the size to 2
	it.PageInfo().MaxSize = 2
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			metrics.GCSListObjectsCompleted(err)
			return result, err
		}
		name, _ := fs.resolve(attrs.Name, prefix)
		// a dir object with a trailing slash will result in an empty name
		if name == "/" || name == "" {
			continue
		}
		result = true
		break
	}

	metrics.GCSListObjectsCompleted(err)
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

func (fs *GCSFs) getPrefixForStat(name string) string {
	prefix := path.Dir(name)
	if prefix == "/" || prefix == "." || prefix == "" {
		prefix = ""
	} else {
		prefix = strings.TrimPrefix(prefix, "/")
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
	metrics.GCSHeadObjectCompleted(err)
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
