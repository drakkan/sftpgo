//go:build !nos3
// +build !nos3

package vfs

import (
	"context"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

// using this mime type for directories improves compatibility with s3fs-fuse
const s3DirMimeType = "application/x-directory"

// S3Fs is a Fs implementation for AWS S3 compatible object storages
type S3Fs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath      string
	config         *S3FsConfig
	svc            *s3.S3
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

func init() {
	version.AddFeature("+s3")
}

// NewS3Fs returns an S3Fs object that allows to interact with an s3 compatible
// object storage
func NewS3Fs(connectionID, localTempDir, mountPath string, config S3FsConfig) (Fs, error) {
	if localTempDir == "" {
		if tempPath != "" {
			localTempDir = tempPath
		} else {
			localTempDir = filepath.Clean(os.TempDir())
		}
	}
	fs := &S3Fs{
		connectionID:   connectionID,
		localTempDir:   localTempDir,
		mountPath:      mountPath,
		config:         &config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
	if err := fs.config.Validate(); err != nil {
		return fs, err
	}
	awsConfig := aws.NewConfig()

	if fs.config.Region != "" {
		awsConfig.WithRegion(fs.config.Region)
	}

	if !fs.config.AccessSecret.IsEmpty() {
		if err := fs.config.AccessSecret.TryDecrypt(); err != nil {
			return fs, err
		}
		awsConfig.Credentials = credentials.NewStaticCredentials(fs.config.AccessKey, fs.config.AccessSecret.GetPayload(), "")
	}

	if fs.config.Endpoint != "" {
		awsConfig.Endpoint = aws.String(fs.config.Endpoint)
	}
	if fs.config.ForcePathStyle {
		awsConfig.S3ForcePathStyle = aws.Bool(true)
	}
	if fs.config.UploadPartSize == 0 {
		fs.config.UploadPartSize = s3manager.DefaultUploadPartSize
	} else {
		fs.config.UploadPartSize *= 1024 * 1024
	}
	if fs.config.UploadConcurrency == 0 {
		fs.config.UploadConcurrency = s3manager.DefaultUploadConcurrency
	}
	if fs.config.DownloadPartSize == 0 {
		fs.config.DownloadPartSize = s3manager.DefaultDownloadPartSize
	} else {
		fs.config.DownloadPartSize *= 1024 * 1024
	}
	if fs.config.DownloadConcurrency == 0 {
		fs.config.DownloadConcurrency = s3manager.DefaultDownloadConcurrency
	}

	sessOpts := session.Options{
		Config:            *awsConfig,
		SharedConfigState: session.SharedConfigEnable,
	}
	sess, err := session.NewSessionWithOptions(sessOpts)
	if err != nil {
		return fs, err
	}
	fs.svc = s3.New(sess)
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *S3Fs) Name() string {
	return fmt.Sprintf("S3Fs bucket %#v", fs.config.Bucket)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *S3Fs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *S3Fs) Stat(name string) (os.FileInfo, error) {
	var result *FileInfo
	if name == "/" || name == "." {
		err := fs.checkIfBucketExists()
		if err != nil {
			return result, err
		}
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	if "/"+fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	obj, err := fs.headObject(name)
	if err == nil {
		// a "dir" has a trailing "/" so we cannot have a directory here
		objSize := *obj.ContentLength
		objectModTime := *obj.LastModified
		return NewFileInfo(name, false, objSize, objectModTime, false), nil
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
	objSize := *obj.ContentLength
	objectModTime := *obj.LastModified
	return NewFileInfo(name, true, objSize, objectModTime, false), nil
}

// Lstat returns a FileInfo describing the named file
func (fs *S3Fs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *S3Fs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	downloader := s3manager.NewDownloaderWithClient(fs.svc)
	if offset == 0 && fs.config.DownloadPartMaxTime > 0 {
		downloader.RequestOptions = append(downloader.RequestOptions, func(r *request.Request) {
			chunkCtx, cancel := context.WithTimeout(r.Context(), time.Duration(fs.config.DownloadPartMaxTime)*time.Second)
			r.SetContext(chunkCtx)

			go func() {
				<-ctx.Done()
				cancel()
			}()
		})
	}
	var streamRange *string
	if offset > 0 {
		streamRange = aws.String(fmt.Sprintf("bytes=%v-", offset))
	}

	go func() {
		defer cancelFn()
		n, err := downloader.DownloadWithContext(ctx, w, &s3.GetObjectInput{
			Bucket: aws.String(fs.config.Bucket),
			Key:    aws.String(name),
			Range:  streamRange,
		}, func(d *s3manager.Downloader) {
			d.Concurrency = fs.config.DownloadConcurrency
			d.PartSize = fs.config.DownloadPartSize
		})
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", name, n, err)
		metric.S3TransferCompleted(n, 1, err)
	}()
	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *S3Fs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)
	ctx, cancelFn := context.WithCancel(context.Background())
	uploader := s3manager.NewUploaderWithClient(fs.svc)
	go func() {
		defer cancelFn()
		key := name
		var contentType string
		if flag == -1 {
			contentType = s3DirMimeType
		} else {
			contentType = mime.TypeByExtension(path.Ext(name))
		}
		response, err := uploader.UploadWithContext(ctx, &s3manager.UploadInput{
			Bucket:       aws.String(fs.config.Bucket),
			Key:          aws.String(key),
			Body:         r,
			ACL:          util.NilIfEmpty(fs.config.ACL),
			StorageClass: util.NilIfEmpty(fs.config.StorageClass),
			ContentType:  util.NilIfEmpty(contentType),
		}, func(u *s3manager.Uploader) {
			u.Concurrency = fs.config.UploadConcurrency
			u.PartSize = fs.config.UploadPartSize
		})
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, acl: %#v, response: %v, readed bytes: %v, err: %+v",
			name, fs.config.ACL, response, r.GetReadedBytes(), err)
		metric.S3TransferCompleted(r.GetReadedBytes(), 0, err)
	}()
	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a CopyObject call.
// TODO: rename does not work for files bigger than 5GB, implement
// multipart copy or wait for this pull request to be merged:
//
// https://github.com/aws/aws-sdk-go/pull/2653
//
func (fs *S3Fs) Rename(source, target string) error {
	if source == target {
		return nil
	}
	fi, err := fs.Stat(source)
	if err != nil {
		return err
	}
	copySource := fs.Join(fs.config.Bucket, source)
	if fi.IsDir() {
		hasContents, err := fs.hasContents(source)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("cannot rename non empty directory: %#v", source)
		}
		if !strings.HasSuffix(copySource, "/") {
			copySource += "/"
		}
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}
	}
	var contentType string
	if fi.IsDir() {
		contentType = s3DirMimeType
	} else {
		contentType = mime.TypeByExtension(path.Ext(source))
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	_, err = fs.svc.CopyObjectWithContext(ctx, &s3.CopyObjectInput{
		Bucket:       aws.String(fs.config.Bucket),
		CopySource:   aws.String(pathEscape(copySource)),
		Key:          aws.String(target),
		StorageClass: util.NilIfEmpty(fs.config.StorageClass),
		ACL:          util.NilIfEmpty(fs.config.ACL),
		ContentType:  util.NilIfEmpty(contentType),
	})
	if err != nil {
		metric.S3CopyObjectCompleted(err)
		return err
	}
	err = fs.svc.WaitUntilObjectExistsWithContext(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(target),
	})
	metric.S3CopyObjectCompleted(err)
	if err != nil {
		return err
	}
	return fs.Remove(source, fi.IsDir())
}

// Remove removes the named file or (empty) directory.
func (fs *S3Fs) Remove(name string, isDir bool) error {
	if isDir {
		hasContents, err := fs.hasContents(name)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("cannot remove non empty directory: %#v", name)
		}
		if !strings.HasSuffix(name, "/") {
			name += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	_, err := fs.svc.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
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
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	_, w, _, err := fs.Create(name, -1)
	if err != nil {
		return err
	}
	return w.Close()
}

// MkdirAll does nothing, we don't have folder
func (*S3Fs) MkdirAll(name string, uid int, gid int) error {
	return nil
}

// Symlink creates source as a symbolic link to target.
func (*S3Fs) Symlink(source, target string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*S3Fs) Readlink(name string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*S3Fs) Chown(name string, uid int, gid int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*S3Fs) Chmod(name string, mode os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (*S3Fs) Chtimes(name string, atime, mtime time.Time) error {
	return ErrVfsUnsupported
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (*S3Fs) Truncate(name string, size int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *S3Fs) ReadDir(dirname string) ([]os.FileInfo, error) {
	var result []os.FileInfo
	// dirname must be already cleaned
	prefix := ""
	if dirname != "/" && dirname != "." {
		prefix = strings.TrimPrefix(dirname, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}

	prefixes := make(map[string]bool)

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, p := range page.CommonPrefixes {
			// prefixes have a trailing slash
			name, _ := fs.resolve(p.Prefix, prefix)
			if name == "" {
				continue
			}
			if _, ok := prefixes[name]; ok {
				continue
			}
			result = append(result, NewFileInfo(name, true, 0, time.Now(), false))
			prefixes[name] = true
		}
		for _, fileObject := range page.Contents {
			objectSize := *fileObject.Size
			objectModTime := *fileObject.LastModified
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if name == "" {
				continue
			}
			if isDir {
				if _, ok := prefixes[name]; ok {
					continue
				}
				prefixes[name] = true
			}
			result = append(result, NewFileInfo(name, (isDir && objectSize == 0), objectSize, objectModTime, false))
		}
		return true
	})
	metric.S3ListObjectsCompleted(err)
	return result, err
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on S3
func (*S3Fs) IsUploadResumeSupported() bool {
	return false
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
	if aerr, ok := err.(awserr.Error); ok {
		if aerr.Code() == s3.ErrCodeNoSuchKey {
			return true
		}
		if aerr.Code() == s3.ErrCodeNoSuchBucket {
			return true
		}
	}
	if multierr, ok := err.(s3manager.MultiUploadFailure); ok {
		if multierr.Code() == s3.ErrCodeNoSuchKey {
			return true
		}
		if multierr.Code() == s3.ErrCodeNoSuchBucket {
			return true
		}
	}
	return strings.Contains(err.Error(), "404")
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*S3Fs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "403")
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*S3Fs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *S3Fs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "")
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *S3Fs) ScanRootDirContents() (int, int64, error) {
	numFiles := 0
	size := int64(0)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(fs.config.Bucket),
		Prefix: aws.String(fs.config.KeyPrefix),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, fileObject := range page.Contents {
			isDir := strings.HasSuffix(*fileObject.Key, "/")
			if isDir && *fileObject.Size == 0 {
				continue
			}
			numFiles++
			size += *fileObject.Size
		}
		return true
	})
	metric.S3ListObjectsCompleted(err)
	return numFiles, size, err
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (*S3Fs) GetDirSize(dirname string) (int, int64, error) {
	return 0, 0, ErrVfsUnsupported
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// S3 uploads are already atomic, we never call this method for S3
func (*S3Fs) GetAtomicUploadPath(name string) string {
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
		return "/" + rel
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
	prefix := ""
	if root != "/" && root != "." {
		prefix = strings.TrimPrefix(root, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(fs.config.Bucket),
		Prefix: aws.String(prefix),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, fileObject := range page.Contents {
			objectSize := *fileObject.Size
			objectModTime := *fileObject.LastModified
			isDir := strings.HasSuffix(*fileObject.Key, "/")
			name := path.Clean(*fileObject.Key)
			if name == "/" || name == "." {
				continue
			}
			err := walkFn(fs.Join("/", *fileObject.Key), NewFileInfo(name, isDir, objectSize, objectModTime, false), nil)
			if err != nil {
				return false
			}
		}
		return true
	})
	metric.S3ListObjectsCompleted(err)
	walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), err) //nolint:errcheck

	return err
}

// Join joins any number of path elements into a single path
func (*S3Fs) Join(elem ...string) string {
	return path.Join(elem...)
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
	return fs.Join("/", fs.config.KeyPrefix, virtualPath), nil
}

func (fs *S3Fs) resolve(name *string, prefix string) (string, bool) {
	result := strings.TrimPrefix(*name, prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	if strings.Contains(result, "/") {
		i := strings.Index(result, "/")
		isDir = true
		result = result[:i]
	}
	return result, isDir
}

func (fs *S3Fs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	_, err := fs.svc.HeadBucketWithContext(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(fs.config.Bucket),
	})
	metric.S3HeadBucketCompleted(err)
	return err
}

func (fs *S3Fs) hasContents(name string) (bool, error) {
	prefix := ""
	if name != "/" && name != "." {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	maxResults := int64(2)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	results, err := fs.svc.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(fs.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: &maxResults,
	})
	metric.S3ListObjectsCompleted(err)
	if err != nil {
		return false, err
	}
	// MinIO returns no contents while S3 returns 1 object
	// with the key equal to the prefix for empty directories
	for _, obj := range results.Contents {
		name, _ := fs.resolve(obj.Key, prefix)
		if name == "" || name == "/" {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (fs *S3Fs) headObject(name string) (*s3.HeadObjectOutput, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	obj, err := fs.svc.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
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
	return *obj.ContentType, err
}

// Close closes the fs
func (*S3Fs) Close() error {
	return nil
}

// GetAvailableDiskSize return the available size for the specified path
func (*S3Fs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
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
