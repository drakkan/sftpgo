//go:build !nos3
// +build !nos3

package vfs

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
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

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

const (
	// using this mime type for directories improves compatibility with s3fs-fuse
	s3DirMimeType        = "application/x-directory"
	s3TransferBufferSize = 256 * 1024
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
		if tempPath != "" {
			localTempDir = tempPath
		} else {
			localTempDir = filepath.Clean(os.TempDir())
		}
	}
	fs := &S3Fs{
		connectionID: connectionID,
		localTempDir: localTempDir,
		mountPath:    getMountPath(mountPath),
		config:       &s3Config,
		ctxTimeout:   30 * time.Second,
	}
	if err := fs.config.Validate(); err != nil {
		return fs, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithHTTPClient(getAWSHTTPClient(0, 30*time.Second)))
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
	if fs.config.Endpoint != "" {
		endpointResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               fs.config.Endpoint,
				HostnameImmutable: fs.config.ForcePathStyle,
				PartitionID:       "aws",
				SigningRegion:     fs.config.Region,
				Source:            aws.EndpointSourceCustom,
			}, nil
		})
		awsConfig.EndpointResolverWithOptions = endpointResolver
	}

	fs.setConfigDefaults()

	if fs.config.RoleARN != "" {
		client := sts.NewFromConfig(awsConfig)
		creds := stscreds.NewAssumeRoleProvider(client, fs.config.RoleARN)
		awsConfig.Credentials = creds
	}
	fs.svc = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		o.UsePathStyle = fs.config.ForcePathStyle
	})
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
	if name == "" || name == "/" || name == "." {
		err := fs.checkIfBucketExists()
		if err != nil {
			return result, err
		}
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Now(), false))
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	obj, err := fs.headObject(name)
	if err == nil {
		// a "dir" has a trailing "/" so we cannot have a directory here
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, false, obj.ContentLength,
			util.GetTimeFromPointer(obj.LastModified), false))
	}
	if !fs.IsNotExist(err) {
		return result, err
	}
	// now check if this is a prefix (virtual directory)
	hasContents, err := fs.hasContents(name)
	if err == nil && hasContents {
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Now(), false))
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
	return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, obj.ContentLength,
		util.GetTimeFromPointer(obj.LastModified), false))
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
	downloader := manager.NewDownloader(fs.svc, func(d *manager.Downloader) {
		d.Concurrency = fs.config.DownloadConcurrency
		d.PartSize = fs.config.DownloadPartSize
		if offset == 0 && fs.config.DownloadPartMaxTime > 0 {
			d.ClientOptions = append(d.ClientOptions, func(o *s3.Options) {
				o.HTTPClient = getAWSHTTPClient(fs.config.DownloadPartMaxTime, 100*time.Millisecond)
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
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %+v", name, n, err)
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
	uploader := manager.NewUploader(fs.svc, func(u *manager.Uploader) {
		u.Concurrency = fs.config.UploadConcurrency
		u.PartSize = fs.config.UploadPartSize
		if fs.config.UploadPartMaxTime > 0 {
			u.ClientOptions = append(u.ClientOptions, func(o *s3.Options) {
				o.HTTPClient = getAWSHTTPClient(fs.config.UploadPartMaxTime, 100*time.Millisecond)
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
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, acl: %#v, readed bytes: %v, err: %+v",
			name, fs.config.ACL, r.GetReadedBytes(), err)
		metric.S3TransferCompleted(r.GetReadedBytes(), 0, err)
	}()
	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a CopyObject call.
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
	copySource = pathEscape(copySource)

	if fi.Size() > 5*1024*1024*1024 {
		fsLog(fs, logger.LevelDebug, "renaming file %#v with size %v, a multipart copy is required, this may take a while",
			source, fi.Size())
		err = fs.doMultipartCopy(copySource, target, contentType, fi.Size())
	} else {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		_, err = fs.svc.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:       aws.String(fs.config.Bucket),
			CopySource:   aws.String(copySource),
			Key:          aws.String(target),
			StorageClass: types.StorageClass(fs.config.StorageClass),
			ACL:          types.ObjectCannedACL(fs.config.ACL),
			ContentType:  util.NilIfEmpty(contentType),
		})
	}
	if err != nil {
		metric.S3CopyObjectCompleted(err)
		return err
	}

	waiter := s3.NewObjectExistsWaiter(fs.svc)
	err = waiter.Wait(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(target),
	}, 10*time.Second)
	metric.S3CopyObjectCompleted(err)
	if err != nil {
		return err
	}
	if plugin.Handler.HasMetadater() {
		if !fi.IsDir() {
			err = plugin.Handler.SetModificationTime(fs.getStorageID(), ensureAbsPath(target),
				util.GetTimeAsMsSinceEpoch(fi.ModTime()))
			if err != nil {
				fsLog(fs, logger.LevelWarn, "unable to preserve modification time after renaming %#v -> %#v: %+v",
					source, target, err)
			}
		}
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

	_, err := fs.svc.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(name),
	})
	metric.S3DeleteObjectCompleted(err)
	if plugin.Handler.HasMetadater() && err == nil && !isDir {
		if errMetadata := plugin.Handler.RemoveMetadata(fs.getStorageID(), ensureAbsPath(name)); errMetadata != nil {
			fsLog(fs, logger.LevelWarn, "unable to remove metadata for path %#v: %+v", name, errMetadata)
		}
	}
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
func (fs *S3Fs) Chtimes(name string, atime, mtime time.Time, isUploading bool) error {
	if !plugin.Handler.HasMetadater() {
		return ErrVfsUnsupported
	}
	if !isUploading {
		info, err := fs.Stat(name)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return ErrVfsUnsupported
		}
	}
	return plugin.Handler.SetModificationTime(fs.getStorageID(), ensureAbsPath(name),
		util.GetTimeAsMsSinceEpoch(mtime))
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
	prefix := fs.getPrefix(dirname)

	modTimes, err := getFolderModTimes(fs.getStorageID(), dirname)
	if err != nil {
		return result, err
	}
	prefixes := make(map[string]bool)

	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})

	for paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			metric.S3ListObjectsCompleted(err)
			return result, err
		}
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
			objectModTime := util.GetTimeFromPointer(fileObject.LastModified)
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if name == "" || name == "/" {
				continue
			}
			if isDir {
				if _, ok := prefixes[name]; ok {
					continue
				}
				prefixes[name] = true
			}
			if t, ok := modTimes[name]; ok {
				objectModTime = util.GetTimeFromMsecSinceEpoch(t)
			}
			result = append(result, NewFileInfo(name, (isDir && fileObject.Size == 0), fileObject.Size,
				objectModTime, false))
		}
	}

	metric.S3ListObjectsCompleted(nil)
	return result, nil
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

	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket: aws.String(fs.config.Bucket),
		Prefix: aws.String(fs.config.KeyPrefix),
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
			if isDir && fileObject.Size == 0 {
				continue
			}
			numFiles++
			size += fileObject.Size
		}
	}

	metric.S3ListObjectsCompleted(nil)
	return numFiles, size, nil
}

func (fs *S3Fs) getFileNamesInPrefix(fsPrefix string) (map[string]bool, error) {
	fileNames := make(map[string]bool)
	prefix := ""
	if fsPrefix != "/" {
		prefix = strings.TrimPrefix(fsPrefix, "/")
	}

	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})

	for paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			metric.S3ListObjectsCompleted(err)
			if err != nil {
				fsLog(fs, logger.LevelError, "unable to get content for prefix %#v: %+v", prefix, err)
				return nil, err
			}
			return fileNames, err
		}
		for _, fileObject := range page.Contents {
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if name != "" && !isDir {
				fileNames[name] = true
			}
		}
	}

	metric.S3ListObjectsCompleted(nil)
	return fileNames, nil
}

// CheckMetadata checks the metadata consistency
func (fs *S3Fs) CheckMetadata() error {
	return fsMetadataCheck(fs, fs.getStorageID(), fs.config.KeyPrefix)
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
		Bucket: aws.String(fs.config.Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		page, err := paginator.NextPage(ctx)
		if err != nil {
			metric.S3ListObjectsCompleted(err)
			walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), err) //nolint:errcheck
			return err
		}
		for _, fileObject := range page.Contents {
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if name == "" {
				continue
			}
			err := walkFn(util.GetStringFromPointer(fileObject.Key),
				NewFileInfo(name, isDir, fileObject.Size, util.GetTimeFromPointer(fileObject.LastModified), false), nil)
			if err != nil {
				return err
			}
		}
	}

	metric.S3ListObjectsCompleted(nil)
	walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), nil) //nolint:errcheck
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

func (fs *S3Fs) resolve(name *string, prefix string) (string, bool) {
	result := strings.TrimPrefix(util.GetStringFromPointer(name), prefix)
	isDir := strings.HasSuffix(result, "/")
	if isDir {
		result = strings.TrimSuffix(result, "/")
	}
	return result, isDir
}

func (fs *S3Fs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.svc.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(fs.config.Bucket),
	})
	metric.S3HeadBucketCompleted(err)
	return err
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

func (fs *S3Fs) hasContents(name string) (bool, error) {
	prefix := fs.getPrefix(name)
	paginator := s3.NewListObjectsV2Paginator(fs.svc, &s3.ListObjectsV2Input{
		Bucket:  aws.String(fs.config.Bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: 2,
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
	maxPartSize := int64(500 * 1024 * 1024)
	completedParts := make([]types.CompletedPart, 0)
	partNumber := int32(1)

	for copied := int64(0); copied < fileSize; copied += maxPartSize {
		innerCtx, innerCancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer innerCancelFn()

		partResp, err := fs.svc.UploadPartCopy(innerCtx, &s3.UploadPartCopyInput{
			Bucket:          aws.String(fs.config.Bucket),
			CopySource:      aws.String(source),
			Key:             aws.String(target),
			PartNumber:      partNumber,
			UploadId:        aws.String(uploadID),
			CopySourceRange: aws.String(getMultipartCopyRange(copied, maxPartSize, fileSize)),
		})
		if err != nil {
			fsLog(fs, logger.LevelError, "unable to copy part number %v: %+v", partNumber, err)
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
			return fmt.Errorf("error copying part number %v: %w", partNumber, err)
		}
		completedParts = append(completedParts, types.CompletedPart{
			ETag:       partResp.CopyPartResult.ETag,
			PartNumber: partNumber,
		})
		partNumber++
	}

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

// GetAvailableDiskSize return the available size for the specified path
func (*S3Fs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
}

func (fs *S3Fs) getStorageID() string {
	if fs.config.Endpoint != "" {
		if !strings.HasSuffix(fs.config.Endpoint, "/") {
			return fmt.Sprintf("s3://%v/%v", fs.config.Endpoint, fs.config.Bucket)
		}
		return fmt.Sprintf("s3://%v%v", fs.config.Endpoint, fs.config.Bucket)
	}
	return fmt.Sprintf("s3://%v", fs.config.Bucket)
}

func getMultipartCopyRange(start, maxPartSize, fileSize int64) string {
	end := start + maxPartSize - 1
	if end > fileSize {
		end = fileSize - 1
	}

	return fmt.Sprintf("bytes=%v-%v", start, end)
}

func getAWSHTTPClient(timeout int, idleConnectionTimeout time.Duration) *awshttp.BuildableClient {
	c := awshttp.NewBuildableClient().
		WithDialerOptions(func(d *net.Dialer) {
			d.Timeout = 8 * time.Second
		}).
		WithTransportOptions(func(tr *http.Transport) {
			tr.IdleConnTimeout = idleConnectionTimeout
			tr.ResponseHeaderTimeout = 5 * time.Second
			tr.WriteBufferSize = s3TransferBufferSize
			tr.ReadBufferSize = s3TransferBufferSize
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
