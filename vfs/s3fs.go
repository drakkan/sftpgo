package vfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/eikenb/pipeat"
)

// S3FsConfig defines the configuration for S3fs
type S3FsConfig struct {
	Bucket       string `json:"bucket,omitempty"`
	Region       string `json:"region,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	AccessSecret string `json:"access_secret,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	StorageClass string `json:"storage_class,omitempty"`
}

// S3Fs is a Fs implementation for Amazon S3 compatible object storage.
type S3Fs struct {
	connectionID   string
	localTempDir   string
	config         S3FsConfig
	svc            *s3.S3
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

// NewS3Fs returns an S3Fs object that allows to interact with an s3 compatible
// object storage
func NewS3Fs(connectionID, localTempDir string, config S3FsConfig) (Fs, error) {
	fs := S3Fs{
		connectionID:   connectionID,
		localTempDir:   localTempDir,
		config:         config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
	if err := ValidateS3FsConfig(&fs.config); err != nil {
		return fs, err
	}
	accessSecret, err := utils.DecryptData(fs.config.AccessSecret)
	if err != nil {
		return fs, err
	}
	fs.config.AccessSecret = accessSecret
	awsConfig := &aws.Config{
		Region:      aws.String(fs.config.Region),
		Credentials: credentials.NewStaticCredentials(fs.config.AccessKey, fs.config.AccessSecret, ""),
	}
	//config.WithLogLevel(aws.LogDebugWithHTTPBody)
	if len(fs.config.Endpoint) > 0 {
		awsConfig.Endpoint = aws.String(fs.config.Endpoint)
		awsConfig.S3ForcePathStyle = aws.Bool(true)
	}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return fs, err
	}
	fs.svc = s3.New(sess)
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs S3Fs) Name() string {
	return fmt.Sprintf("S3Fs bucket: %#v", fs.config.Bucket)
}

// ConnectionID returns the SSH connection ID associated to this Fs implementation
func (fs S3Fs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs S3Fs) Stat(name string) (os.FileInfo, error) {
	var result S3FileInfo
	if name == "/" || name == "." {
		err := fs.checkIfBucketExists()
		if err != nil {
			return result, err
		}
		return NewS3FileInfo(name, true, 0, time.Time{}), nil
	}
	prefix := path.Dir(name)
	if prefix == "/" || prefix == "." {
		prefix = ""
	} else {
		prefix = strings.TrimPrefix(prefix, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, p := range page.CommonPrefixes {
			if fs.isEqual(p.Prefix, name) {
				result = NewS3FileInfo(name, true, 0, time.Time{})
				return false
			}
		}
		for _, fileObject := range page.Contents {
			if fs.isEqual(fileObject.Key, name) {
				objectSize := *fileObject.Size
				objectModTime := *fileObject.LastModified
				isDir := strings.HasSuffix(*fileObject.Key, "/")
				result = NewS3FileInfo(name, isDir, objectSize, objectModTime)
				return false
			}
		}
		return true
	})
	if err == nil && len(result.Name()) == 0 {
		err = errors.New("404 no such file or directory")
	}
	return result, err
}

// Lstat returns a FileInfo describing the named file
func (fs S3Fs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs S3Fs) Open(name string) (*os.File, *pipeat.PipeReaderAt, func(), error) {
	r, w, err := pipeat.AsyncWriterPipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	downloader := s3manager.NewDownloaderWithClient(fs.svc)
	go func() {
		defer cancelFn()
		key := name
		n, err := downloader.DownloadWithContext(ctx, w, &s3.GetObjectInput{
			Bucket: aws.String(fs.config.Bucket),
			Key:    aws.String(key),
		})
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", name, n, err)
		w.CloseWithError(err)
	}()
	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs S3Fs) Create(name string, flag int) (*os.File, *pipeat.PipeWriterAt, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	uploader := s3manager.NewUploaderWithClient(fs.svc)
	go func() {
		defer cancelFn()
		key := name
		response, err := uploader.UploadWithContext(ctx, &s3manager.UploadInput{
			Bucket:       aws.String(fs.config.Bucket),
			Key:          aws.String(key),
			Body:         r,
			StorageClass: utils.NilIfEmpty(fs.config.StorageClass),
		})
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, response: %v, err: %v", name, response, err)
		r.CloseWithError(err)
	}()
	return nil, w, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a CopyObject call.
func (fs S3Fs) Rename(source, target string) error {
	if source == target {
		return nil
	}
	fi, err := fs.Stat(source)
	if err != nil {
		return err
	}
	copySource := fs.Join(fs.config.Bucket, source)
	if fi.IsDir() {
		contents, err := fs.ReadDir(source)
		if err != nil {
			return err
		}
		if len(contents) > 0 {
			return fmt.Errorf("Cannot rename non empty directory: %#v", source)
		}
		if !strings.HasSuffix(copySource, "/") {
			copySource += "/"
		}
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	_, err = fs.svc.CopyObjectWithContext(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(fs.config.Bucket),
		CopySource: aws.String(copySource),
		Key:        aws.String(target),
	})
	if err != nil {
		return err
	}
	return fs.Remove(source, fi.IsDir())
}

// Remove removes the named file or (empty) directory.
func (fs S3Fs) Remove(name string, isDir bool) error {
	if isDir {
		contents, err := fs.ReadDir(name)
		if err != nil {
			return err
		}
		if len(contents) > 0 {
			return fmt.Errorf("Cannot remove non empty directory: %#v", name)
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
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs S3Fs) Mkdir(name string) error {
	_, err := fs.Stat(name)
	if !fs.IsNotExist(err) {
		return err
	}
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	_, w, _, err := fs.Create(name, 0)
	if err != nil {
		return err
	}
	return w.Close()
}

// Symlink creates source as a symbolic link to target.
func (S3Fs) Symlink(source, target string) error {
	return errors.New("403 symlinks are not supported")
}

// Chown changes the numeric uid and gid of the named file.
// Silently ignored.
func (S3Fs) Chown(name string, uid int, gid int) error {
	return nil
}

// Chmod changes the mode of the named file to mode.
// Silently ignored.
func (S3Fs) Chmod(name string, mode os.FileMode) error {
	return nil
}

// Chtimes changes the access and modification times of the named file.
// Silently ignored.
func (S3Fs) Chtimes(name string, atime, mtime time.Time) error {
	return errors.New("403 chtimes is not supported")
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs S3Fs) ReadDir(dirname string) ([]os.FileInfo, error) {
	var result []os.FileInfo
	// dirname deve essere già cleaned
	prefix := ""
	if dirname != "/" && dirname != "." {
		prefix = strings.TrimPrefix(dirname, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(fs.config.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, p := range page.CommonPrefixes {
			name, isDir := fs.resolve(p.Prefix, prefix)
			result = append(result, NewS3FileInfo(name, isDir, 0, time.Time{}))
		}
		for _, fileObject := range page.Contents {
			objectSize := *fileObject.Size
			objectModTime := *fileObject.LastModified
			name, isDir := fs.resolve(fileObject.Key, prefix)
			if len(name) == 0 {
				continue
			}
			result = append(result, NewS3FileInfo(name, isDir, objectSize, objectModTime))
		}
		return true
	})
	return result, err
}

// IsUploadResumeSupported returns true if upload resume is supported.
// SFTP Resume is not supported on S3
func (S3Fs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// S3 uploads are already atomic, we don't need to upload to a temporary
// file
func (S3Fs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (S3Fs) IsNotExist(err error) bool {
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
func (S3Fs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "403")
}

// CheckRootPath creates the specified root directory if it does not exists
func (fs S3Fs) CheckRootPath(rootPath, username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID())
	osFs.CheckRootPath(fs.localTempDir, username, uid, gid)
	err := fs.checkIfBucketExists()
	if err == nil {
		return true
	}
	if !fs.IsNotExist(err) {
		return false
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	input := &s3.CreateBucketInput{
		Bucket: aws.String(fs.config.Bucket),
	}
	_, err = fs.svc.CreateBucketWithContext(ctx, input)
	fsLog(fs, logger.LevelDebug, "bucket %#v for user %#v does not exists, try to create, error: %v",
		fs.config.Bucket, username, err)
	return err == nil
}

// ScanDirContents returns the number of files contained in the bucket,
// and their size
func (fs S3Fs) ScanDirContents(dirPath string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()
	err := fs.svc.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(fs.config.Bucket),
		Prefix: aws.String(""),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, fileObject := range page.Contents {
			numFiles++
			size += *fileObject.Size
		}
		return true
	})

	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// S3 uploads are already atomic, we never call this method for S3
func (S3Fs) GetAtomicUploadPath(name string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTP users
func (S3Fs) GetRelativePath(name, rootPath string) string {
	rel := name
	if name == "." {
		rel = ""
	}
	if !strings.HasPrefix(rel, "/") {
		return "/" + rel
	}
	return rel
}

// Join joins any number of path elements into a single path
func (S3Fs) Join(elem ...string) string {
	return path.Join(elem...)
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs S3Fs) ResolvePath(sftpPath, rootPath string) (string, error) {
	return sftpPath, nil
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

func (fs *S3Fs) isEqual(s3Key *string, sftpName string) bool {
	if *s3Key == sftpName {
		return true
	}
	if "/"+*s3Key == sftpName {
		return true
	}
	if "/"+*s3Key == sftpName+"/" {
		return true
	}
	return false
}

func (fs *S3Fs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	_, err := fs.svc.HeadBucketWithContext(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(fs.config.Bucket),
	})
	return err
}

func (fs *S3Fs) getObjectDetails(key string) (*s3.HeadObjectOutput, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()
	input := &s3.HeadObjectInput{
		Bucket: aws.String(fs.config.Bucket),
		Key:    aws.String(key),
	}
	return fs.svc.HeadObjectWithContext(ctx, input)
}
