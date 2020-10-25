// +build !noazblob

package vfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

const azureDefaultEndpoint = "blob.core.windows.net"

// max time of an azure web request response window (whether or not data is flowing)
// this is the same value used in rclone
var maxTryTimeout = time.Hour * 24 * 365

// AzureBlobFs is a Fs implementation for Azure Blob storage.
type AzureBlobFs struct {
	connectionID   string
	localTempDir   string
	config         AzBlobFsConfig
	svc            *azblob.ServiceURL
	containerURL   azblob.ContainerURL
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

func init() {
	version.AddFeature("+azblob")
}

// NewAzBlobFs returns an AzBlobFs object that allows to interact with Azure Blob storage
func NewAzBlobFs(connectionID, localTempDir string, config AzBlobFsConfig) (Fs, error) {
	fs := AzureBlobFs{
		connectionID:   connectionID,
		localTempDir:   localTempDir,
		config:         config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 300 * time.Second,
	}
	if err := ValidateAzBlobFsConfig(&fs.config); err != nil {
		return fs, err
	}
	if fs.config.AccountKey != "" {
		accountKey, err := utils.DecryptData(fs.config.AccountKey)
		if err != nil {
			return fs, err
		}
		fs.config.AccountKey = accountKey
	}
	setConfigDefaults(&fs)

	if fs.config.SASURL != "" {
		u, err := url.Parse(fs.config.SASURL)
		if err != nil {
			return fs, fmt.Errorf("invalid credentials: %v", err)
		}
		pipeline := azblob.NewPipeline(azblob.NewAnonymousCredential(), azblob.PipelineOptions{
			Retry: azblob.RetryOptions{
				TryTimeout: maxTryTimeout,
			},
			Telemetry: azblob.TelemetryOptions{
				Value: "SFTPGo",
			},
		})
		// Check if we have container level SAS or account level SAS
		parts := azblob.NewBlobURLParts(*u)
		if parts.ContainerName != "" {
			if fs.config.Container != "" && fs.config.Container != parts.ContainerName {
				return fs, fmt.Errorf("Container name in SAS URL %#v and container provided %#v do not match",
					parts.ContainerName, fs.config.Container)
			}
			fs.svc = nil
			fs.containerURL = azblob.NewContainerURL(*u, pipeline)
		} else {
			if fs.config.Container == "" {
				return fs, errors.New("container is required with this SAS URL")
			}
			serviceURL := azblob.NewServiceURL(*u, pipeline)
			fs.svc = &serviceURL
			fs.containerURL = fs.svc.NewContainerURL(fs.config.Container)
		}
		return fs, nil
	}

	credential, err := azblob.NewSharedKeyCredential(fs.config.AccountName, fs.config.AccountKey)
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	var u *url.URL
	if fs.config.UseEmulator {
		// for the emulator we expect the endpoint prefixed with the protocol, for example:
		// http://127.0.0.1:10000
		u, err = url.Parse(fmt.Sprintf("%s/%s", fs.config.Endpoint, fs.config.AccountName))
	} else {
		u, err = url.Parse(fmt.Sprintf("https://%s.%s", fs.config.AccountName, fs.config.Endpoint))
	}
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	pipeline := azblob.NewPipeline(credential, azblob.PipelineOptions{
		Retry: azblob.RetryOptions{
			TryTimeout: maxTryTimeout,
		},
		Telemetry: azblob.TelemetryOptions{
			Value: "SFTPGo",
		},
	})
	serviceURL := azblob.NewServiceURL(*u, pipeline)
	fs.svc = &serviceURL
	fs.containerURL = fs.svc.NewContainerURL(fs.config.Container)
	return fs, nil
}

func setConfigDefaults(fs *AzureBlobFs) {
	if fs.config.Endpoint == "" {
		fs.config.Endpoint = azureDefaultEndpoint
	}
	if fs.config.UploadPartSize == 0 {
		fs.config.UploadPartSize = 4
	}
	fs.config.UploadPartSize *= 1024 * 1024
	if fs.config.UploadConcurrency == 0 {
		fs.config.UploadConcurrency = 2
	}
}

// Name returns the name for the Fs implementation
func (fs AzureBlobFs) Name() string {
	if fs.config.SASURL != "" {
		return fmt.Sprintf("Azure Blob SAS URL %#v", fs.config.Container)
	}
	return fmt.Sprintf("Azure Blob container %#v", fs.config.Container)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs AzureBlobFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs AzureBlobFs) Stat(name string) (os.FileInfo, error) {
	if name == "" || name == "." {
		err := fs.checkIfBucketExists()
		if err != nil {
			return nil, err
		}
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	prefix := fs.getPrefixForStat(name)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	for marker := (azblob.Marker{}); marker.NotDone(); {
		listBlob, err := fs.containerURL.ListBlobsHierarchySegment(ctx, marker, "/", azblob.ListBlobsSegmentOptions{
			Details: azblob.BlobListingDetails{
				Copy:             false,
				Metadata:         false,
				Snapshots:        false,
				UncommittedBlobs: false,
				Deleted:          false,
			},
			Prefix: prefix,
		})
		if err != nil {
			return nil, err
		}
		marker = listBlob.NextMarker
		for _, blobPrefix := range listBlob.Segment.BlobPrefixes {
			if fs.isEqual(blobPrefix.Name, name) {
				return NewFileInfo(name, true, 0, time.Now(), false), nil
			}
		}
		for _, blobInfo := range listBlob.Segment.BlobItems {
			if fs.isEqual(blobInfo.Name, name) {
				isDir := false
				if blobInfo.Properties.ContentType != nil {
					isDir = (*blobInfo.Properties.ContentType == dirMimeType)
				}
				size := int64(0)
				if blobInfo.Properties.ContentLength != nil {
					size = *blobInfo.Properties.ContentLength
				}
				return NewFileInfo(name, isDir, size, blobInfo.Properties.LastModified, false), nil
			}
		}
	}

	return nil, errors.New("404 no such file or directory")
}

// Lstat returns a FileInfo describing the named file
func (fs AzureBlobFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs AzureBlobFs) Open(name string, offset int64) (*os.File, *pipeat.PipeReaderAt, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	ctx, cancelFn := context.WithCancel(context.Background())
	blobDownloadResponse, err := blobBlockURL.Download(ctx, offset, azblob.CountToEnd, azblob.BlobAccessConditions{}, false)
	if err != nil {
		r.Close()
		w.Close()
		cancelFn()
		return nil, nil, nil, err
	}
	body := blobDownloadResponse.Body(azblob.RetryReaderOptions{
		MaxRetryRequests: 3,
	})

	go func() {
		defer cancelFn()
		defer body.Close()

		n, err := io.Copy(w, body)
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", name, n, err)
	}()

	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs AzureBlobFs) Create(name string, flag int) (*os.File, *PipeWriter, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)
	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	ctx, cancelFn := context.WithCancel(context.Background())

	headers := azblob.BlobHTTPHeaders{}
	var contentType string
	if flag == -1 {
		contentType = dirMimeType
	} else {
		contentType = mime.TypeByExtension(path.Ext(name))
	}
	if contentType != "" {
		headers.ContentType = contentType
	}

	go func() {
		defer cancelFn()

		uploadOptions := azblob.UploadStreamToBlockBlobOptions{
			BufferSize:      int(fs.config.UploadPartSize),
			BlobHTTPHeaders: headers,
			MaxBuffers:      fs.config.UploadConcurrency,
		}
		_, err := azblob.UploadStreamToBlockBlob(ctx, r, blobBlockURL, uploadOptions)
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %v", name, r.GetReadedBytes(), err)
	}()

	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a StartCopyFromURL call.
func (fs AzureBlobFs) Rename(source, target string) error {
	if source == target {
		return nil
	}
	fi, err := fs.Stat(source)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		contents, err := fs.ReadDir(source)
		if err != nil {
			return err
		}
		if len(contents) > 0 {
			return fmt.Errorf("Cannot rename non empty directory: %#v", source)
		}
	}
	dstBlobURL := fs.containerURL.NewBlobURL(target)
	srcURL := fs.containerURL.NewBlobURL(source).URL()

	md := azblob.Metadata{}
	mac := azblob.ModifiedAccessConditions{}
	bac := azblob.BlobAccessConditions{}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := dstBlobURL.StartCopyFromURL(ctx, srcURL, md, mac, bac)
	if err != nil {
		return err
	}
	copyStatus := resp.CopyStatus()
	nErrors := 0
	for copyStatus == azblob.CopyStatusPending {
		// Poll until the copy is complete.
		time.Sleep(500 * time.Millisecond)
		propertiesResp, err := dstBlobURL.GetProperties(ctx, azblob.BlobAccessConditions{})
		if err != nil {
			// A GetProperties failure may be transient, so allow a couple
			// of them before giving up.
			nErrors++
			if ctx.Err() != nil || nErrors == 3 {
				return err
			}
		} else {
			copyStatus = propertiesResp.CopyStatus()
		}
	}
	if copyStatus != azblob.CopyStatusSuccess {
		return fmt.Errorf("Copy failed with status: %s", copyStatus)
	}
	return fs.Remove(source, fi.IsDir())
}

// Remove removes the named file or (empty) directory.
func (fs AzureBlobFs) Remove(name string, isDir bool) error {
	if isDir {
		contents, err := fs.ReadDir(name)
		if err != nil {
			return err
		}
		if len(contents) > 0 {
			return fmt.Errorf("Cannot remove non empty directory: %#v", name)
		}
	}
	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := blobBlockURL.Delete(ctx, azblob.DeleteSnapshotsOptionNone, azblob.BlobAccessConditions{})
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs AzureBlobFs) Mkdir(name string) error {
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
func (AzureBlobFs) Symlink(source, target string) error {
	return errors.New("403 symlinks are not supported")
}

// Readlink returns the destination of the named symbolic link
func (AzureBlobFs) Readlink(name string) (string, error) {
	return "", errors.New("403 readlink is not supported")
}

// Chown changes the numeric uid and gid of the named file.
// Silently ignored.
func (AzureBlobFs) Chown(name string, uid int, gid int) error {
	return nil
}

// Chmod changes the mode of the named file to mode.
// Silently ignored.
func (AzureBlobFs) Chmod(name string, mode os.FileMode) error {
	return nil
}

// Chtimes changes the access and modification times of the named file.
// Silently ignored.
func (AzureBlobFs) Chtimes(name string, atime, mtime time.Time) error {
	return errors.New("403 chtimes is not supported")
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (AzureBlobFs) Truncate(name string, size int64) error {
	return errors.New("403 truncate is not supported")
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs AzureBlobFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	var result []os.FileInfo
	// dirname must be already cleaned
	prefix := ""
	if dirname != "" && dirname != "." {
		prefix = strings.TrimPrefix(dirname, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}

	prefixes := make(map[string]bool)

	for marker := (azblob.Marker{}); marker.NotDone(); {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		listBlob, err := fs.containerURL.ListBlobsHierarchySegment(ctx, marker, "/", azblob.ListBlobsSegmentOptions{
			Details: azblob.BlobListingDetails{
				Copy:             false,
				Metadata:         false,
				Snapshots:        false,
				UncommittedBlobs: false,
				Deleted:          false,
			},
			Prefix: prefix,
		})
		if err != nil {
			return nil, err
		}
		marker = listBlob.NextMarker
		for _, blobPrefix := range listBlob.Segment.BlobPrefixes {
			// we don't support prefixes == "/" this will be sent if a key starts with "/"
			if blobPrefix.Name == "/" {
				continue
			}
			name := strings.TrimPrefix(blobPrefix.Name, prefix)
			result = append(result, NewFileInfo(name, true, 0, time.Now(), false))
			prefixes[strings.TrimSuffix(name, "/")] = true
		}
		for _, blobInfo := range listBlob.Segment.BlobItems {
			name := strings.TrimPrefix(blobInfo.Name, prefix)
			size := int64(0)
			if blobInfo.Properties.ContentLength != nil {
				size = *blobInfo.Properties.ContentLength
			}
			isDir := false
			if blobInfo.Properties.ContentType != nil {
				isDir = (*blobInfo.Properties.ContentType == dirMimeType)
				if isDir {
					// check if the dir is already included, it will be sent as blob prefix if it contains at least one item
					if _, ok := prefixes[name]; ok {
						continue
					}
				}
			}
			result = append(result, NewFileInfo(name, isDir, size, blobInfo.Properties.LastModified, false))
		}
	}

	return result, nil
}

// IsUploadResumeSupported returns true if upload resume is supported.
// Upload Resume is not supported on Azure Blob
func (AzureBlobFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// Azure Blob uploads are already atomic, we don't need to upload to a temporary
// file
func (AzureBlobFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (AzureBlobFs) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	if storageErr, ok := err.(azblob.StorageError); ok {
		if storageErr.Response().StatusCode == http.StatusNotFound { //nolint:bodyclose
			return true
		}
		if storageErr.ServiceCode() == azblob.ServiceCodeContainerNotFound ||
			storageErr.ServiceCode() == azblob.ServiceCodeBlobNotFound {
			return true
		}
	}

	return strings.Contains(err.Error(), "404")
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (AzureBlobFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	if storageErr, ok := err.(azblob.StorageError); ok {
		code := storageErr.Response().StatusCode //nolint:bodyclose
		if code == http.StatusForbidden || code == http.StatusUnauthorized {
			return true
		}
		if storageErr.ServiceCode() == azblob.ServiceCodeInsufficientAccountPermissions ||
			storageErr.ServiceCode() == azblob.ServiceCodeInvalidAuthenticationInfo ||
			storageErr.ServiceCode() == azblob.ServiceCodeUnauthorizedBlobOverwrite {
			return true
		}
	}
	return strings.Contains(err.Error(), "403")
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs AzureBlobFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs AzureBlobFs) ScanRootDirContents() (int, int64, error) {
	numFiles := 0
	size := int64(0)

	for marker := (azblob.Marker{}); marker.NotDone(); {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		listBlob, err := fs.containerURL.ListBlobsFlatSegment(ctx, marker, azblob.ListBlobsSegmentOptions{
			Details: azblob.BlobListingDetails{
				Copy:             false,
				Metadata:         false,
				Snapshots:        false,
				UncommittedBlobs: false,
				Deleted:          false,
			},
			Prefix: fs.config.KeyPrefix,
		})
		if err != nil {
			return numFiles, size, err
		}
		marker = listBlob.NextMarker
		for _, blobInfo := range listBlob.Segment.BlobItems {
			isDir := false
			if blobInfo.Properties.ContentType != nil {
				isDir = (*blobInfo.Properties.ContentType == dirMimeType)
			}
			blobSize := int64(0)
			if blobInfo.Properties.ContentLength != nil {
				blobSize = *blobInfo.Properties.ContentLength
			}
			if isDir && blobSize == 0 {
				continue
			}
			numFiles++
			size += blobSize
		}
	}

	return numFiles, size, nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (AzureBlobFs) GetDirSize(dirname string) (int, int64, error) {
	return 0, 0, errUnsupported
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// Azure Blob Storage uploads are already atomic, we never call this method
func (AzureBlobFs) GetAtomicUploadPath(name string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs AzureBlobFs) GetRelativePath(name string) string {
	rel := path.Clean(name)
	if rel == "." {
		rel = ""
	}
	if !path.IsAbs(rel) {
		rel = "/" + rel
	}
	if len(fs.config.KeyPrefix) > 0 {
		if !strings.HasPrefix(rel, "/"+fs.config.KeyPrefix) {
			rel = "/"
		}
		rel = path.Clean("/" + strings.TrimPrefix(rel, "/"+fs.config.KeyPrefix))
	}
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root
func (fs AzureBlobFs) Walk(root string, walkFn filepath.WalkFunc) error {
	prefix := ""
	if root != "" && root != "." {
		prefix = strings.TrimPrefix(root, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	for marker := (azblob.Marker{}); marker.NotDone(); {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		listBlob, err := fs.containerURL.ListBlobsFlatSegment(ctx, marker, azblob.ListBlobsSegmentOptions{
			Details: azblob.BlobListingDetails{
				Copy:             false,
				Metadata:         false,
				Snapshots:        false,
				UncommittedBlobs: false,
				Deleted:          false,
			},
			Prefix: prefix,
		})
		if err != nil {
			return err
		}
		marker = listBlob.NextMarker
		for _, blobInfo := range listBlob.Segment.BlobItems {
			isDir := false
			if blobInfo.Properties.ContentType != nil {
				isDir = (*blobInfo.Properties.ContentType == dirMimeType)
			}
			name := path.Clean(blobInfo.Name)
			if len(name) == 0 {
				continue
			}
			blobSize := int64(0)
			if blobInfo.Properties.ContentLength != nil {
				blobSize = *blobInfo.Properties.ContentLength
			}
			err = walkFn(blobInfo.Name, NewFileInfo(name, isDir, blobSize, blobInfo.Properties.LastModified, false), nil)
			if err != nil {
				return err
			}
		}
	}

	return walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), nil)
}

// Join joins any number of path elements into a single path
func (AzureBlobFs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (AzureBlobFs) HasVirtualFolders() bool {
	return true
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs AzureBlobFs) ResolvePath(virtualPath string) (string, error) {
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return fs.Join(fs.config.KeyPrefix, strings.TrimPrefix(virtualPath, "/")), nil
}

// GetMimeType implements MimeTyper interface
func (fs AzureBlobFs) GetMimeType(name string) (string, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	response, err := blobBlockURL.GetProperties(ctx, azblob.BlobAccessConditions{})
	if err != nil {
		return "", err
	}
	return response.ContentType(), nil
}

func (fs *AzureBlobFs) isEqual(key string, virtualName string) bool {
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

func (fs *AzureBlobFs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.containerURL.GetProperties(ctx, azblob.LeaseAccessConditions{})
	return err
}

func (fs *AzureBlobFs) getPrefixForStat(name string) string {
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
