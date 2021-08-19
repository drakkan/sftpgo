//go:build !noazblob
// +build !noazblob

package vfs

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"sync"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/version"
)

const azureDefaultEndpoint = "blob.core.windows.net"

// max time of an azure web request response window (whether or not data is flowing)
// this is the same value used in rclone
var maxTryTimeout = time.Hour * 24 * 365

// AzureBlobFs is a Fs implementation for Azure Blob storage.
type AzureBlobFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath      string
	config         *AzBlobFsConfig
	svc            *azblob.ServiceURL
	containerURL   azblob.ContainerURL
	ctxTimeout     time.Duration
	ctxLongTimeout time.Duration
}

func init() {
	version.AddFeature("+azblob")
}

// NewAzBlobFs returns an AzBlobFs object that allows to interact with Azure Blob storage
func NewAzBlobFs(connectionID, localTempDir, mountPath string, config AzBlobFsConfig) (Fs, error) {
	if localTempDir == "" {
		if tempPath != "" {
			localTempDir = tempPath
		} else {
			localTempDir = filepath.Clean(os.TempDir())
		}
	}
	fs := &AzureBlobFs{
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

	if err := fs.config.AccountKey.TryDecrypt(); err != nil {
		return fs, err
	}
	if err := fs.config.SASURL.TryDecrypt(); err != nil {
		return fs, err
	}
	fs.setConfigDefaults()

	version := version.Get()
	telemetryValue := fmt.Sprintf("SFTPGo-%v_%v", version.Version, version.CommitHash)

	if fs.config.SASURL.GetPayload() != "" {
		u, err := url.Parse(fs.config.SASURL.GetPayload())
		if err != nil {
			return fs, fmt.Errorf("invalid credentials: %v", err)
		}
		pipeline := azblob.NewPipeline(azblob.NewAnonymousCredential(), azblob.PipelineOptions{
			Retry: azblob.RetryOptions{
				TryTimeout: maxTryTimeout,
			},
			Telemetry: azblob.TelemetryOptions{
				Value: telemetryValue,
			},
		})
		// Check if we have container level SAS or account level SAS
		parts := azblob.NewBlobURLParts(*u)
		if parts.ContainerName != "" {
			if fs.config.Container != "" && fs.config.Container != parts.ContainerName {
				return fs, fmt.Errorf("container name in SAS URL %#v and container provided %#v do not match",
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

	credential, err := azblob.NewSharedKeyCredential(fs.config.AccountName, fs.config.AccountKey.GetPayload())
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
			Value: telemetryValue,
		},
	})
	serviceURL := azblob.NewServiceURL(*u, pipeline)
	fs.svc = &serviceURL
	fs.containerURL = fs.svc.NewContainerURL(fs.config.Container)
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *AzureBlobFs) Name() string {
	if !fs.config.SASURL.IsEmpty() {
		return fmt.Sprintf("Azure Blob with SAS URL, container %#v", fs.config.Container)
	}
	return fmt.Sprintf("Azure Blob container %#v", fs.config.Container)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *AzureBlobFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *AzureBlobFs) Stat(name string) (os.FileInfo, error) {
	if name == "" || name == "." {
		if fs.svc != nil {
			err := fs.checkIfBucketExists()
			if err != nil {
				return nil, err
			}
		}
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	if fs.config.KeyPrefix == name+"/" {
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}

	attrs, err := fs.headObject(name)
	if err == nil {
		isDir := (attrs.ContentType() == dirMimeType)
		metric.AZListObjectsCompleted(nil)
		return NewFileInfo(name, isDir, attrs.ContentLength(), attrs.LastModified(), false), nil
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
		return NewFileInfo(name, true, 0, time.Now(), false), nil
	}
	return nil, errors.New("404 no such file or directory")
}

// Lstat returns a FileInfo describing the named file
func (fs *AzureBlobFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *AzureBlobFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	ctx, cancelFn := context.WithCancel(context.Background())
	blobDownloadResponse, err := blobBlockURL.Download(ctx, offset, azblob.CountToEnd, azblob.BlobAccessConditions{}, false,
		azblob.ClientProvidedKeyOptions{})
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
		metric.AZTransferCompleted(n, 1, err)
	}()

	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *AzureBlobFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
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

		/*uploadOptions := azblob.UploadStreamToBlockBlobOptions{
			BufferSize:      int(fs.config.UploadPartSize),
			BlobHTTPHeaders: headers,
			MaxBuffers:      fs.config.UploadConcurrency,
		}
		// UploadStreamToBlockBlob seems to have issues if there is an error, for example
		// if we shutdown Azurite while uploading it hangs, so we use our own wrapper for
		// the low level functions
		_, err := azblob.UploadStreamToBlockBlob(ctx, r, blobBlockURL, uploadOptions)*/
		err := fs.handleMultipartUpload(ctx, r, &blobBlockURL, &headers)
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %v", name, r.GetReadedBytes(), err)
		metric.AZTransferCompleted(r.GetReadedBytes(), 0, err)
	}()

	return nil, p, cancelFn, nil
}

// Rename renames (moves) source to target.
// We don't support renaming non empty directories since we should
// rename all the contents too and this could take long time: think
// about directories with thousands of files, for each file we should
// execute a StartCopyFromURL call.
func (fs *AzureBlobFs) Rename(source, target string) error {
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
			return fmt.Errorf("cannot rename non empty directory: %#v", source)
		}
	}
	dstBlobURL := fs.containerURL.NewBlobURL(target)
	srcURL := fs.containerURL.NewBlobURL(source).URL()

	md := azblob.Metadata{}
	mac := azblob.ModifiedAccessConditions{}
	bac := azblob.BlobAccessConditions{}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := dstBlobURL.StartCopyFromURL(ctx, srcURL, md, mac, bac, azblob.AccessTierType(fs.config.AccessTier), nil)
	if err != nil {
		metric.AZCopyObjectCompleted(err)
		return err
	}
	copyStatus := resp.CopyStatus()
	nErrors := 0
	for copyStatus == azblob.CopyStatusPending {
		// Poll until the copy is complete.
		time.Sleep(500 * time.Millisecond)
		propertiesResp, err := dstBlobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
		if err != nil {
			// A GetProperties failure may be transient, so allow a couple
			// of them before giving up.
			nErrors++
			if ctx.Err() != nil || nErrors == 3 {
				metric.AZCopyObjectCompleted(err)
				return err
			}
		} else {
			copyStatus = propertiesResp.CopyStatus()
		}
	}
	if copyStatus != azblob.CopyStatusSuccess {
		err := fmt.Errorf("copy failed with status: %s", copyStatus)
		metric.AZCopyObjectCompleted(err)
		return err
	}
	metric.AZCopyObjectCompleted(nil)
	return fs.Remove(source, fi.IsDir())
}

// Remove removes the named file or (empty) directory.
func (fs *AzureBlobFs) Remove(name string, isDir bool) error {
	if isDir {
		hasContents, err := fs.hasContents(name)
		if err != nil {
			return err
		}
		if hasContents {
			return fmt.Errorf("cannot remove non empty directory: %#v", name)
		}
	}
	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := blobBlockURL.Delete(ctx, azblob.DeleteSnapshotsOptionNone, azblob.BlobAccessConditions{})
	metric.AZDeleteObjectCompleted(err)
	return err
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *AzureBlobFs) Mkdir(name string) error {
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

// MkdirAll does nothing, we don't have folder
func (*AzureBlobFs) MkdirAll(name string, uid int, gid int) error {
	return nil
}

// Symlink creates source as a symbolic link to target.
func (*AzureBlobFs) Symlink(source, target string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*AzureBlobFs) Readlink(name string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*AzureBlobFs) Chown(name string, uid int, gid int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*AzureBlobFs) Chmod(name string, mode os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (*AzureBlobFs) Chtimes(name string, atime, mtime time.Time) error {
	return ErrVfsUnsupported
}

// Truncate changes the size of the named file.
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
func (*AzureBlobFs) Truncate(name string, size int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *AzureBlobFs) ReadDir(dirname string) ([]os.FileInfo, error) {
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
			metric.AZListObjectsCompleted(err)
			return nil, err
		}
		marker = listBlob.NextMarker
		for _, blobPrefix := range listBlob.Segment.BlobPrefixes {
			// we don't support prefixes == "/" this will be sent if a key starts with "/"
			if blobPrefix.Name == "/" {
				continue
			}
			// sometime we have duplicate prefixes, maybe an Azurite bug
			name := strings.TrimPrefix(blobPrefix.Name, prefix)
			if _, ok := prefixes[strings.TrimSuffix(name, "/")]; ok {
				continue
			}
			result = append(result, NewFileInfo(name, true, 0, time.Now(), false))
			prefixes[strings.TrimSuffix(name, "/")] = true
		}
		for idx := range listBlob.Segment.BlobItems {
			blobInfo := &listBlob.Segment.BlobItems[idx]
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
					prefixes[name] = true
				}
			}
			result = append(result, NewFileInfo(name, isDir, size, blobInfo.Properties.LastModified, false))
		}
	}

	metric.AZListObjectsCompleted(nil)
	return result, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on Azure Blob
func (*AzureBlobFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// Azure Blob uploads are already atomic, we don't need to upload to a temporary
// file
func (*AzureBlobFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (*AzureBlobFs) IsNotExist(err error) bool {
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
func (*AzureBlobFs) IsPermission(err error) bool {
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

// IsNotSupported returns true if the error indicate an unsupported operation
func (*AzureBlobFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *AzureBlobFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "")
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *AzureBlobFs) ScanRootDirContents() (int, int64, error) {
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
			metric.AZListObjectsCompleted(err)
			return numFiles, size, err
		}
		marker = listBlob.NextMarker
		for idx := range listBlob.Segment.BlobItems {
			blobInfo := &listBlob.Segment.BlobItems[idx]
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

	metric.AZListObjectsCompleted(nil)
	return numFiles, size, nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (*AzureBlobFs) GetDirSize(dirname string) (int, int64, error) {
	return 0, 0, ErrVfsUnsupported
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
// Azure Blob Storage uploads are already atomic, we never call this method
func (*AzureBlobFs) GetAtomicUploadPath(name string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *AzureBlobFs) GetRelativePath(name string) string {
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
func (fs *AzureBlobFs) Walk(root string, walkFn filepath.WalkFunc) error {
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
			metric.AZListObjectsCompleted(err)
			return err
		}
		marker = listBlob.NextMarker
		for idx := range listBlob.Segment.BlobItems {
			blobInfo := &listBlob.Segment.BlobItems[idx]
			isDir := false
			if blobInfo.Properties.ContentType != nil {
				isDir = (*blobInfo.Properties.ContentType == dirMimeType)
			}
			if fs.isEqual(blobInfo.Name, prefix) {
				continue
			}
			blobSize := int64(0)
			if blobInfo.Properties.ContentLength != nil {
				blobSize = *blobInfo.Properties.ContentLength
			}
			err = walkFn(blobInfo.Name, NewFileInfo(blobInfo.Name, isDir, blobSize, blobInfo.Properties.LastModified, false), nil)
			if err != nil {
				return err
			}
		}
	}

	metric.AZListObjectsCompleted(nil)
	return walkFn(root, NewFileInfo(root, true, 0, time.Now(), false), nil)
}

// Join joins any number of path elements into a single path
func (*AzureBlobFs) Join(elem ...string) string {
	return strings.TrimPrefix(path.Join(elem...), "/")
}

// HasVirtualFolders returns true if folders are emulated
func (*AzureBlobFs) HasVirtualFolders() bool {
	return true
}

// ResolvePath returns the matching filesystem path for the specified sftp path
func (fs *AzureBlobFs) ResolvePath(virtualPath string) (string, error) {
	if fs.mountPath != "" {
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}
	return fs.Join(fs.config.KeyPrefix, strings.TrimPrefix(virtualPath, "/")), nil
}

func (fs *AzureBlobFs) headObject(name string) (*azblob.BlobGetPropertiesResponse, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	blobBlockURL := fs.containerURL.NewBlockBlobURL(name)
	response, err := blobBlockURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	metric.AZHeadObjectCompleted(err)
	return response, err
}

// GetMimeType returns the content type
func (fs *AzureBlobFs) GetMimeType(name string) (string, error) {
	response, err := fs.headObject(name)
	if err != nil {
		return "", err
	}
	return response.ContentType(), nil
}

// Close closes the fs
func (*AzureBlobFs) Close() error {
	return nil
}

// GetAvailableDiskSize return the available size for the specified path
func (*AzureBlobFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
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

func (fs *AzureBlobFs) setConfigDefaults() {
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
	if fs.config.AccessTier == "" {
		fs.config.AccessTier = string(azblob.AccessTierNone)
	}
}

func (fs *AzureBlobFs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.containerURL.GetProperties(ctx, azblob.LeaseAccessConditions{})
	metric.AZHeadContainerCompleted(err)
	return err
}

func (fs *AzureBlobFs) hasContents(name string) (bool, error) {
	result := false
	prefix := ""
	if name != "" && name != "." {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	listBlob, err := fs.containerURL.ListBlobsFlatSegment(ctx, azblob.Marker{}, azblob.ListBlobsSegmentOptions{
		Details: azblob.BlobListingDetails{
			Copy:             false,
			Metadata:         false,
			Snapshots:        false,
			UncommittedBlobs: false,
			Deleted:          false,
		},
		Prefix:     prefix,
		MaxResults: 1,
	})
	metric.AZListObjectsCompleted(err)
	if err != nil {
		return result, err
	}
	result = len(listBlob.Segment.BlobItems) > 0
	return result, err
}

func (fs *AzureBlobFs) handleMultipartUpload(ctx context.Context, reader io.Reader, blockBlobURL *azblob.BlockBlobURL,
	httpHeaders *azblob.BlobHTTPHeaders) error {
	partSize := fs.config.UploadPartSize
	guard := make(chan struct{}, fs.config.UploadConcurrency)
	blockCtxTimeout := time.Duration(fs.config.UploadPartSize/(1024*1024)) * time.Minute

	// sync.Pool seems to use a lot of memory so prefer our own, very simple, allocator
	// we only need to recycle few byte slices
	pool := newBufferAllocator(int(partSize))
	finished := false
	binaryBlockID := make([]byte, 8)
	var blocks []string
	var wg sync.WaitGroup
	var errOnce sync.Once
	var poolError error

	poolCtx, poolCancel := context.WithCancel(ctx)
	defer poolCancel()

	for part := 0; !finished; part++ {
		buf := pool.getBuffer()

		n, err := fs.readFill(reader, buf)
		if err == io.EOF {
			// read finished, if n > 0 we need to process the last data chunck
			if n == 0 {
				pool.releaseBuffer(buf)
				break
			}
			finished = true
		} else if err != nil {
			pool.releaseBuffer(buf)
			pool.free()
			return err
		}

		fs.incrementBlockID(binaryBlockID)
		blockID := base64.StdEncoding.EncodeToString(binaryBlockID)
		blocks = append(blocks, blockID)

		guard <- struct{}{}
		if poolError != nil {
			fsLog(fs, logger.LevelDebug, "pool error, upload for part %v not started", part)
			pool.releaseBuffer(buf)
			break
		}

		wg.Add(1)
		go func(blockID string, buf []byte, bufSize int) {
			defer wg.Done()
			bufferReader := bytes.NewReader(buf[:bufSize])
			innerCtx, cancelFn := context.WithDeadline(poolCtx, time.Now().Add(blockCtxTimeout))
			defer cancelFn()

			_, err := blockBlobURL.StageBlock(innerCtx, blockID, bufferReader, azblob.LeaseAccessConditions{}, nil,
				azblob.ClientProvidedKeyOptions{})
			if err != nil {
				errOnce.Do(func() {
					poolError = err
					fsLog(fs, logger.LevelDebug, "multipart upload error: %v", poolError)
					poolCancel()
				})
			}
			pool.releaseBuffer(buf)
			<-guard
		}(blockID, buf, n)
	}

	wg.Wait()
	close(guard)
	pool.free()

	if poolError != nil {
		return poolError
	}

	_, err := blockBlobURL.CommitBlockList(ctx, blocks, *httpHeaders, azblob.Metadata{}, azblob.BlobAccessConditions{},
		azblob.AccessTierType(fs.config.AccessTier), nil, azblob.ClientProvidedKeyOptions{})
	return err
}

// copied from rclone
func (fs *AzureBlobFs) readFill(r io.Reader, buf []byte) (n int, err error) {
	var nn int
	for n < len(buf) && err == nil {
		nn, err = r.Read(buf[n:])
		n += nn
	}
	return n, err
}

// copied from rclone
func (fs *AzureBlobFs) incrementBlockID(blockID []byte) {
	for i, digit := range blockID {
		newDigit := digit + 1
		blockID[i] = newDigit
		if newDigit >= digit {
			// exit if no carry
			break
		}
	}
}

type bufferAllocator struct {
	sync.Mutex
	available  [][]byte
	bufferSize int
	finalized  bool
}

func newBufferAllocator(size int) *bufferAllocator {
	return &bufferAllocator{
		bufferSize: size,
		finalized:  false,
	}
}

func (b *bufferAllocator) getBuffer() []byte {
	b.Lock()
	defer b.Unlock()

	if len(b.available) > 0 {
		var result []byte

		truncLength := len(b.available) - 1
		result = b.available[truncLength]

		b.available[truncLength] = nil
		b.available = b.available[:truncLength]

		return result
	}

	return make([]byte, b.bufferSize)
}

func (b *bufferAllocator) releaseBuffer(buf []byte) {
	b.Lock()
	defer b.Unlock()

	if b.finalized || len(buf) != b.bufferSize {
		return
	}

	b.available = append(b.available, buf)
}

func (b *bufferAllocator) free() {
	b.Lock()
	defer b.Unlock()

	b.available = nil
	b.finalized = true
}
