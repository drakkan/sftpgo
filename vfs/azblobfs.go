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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

const (
	azureDefaultEndpoint = "blob.core.windows.net"
)

// AzureBlobFs is a Fs implementation for Azure Blob storage.
type AzureBlobFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath          string
	config             *AzBlobFsConfig
	hasContainerAccess bool
	containerClient    azblob.ContainerClient
	ctxTimeout         time.Duration
	ctxLongTimeout     time.Duration
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
		mountPath:      getMountPath(mountPath),
		config:         &config,
		ctxTimeout:     30 * time.Second,
		ctxLongTimeout: 90 * time.Second,
	}
	if err := fs.config.Validate(); err != nil {
		return fs, err
	}

	if err := fs.config.tryDecrypt(); err != nil {
		return fs, err
	}

	fs.setConfigDefaults()

	version := version.Get()
	clientOptions := &azblob.ClientOptions{
		Telemetry: policy.TelemetryOptions{
			ApplicationID: fmt.Sprintf("SFTPGo-%v_%v", version.Version, version.CommitHash),
		},
	}

	if fs.config.SASURL.GetPayload() != "" {
		if _, err := url.Parse(fs.config.SASURL.GetPayload()); err != nil {
			return fs, fmt.Errorf("invalid SAS URL: %w", err)
		}
		parts := azblob.NewBlobURLParts(fs.config.SASURL.GetPayload())
		if parts.ContainerName != "" {
			if fs.config.Container != "" && fs.config.Container != parts.ContainerName {
				return fs, fmt.Errorf("container name in SAS URL %#v and container provided %#v do not match",
					parts.ContainerName, fs.config.Container)
			}
			fs.config.Container = parts.ContainerName
		} else {
			if fs.config.Container == "" {
				return fs, errors.New("container is required with this SAS URL")
			}
		}
		svc, err := azblob.NewServiceClientWithNoCredential(fs.config.SASURL.GetPayload(), clientOptions)
		if err != nil {
			return fs, fmt.Errorf("invalid credentials: %v", err)
		}
		fs.hasContainerAccess = false
		fs.containerClient = svc.NewContainerClient(fs.config.Container)
		return fs, nil
	}

	credential, err := azblob.NewSharedKeyCredential(fs.config.AccountName, fs.config.AccountKey.GetPayload())
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	var endpoint string
	if fs.config.UseEmulator {
		endpoint = fmt.Sprintf("%s/%s", fs.config.Endpoint, fs.config.AccountName)
	} else {
		endpoint = fmt.Sprintf("https://%s.%s/", fs.config.AccountName, fs.config.Endpoint)
	}
	svc, err := azblob.NewServiceClientWithSharedKey(endpoint, credential, clientOptions)
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	fs.hasContainerAccess = true
	fs.containerClient = svc.NewContainerClient(fs.config.Container)
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
		if fs.hasContainerAccess {
			err := fs.checkIfBucketExists()
			if err != nil {
				return nil, err
			}
		}
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Now(), false))
	}
	if fs.config.KeyPrefix == name+"/" {
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Now(), false))
	}

	attrs, err := fs.headObject(name)
	if err == nil {
		contentType := util.GetStringFromPointer(attrs.ContentType)
		isDir := contentType == dirMimeType
		metric.AZListObjectsCompleted(nil)
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, isDir,
			util.GetIntFromPointer(attrs.ContentLength),
			util.GetTimeFromPointer(attrs.LastModified), false))
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
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Now(), false))
	}
	return nil, os.ErrNotExist
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
	ctx, cancelFn := context.WithCancel(context.Background())
	blockBlob := fs.containerClient.NewBlockBlobClient(name)

	go func() {
		defer cancelFn()

		err := fs.handleMultipartDownload(ctx, blockBlob, offset, w)
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %+v", name, w.GetWrittenBytes(), err)
		metric.AZTransferCompleted(w.GetWrittenBytes(), 1, err)
	}()

	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *AzureBlobFs) Create(name string, flag int) (File, *PipeWriter, func(), error) {
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancelFn := context.WithCancel(context.Background())

	p := NewPipeWriter(w)
	blockBlob := fs.containerClient.NewBlockBlobClient(name)
	headers := azblob.BlobHTTPHeaders{}
	var contentType string
	if flag == -1 {
		contentType = dirMimeType
	} else {
		contentType = mime.TypeByExtension(path.Ext(name))
	}
	if contentType != "" {
		headers.BlobContentType = &contentType
	}

	go func() {
		defer cancelFn()

		err := fs.handleMultipartUpload(ctx, r, blockBlob, &headers)
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %+v", name, r.GetReadedBytes(), err)
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
	dstBlob := fs.containerClient.NewBlockBlobClient(target)
	srcURL := fs.containerClient.NewBlockBlobClient(source).URL()

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
	defer cancelFn()

	resp, err := dstBlob.StartCopyFromURL(ctx, srcURL, fs.getCopyOptions())
	if err != nil {
		metric.AZCopyObjectCompleted(err)
		return err
	}
	copyStatus := azblob.CopyStatusType(util.GetStringFromPointer((*string)(resp.CopyStatus)))
	nErrors := 0
	for copyStatus == azblob.CopyStatusTypePending {
		// Poll until the copy is complete.
		time.Sleep(500 * time.Millisecond)
		resp, err := dstBlob.GetProperties(ctx, &azblob.GetBlobPropertiesOptions{
			BlobAccessConditions: &azblob.BlobAccessConditions{},
		})
		if err != nil {
			// A GetProperties failure may be transient, so allow a couple
			// of them before giving up.
			nErrors++
			if ctx.Err() != nil || nErrors == 3 {
				metric.AZCopyObjectCompleted(err)
				return err
			}
		} else {
			copyStatus = azblob.CopyStatusType(util.GetStringFromPointer((*string)(resp.CopyStatus)))
		}
	}
	if copyStatus != azblob.CopyStatusTypeSuccess {
		err := fmt.Errorf("copy failed with status: %s", copyStatus)
		metric.AZCopyObjectCompleted(err)
		return err
	}

	metric.AZCopyObjectCompleted(nil)
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
	blobBlock := fs.containerClient.NewBlockBlobClient(name)
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := blobBlock.Delete(ctx, &azblob.DeleteBlobOptions{
		DeleteSnapshots: azblob.DeleteSnapshotsOptionTypeInclude.ToPtr(),
	})
	metric.AZDeleteObjectCompleted(err)
	if plugin.Handler.HasMetadater() && err == nil && !isDir {
		if errMetadata := plugin.Handler.RemoveMetadata(fs.getStorageID(), ensureAbsPath(name)); errMetadata != nil {
			fsLog(fs, logger.LevelWarn, "unable to remove metadata for path %#v: %+v", name, errMetadata)
		}
	}
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
func (fs *AzureBlobFs) Chtimes(name string, atime, mtime time.Time, isUploading bool) error {
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
func (*AzureBlobFs) Truncate(name string, size int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *AzureBlobFs) ReadDir(dirname string) ([]os.FileInfo, error) {
	var result []os.FileInfo
	// dirname must be already cleaned
	prefix := fs.getPrefix(dirname)

	modTimes, err := getFolderModTimes(fs.getStorageID(), dirname)
	if err != nil {
		return result, err
	}
	prefixes := make(map[string]bool)

	timeout := int32(fs.ctxTimeout / time.Second)
	pager := fs.containerClient.ListBlobsHierarchy("/", &azblob.ContainerListBlobHierarchySegmentOptions{
		Include: []azblob.ListBlobsIncludeItem{},
		Prefix:  &prefix,
		Timeout: &timeout,
	})

	hasNext := true
	for hasNext {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		if hasNext = pager.NextPage(ctx); hasNext {
			resp := pager.PageResponse()

			for _, blobPrefix := range resp.ContainerListBlobHierarchySegmentResult.Segment.BlobPrefixes {
				name := util.GetStringFromPointer(blobPrefix.Name)
				// we don't support prefixes == "/" this will be sent if a key starts with "/"
				if name == "" || name == "/" {
					continue
				}
				// sometime we have duplicate prefixes, maybe an Azurite bug
				name = strings.TrimPrefix(name, prefix)
				if _, ok := prefixes[strings.TrimSuffix(name, "/")]; ok {
					continue
				}
				result = append(result, NewFileInfo(name, true, 0, time.Now(), false))
				prefixes[strings.TrimSuffix(name, "/")] = true
			}

			for _, blobItem := range resp.ContainerListBlobHierarchySegmentResult.Segment.BlobItems {
				name := util.GetStringFromPointer(blobItem.Name)
				name = strings.TrimPrefix(name, prefix)
				size := int64(0)
				isDir := false
				modTime := time.Now()
				if blobItem.Properties != nil {
					size = util.GetIntFromPointer(blobItem.Properties.ContentLength)
					modTime = util.GetTimeFromPointer(blobItem.Properties.LastModified)
					contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
					isDir = (contentType == dirMimeType)
					if isDir {
						// check if the dir is already included, it will be sent as blob prefix if it contains at least one item
						if _, ok := prefixes[name]; ok {
							continue
						}
						prefixes[name] = true
					}
				}
				if t, ok := modTimes[name]; ok {
					modTime = util.GetTimeFromMsecSinceEpoch(t)
				}
				result = append(result, NewFileInfo(name, isDir, size, modTime, false))
			}
		}
	}

	err = pager.Err()
	metric.AZListObjectsCompleted(err)

	return result, err
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
	var errStorage *azblob.StorageError
	if errors.As(err, &errStorage) {
		return errStorage.StatusCode() == http.StatusNotFound
	}

	var errResp *azcore.ResponseError
	if errors.As(err, &errResp) {
		return errResp.StatusCode == http.StatusNotFound
	}
	// os.ErrNotExist can be returned internally by fs.Stat
	return errors.Is(err, os.ErrNotExist)
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*AzureBlobFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}
	var errStorage *azblob.StorageError
	if errors.As(err, &errStorage) {
		statusCode := errStorage.StatusCode()
		return statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized
	}

	var errResp *azcore.ResponseError
	if errors.As(err, &errResp) {
		return errResp.StatusCode == http.StatusForbidden || errResp.StatusCode == http.StatusUnauthorized
	}

	return false
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

	timeout := int32(fs.ctxTimeout / time.Second)
	pager := fs.containerClient.ListBlobsFlat(&azblob.ContainerListBlobFlatSegmentOptions{
		Prefix:  &fs.config.KeyPrefix,
		Timeout: &timeout,
	})

	hasNext := true
	for hasNext {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		if hasNext = pager.NextPage(ctx); hasNext {
			resp := pager.PageResponse()
			for _, blobItem := range resp.ContainerListBlobFlatSegmentResult.Segment.BlobItems {
				if blobItem.Properties != nil {
					contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
					isDir := (contentType == dirMimeType)
					blobSize := util.GetIntFromPointer(blobItem.Properties.ContentLength)
					if isDir && blobSize == 0 {
						continue
					}
					numFiles++
					size += blobSize
				}
			}
		}
	}

	err := pager.Err()
	metric.AZListObjectsCompleted(err)

	return numFiles, size, err
}

func (fs *AzureBlobFs) getFileNamesInPrefix(fsPrefix string) (map[string]bool, error) {
	fileNames := make(map[string]bool)
	prefix := ""
	if fsPrefix != "/" {
		prefix = strings.TrimPrefix(fsPrefix, "/")
	}

	timeout := int32(fs.ctxTimeout / time.Second)
	pager := fs.containerClient.ListBlobsHierarchy("/", &azblob.ContainerListBlobHierarchySegmentOptions{
		Include: []azblob.ListBlobsIncludeItem{},
		Prefix:  &prefix,
		Timeout: &timeout,
	})

	hasNext := true
	for hasNext {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		if hasNext = pager.NextPage(ctx); hasNext {
			resp := pager.PageResponse()
			for _, blobItem := range resp.ContainerListBlobHierarchySegmentResult.Segment.BlobItems {
				name := util.GetStringFromPointer(blobItem.Name)
				name = strings.TrimPrefix(name, prefix)
				if blobItem.Properties != nil {
					contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
					isDir := (contentType == dirMimeType)
					if isDir {
						continue
					}
					fileNames[name] = true
				}
			}
		}
	}

	err := pager.Err()
	metric.AZListObjectsCompleted(err)

	return fileNames, err
}

// CheckMetadata checks the metadata consistency
func (fs *AzureBlobFs) CheckMetadata() error {
	return fsMetadataCheck(fs, fs.getStorageID(), fs.config.KeyPrefix)
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
	prefix := fs.getPrefix(root)
	timeout := int32(fs.ctxTimeout / time.Second)
	pager := fs.containerClient.ListBlobsFlat(&azblob.ContainerListBlobFlatSegmentOptions{
		Prefix:  &prefix,
		Timeout: &timeout,
	})

	hasNext := true
	for hasNext {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		if hasNext = pager.NextPage(ctx); hasNext {
			resp := pager.PageResponse()
			for _, blobItem := range resp.ContainerListBlobFlatSegmentResult.Segment.BlobItems {
				name := util.GetStringFromPointer(blobItem.Name)
				if fs.isEqual(name, prefix) {
					continue
				}
				blobSize := int64(0)
				lastModified := time.Now()
				isDir := false
				if blobItem.Properties != nil {
					contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
					isDir = (contentType == dirMimeType)
					blobSize = util.GetIntFromPointer(blobItem.Properties.ContentLength)
					lastModified = util.GetTimeFromPointer(blobItem.Properties.LastModified)
				}
				err := walkFn(name, NewFileInfo(name, isDir, blobSize, lastModified, false), nil)
				if err != nil {
					return err
				}
			}
		}
	}

	err := pager.Err()
	if err != nil {
		metric.AZListObjectsCompleted(err)
		return err
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

func (fs *AzureBlobFs) headObject(name string) (azblob.GetBlobPropertiesResponse, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	blobClient := fs.containerClient.NewBlockBlobClient(name)
	resp, err := blobClient.GetProperties(ctx, &azblob.GetBlobPropertiesOptions{
		BlobAccessConditions: &azblob.BlobAccessConditions{},
	})
	metric.AZHeadObjectCompleted(err)
	return resp, err
}

// GetMimeType returns the content type
func (fs *AzureBlobFs) GetMimeType(name string) (string, error) {
	response, err := fs.headObject(name)
	if err != nil {
		return "", err
	}
	return util.GetStringFromPointer(response.ContentType), nil
}

// Close closes the fs
func (*AzureBlobFs) Close() error {
	return nil
}

// GetAvailableDiskSize return the available size for the specified path
func (*AzureBlobFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
}

func (*AzureBlobFs) getPrefix(name string) string {
	prefix := ""
	if name != "" && name != "." {
		prefix = strings.TrimPrefix(name, "/")
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	return prefix
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
		fs.config.UploadPartSize = 5
	}
	if fs.config.UploadPartSize < 1024*1024 {
		fs.config.UploadPartSize *= 1024 * 1024
	}
	if fs.config.UploadConcurrency == 0 {
		fs.config.UploadConcurrency = 5
	}
	if fs.config.DownloadPartSize == 0 {
		fs.config.DownloadPartSize = 5
	}
	if fs.config.DownloadPartSize < 1024*1024 {
		fs.config.DownloadPartSize *= 1024 * 1024
	}
	if fs.config.DownloadConcurrency == 0 {
		fs.config.DownloadConcurrency = 5
	}
}

func (fs *AzureBlobFs) checkIfBucketExists() error {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	_, err := fs.containerClient.GetProperties(ctx, &azblob.GetPropertiesOptionsContainer{})
	metric.AZHeadContainerCompleted(err)
	return err
}

func (fs *AzureBlobFs) hasContents(name string) (bool, error) {
	result := false
	prefix := fs.getPrefix(name)

	maxResults := int32(1)
	timeout := int32(fs.ctxTimeout / time.Second)
	pager := fs.containerClient.ListBlobsFlat(&azblob.ContainerListBlobFlatSegmentOptions{
		Maxresults: &maxResults,
		Prefix:     &prefix,
		Timeout:    &timeout,
	})

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	if pager.NextPage(ctx) {
		resp := pager.PageResponse()
		result = len(resp.ContainerListBlobFlatSegmentResult.Segment.BlobItems) > 0
	}

	err := pager.Err()
	metric.AZListObjectsCompleted(err)
	return result, err
}

func (fs *AzureBlobFs) downloadPart(ctx context.Context, blockBlob azblob.BlockBlobClient, buf []byte,
	w io.WriterAt, offset, count, writeOffset int64,
) error {
	if count == 0 {
		return nil
	}
	resp, err := blockBlob.Download(ctx, &azblob.DownloadBlobOptions{
		Offset: &offset,
		Count:  &count,
	})
	if err != nil {
		return err
	}
	body := resp.Body(&azblob.RetryReaderOptions{MaxRetryRequests: 2})
	defer body.Close()

	_, err = io.ReadAtLeast(body, buf, int(count))
	if err != nil {
		return err
	}

	_, err = fs.writeAtFull(w, buf, writeOffset, int(count))
	return err
}

func (fs *AzureBlobFs) handleMultipartDownload(ctx context.Context, blockBlob azblob.BlockBlobClient,
	offset int64, writer io.WriterAt,
) error {
	props, err := blockBlob.GetProperties(ctx, &azblob.GetBlobPropertiesOptions{
		BlobAccessConditions: &azblob.BlobAccessConditions{},
	})
	if err != nil {
		fsLog(fs, logger.LevelError, "unable to get blob properties, download aborted: %+v", err)
		return err
	}
	contentLength := util.GetIntFromPointer(props.ContentLength)
	sizeToDownload := contentLength - offset
	if sizeToDownload < 0 {
		fsLog(fs, logger.LevelError, "invalid multipart download size or offset, size: %v, offset: %v, size to download: %v",
			contentLength, offset, sizeToDownload)
		return errors.New("the requested offset exceeds the file size")
	}
	if sizeToDownload == 0 {
		fsLog(fs, logger.LevelDebug, "nothing to download, offset %v, content length %v", offset, contentLength)
		return nil
	}
	partSize := fs.config.DownloadPartSize
	guard := make(chan struct{}, fs.config.DownloadConcurrency)
	blockCtxTimeout := time.Duration(fs.config.DownloadPartSize/(1024*1024)) * time.Minute
	pool := newBufferAllocator(int(partSize))
	finished := false
	var wg sync.WaitGroup
	var errOnce sync.Once
	var poolError error

	poolCtx, poolCancel := context.WithCancel(ctx)
	defer poolCancel()

	for part := 0; !finished; part++ {
		start := offset
		end := offset + partSize
		if end >= contentLength {
			end = contentLength
			finished = true
		}
		writeOffset := int64(part) * partSize
		offset = end

		guard <- struct{}{}
		if poolError != nil {
			fsLog(fs, logger.LevelDebug, "pool error, download for part %v not started", part)
			break
		}

		buf := pool.getBuffer()
		wg.Add(1)
		go func(start, end, writeOffset int64, buf []byte) {
			defer func() {
				pool.releaseBuffer(buf)
				<-guard
				wg.Done()
			}()

			innerCtx, cancelFn := context.WithDeadline(poolCtx, time.Now().Add(blockCtxTimeout))
			defer cancelFn()

			count := end - start
			err := fs.downloadPart(innerCtx, blockBlob, buf, writer, start, count, writeOffset)
			if err != nil {
				errOnce.Do(func() {
					poolError = err
					fsLog(fs, logger.LevelError, "multipart download error: %+v", poolError)
					poolCancel()
				})
			}
		}(start, end, writeOffset, buf)
	}

	wg.Wait()
	close(guard)
	pool.free()

	return poolError
}

func (fs *AzureBlobFs) handleMultipartUpload(ctx context.Context, reader io.Reader,
	blockBlob azblob.BlockBlobClient, httpHeaders *azblob.BlobHTTPHeaders,
) error {
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
			fsLog(fs, logger.LevelError, "pool error, upload for part %v not started", part)
			pool.releaseBuffer(buf)
			break
		}

		wg.Add(1)
		go func(blockID string, buf []byte, bufSize int) {
			defer func() {
				pool.releaseBuffer(buf)
				<-guard
				wg.Done()
			}()

			bufferReader := &bytesReaderWrapper{
				Reader: bytes.NewReader(buf[:bufSize]),
			}
			innerCtx, cancelFn := context.WithDeadline(poolCtx, time.Now().Add(blockCtxTimeout))
			defer cancelFn()

			_, err := blockBlob.StageBlock(innerCtx, blockID, bufferReader, &azblob.StageBlockOptions{})
			if err != nil {
				errOnce.Do(func() {
					poolError = err
					fsLog(fs, logger.LevelDebug, "multipart upload error: %+v", poolError)
					poolCancel()
				})
			}
		}(blockID, buf, n)
	}

	wg.Wait()
	close(guard)
	pool.free()

	if poolError != nil {
		return poolError
	}

	commitOptions := azblob.CommitBlockListOptions{
		BlobHTTPHeaders: httpHeaders,
	}
	if fs.config.AccessTier != "" {
		commitOptions.Tier = (*azblob.AccessTier)(&fs.config.AccessTier)
	}

	_, err := blockBlob.CommitBlockList(ctx, blocks, &commitOptions)
	return err
}

func (*AzureBlobFs) writeAtFull(w io.WriterAt, buf []byte, offset int64, count int) (int, error) {
	written := 0
	for written < count {
		n, err := w.WriteAt(buf[written:count], offset+int64(written))
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// copied from rclone
func (*AzureBlobFs) readFill(r io.Reader, buf []byte) (n int, err error) {
	var nn int
	for n < len(buf) && err == nil {
		nn, err = r.Read(buf[n:])
		n += nn
	}
	return n, err
}

// copied from rclone
func (*AzureBlobFs) incrementBlockID(blockID []byte) {
	for i, digit := range blockID {
		newDigit := digit + 1
		blockID[i] = newDigit
		if newDigit >= digit {
			// exit if no carry
			break
		}
	}
}

func (fs *AzureBlobFs) getCopyOptions() *azblob.StartCopyBlobOptions {
	copyOptions := &azblob.StartCopyBlobOptions{}
	if fs.config.AccessTier != "" {
		copyOptions.Tier = (*azblob.AccessTier)(&fs.config.AccessTier)
	}
	return copyOptions
}

func (fs *AzureBlobFs) getStorageID() string {
	if fs.config.Endpoint != "" {
		if !strings.HasSuffix(fs.config.Endpoint, "/") {
			return fmt.Sprintf("azblob://%v/%v", fs.config.Endpoint, fs.config.Container)
		}
		return fmt.Sprintf("azblob://%v%v", fs.config.Endpoint, fs.config.Container)
	}
	return fmt.Sprintf("azblob://%v", fs.config.Container)
}

type bytesReaderWrapper struct {
	*bytes.Reader
}

func (b *bytesReaderWrapper) Close() error {
	return nil
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
