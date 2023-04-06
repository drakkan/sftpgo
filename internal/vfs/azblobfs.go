// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/eikenb/pipeat"
	"github.com/google/uuid"
	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	azureDefaultEndpoint = "blob.core.windows.net"
	azFolderKey          = "hdi_isfolder"
)

// AzureBlobFs is a Fs implementation for Azure Blob storage.
type AzureBlobFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath       string
	config          *AzBlobFsConfig
	containerClient *container.Client
	ctxTimeout      time.Duration
	ctxLongTimeout  time.Duration
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
	if err := fs.config.validate(); err != nil {
		return fs, err
	}

	if err := fs.config.tryDecrypt(); err != nil {
		return fs, err
	}

	fs.setConfigDefaults()

	if fs.config.SASURL.GetPayload() != "" {
		return fs.initFromSASURL()
	}

	credential, err := blob.NewSharedKeyCredential(fs.config.AccountName, fs.config.AccountKey.GetPayload())
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	var endpoint string
	if fs.config.UseEmulator {
		endpoint = fmt.Sprintf("%s/%s", fs.config.Endpoint, fs.config.AccountName)
	} else {
		endpoint = fmt.Sprintf("https://%s.%s/", fs.config.AccountName, fs.config.Endpoint)
	}
	containerURL := runtime.JoinPaths(endpoint, fs.config.Container)
	svc, err := container.NewClientWithSharedKeyCredential(containerURL, credential, getAzContainerClientOptions())
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	fs.containerClient = svc
	return fs, err
}

func (fs *AzureBlobFs) initFromSASURL() (Fs, error) {
	parts, err := blob.ParseURL(fs.config.SASURL.GetPayload())
	if err != nil {
		return fs, fmt.Errorf("invalid SAS URL: %w", err)
	}
	if parts.BlobName != "" {
		return fs, fmt.Errorf("SAS URL with blob name not supported")
	}
	if parts.ContainerName != "" {
		if fs.config.Container != "" && fs.config.Container != parts.ContainerName {
			return fs, fmt.Errorf("container name in SAS URL %q and container provided %q do not match",
				parts.ContainerName, fs.config.Container)
		}
		svc, err := container.NewClientWithNoCredential(fs.config.SASURL.GetPayload(), getAzContainerClientOptions())
		if err != nil {
			return fs, fmt.Errorf("invalid credentials: %v", err)
		}
		fs.config.Container = parts.ContainerName
		fs.containerClient = svc
		return fs, nil
	}
	if fs.config.Container == "" {
		return fs, errors.New("container is required with this SAS URL")
	}
	sasURL := runtime.JoinPaths(fs.config.SASURL.GetPayload(), fs.config.Container)
	svc, err := container.NewClientWithNoCredential(sasURL, getAzContainerClientOptions())
	if err != nil {
		return fs, fmt.Errorf("invalid credentials: %v", err)
	}
	fs.containerClient = svc
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *AzureBlobFs) Name() string {
	if !fs.config.SASURL.IsEmpty() {
		return fmt.Sprintf("%s with SAS URL, container %q", azBlobFsName, fs.config.Container)
	}
	return fmt.Sprintf("%s container %q", azBlobFsName, fs.config.Container)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *AzureBlobFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *AzureBlobFs) Stat(name string) (os.FileInfo, error) {
	if name == "" || name == "/" || name == "." {
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
	}
	if fs.config.KeyPrefix == name+"/" {
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
	}

	attrs, err := fs.headObject(name)
	if err == nil {
		contentType := util.GetStringFromPointer(attrs.ContentType)
		isDir := checkDirectoryMarkers(contentType, attrs.Metadata)
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
		return updateFileInfoModTime(fs.getStorageID(), name, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
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

	go func() {
		defer cancelFn()

		blockBlob := fs.containerClient.NewBlockBlobClient(name)
		err := fs.handleMultipartDownload(ctx, blockBlob, offset, w)
		w.CloseWithError(err) //nolint:errcheck
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %+v", name, w.GetWrittenBytes(), err)
		metric.AZTransferCompleted(w.GetWrittenBytes(), 1, err)
	}()

	return nil, r, cancelFn, nil
}

// Create creates or opens the named file for writing
func (fs *AzureBlobFs) Create(name string, flag, checks int) (File, *PipeWriter, func(), error) {
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
	ctx, cancelFn := context.WithCancel(context.Background())

	p := NewPipeWriter(w)
	headers := blob.HTTPHeaders{}
	var contentType string
	var metadata map[string]*string
	if flag == -1 {
		contentType = dirMimeType
		metadata = map[string]*string{
			azFolderKey: util.NilIfEmpty("true"),
		}
	} else {
		contentType = mime.TypeByExtension(path.Ext(name))
	}
	if contentType != "" {
		headers.BlobContentType = &contentType
	}

	go func() {
		defer cancelFn()

		blockBlob := fs.containerClient.NewBlockBlobClient(name)
		err := fs.handleMultipartUpload(ctx, r, blockBlob, &headers, metadata)
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
	_, err := fs.Stat(path.Dir(target))
	if err != nil {
		return err
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
		if err := fs.mkdirInternal(target); err != nil {
			return err
		}
	} else {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxLongTimeout))
		defer cancelFn()

		srcBlob := fs.containerClient.NewBlockBlobClient(source)
		dstBlob := fs.containerClient.NewBlockBlobClient(target)
		resp, err := dstBlob.StartCopyFromURL(ctx, srcBlob.URL(), fs.getCopyOptions())
		if err != nil {
			metric.AZCopyObjectCompleted(err)
			return err
		}
		copyStatus := blob.CopyStatusType(util.GetStringFromPointer((*string)(resp.CopyStatus)))
		nErrors := 0
		for copyStatus == blob.CopyStatusTypePending {
			// Poll until the copy is complete.
			time.Sleep(500 * time.Millisecond)
			resp, err := dstBlob.GetProperties(ctx, &blob.GetPropertiesOptions{})
			if err != nil {
				// A GetProperties failure may be transient, so allow a couple
				// of them before giving up.
				nErrors++
				if ctx.Err() != nil || nErrors == 3 {
					metric.AZCopyObjectCompleted(err)
					return err
				}
			} else {
				copyStatus = blob.CopyStatusType(util.GetStringFromPointer((*string)(resp.CopyStatus)))
			}
		}
		if copyStatus != blob.CopyStatusTypeSuccess {
			err := fmt.Errorf("copy failed with status: %s", copyStatus)
			metric.AZCopyObjectCompleted(err)
			return err
		}

		metric.AZCopyObjectCompleted(nil)
		fs.preserveModificationTime(source, target, fi)
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

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	blobBlock := fs.containerClient.NewBlockBlobClient(name)
	var deletSnapshots blob.DeleteSnapshotsOptionType
	if !isDir {
		deletSnapshots = blob.DeleteSnapshotsOptionTypeInclude
	}
	_, err := blobBlock.Delete(ctx, &blob.DeleteOptions{
		DeleteSnapshots: &deletSnapshots,
	})
	if err != nil && isDir {
		if fs.isBadRequestError(err) {
			deletSnapshots = blob.DeleteSnapshotsOptionTypeInclude
			_, err = blobBlock.Delete(ctx, &blob.DeleteOptions{
				DeleteSnapshots: &deletSnapshots,
			})
		}
	}
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
	return fs.mkdirInternal(name)
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

	pager := fs.containerClient.NewListBlobsHierarchyPager("/", &container.ListBlobsHierarchyOptions{
		Include: container.ListBlobsInclude{
			//Metadata: true,
		},
		Prefix: &prefix,
	})

	for pager.More() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		resp, err := pager.NextPage(ctx)
		if err != nil {
			metric.AZListObjectsCompleted(err)
			return result, err
		}
		for _, blobPrefix := range resp.ListBlobsHierarchySegmentResponse.Segment.BlobPrefixes {
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
			result = append(result, NewFileInfo(name, true, 0, time.Unix(0, 0), false))
			prefixes[strings.TrimSuffix(name, "/")] = true
		}

		for _, blobItem := range resp.ListBlobsHierarchySegmentResponse.Segment.BlobItems {
			name := util.GetStringFromPointer(blobItem.Name)
			name = strings.TrimPrefix(name, prefix)
			size := int64(0)
			isDir := false
			modTime := time.Unix(0, 0)
			if blobItem.Properties != nil {
				size = util.GetIntFromPointer(blobItem.Properties.ContentLength)
				modTime = util.GetTimeFromPointer(blobItem.Properties.LastModified)
				contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
				isDir = checkDirectoryMarkers(contentType, blobItem.Metadata)
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
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusNotFound
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
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusUnauthorized
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

func (*AzureBlobFs) isBadRequestError(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusBadRequest
	}
	return false
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
	return fs.GetDirSize(fs.config.KeyPrefix)
}

func (fs *AzureBlobFs) getFileNamesInPrefix(fsPrefix string) (map[string]bool, error) {
	fileNames := make(map[string]bool)
	prefix := ""
	if fsPrefix != "/" {
		prefix = strings.TrimPrefix(fsPrefix, "/")
	}

	pager := fs.containerClient.NewListBlobsHierarchyPager("/", &container.ListBlobsHierarchyOptions{
		Include: container.ListBlobsInclude{
			//Metadata: true,
		},
		Prefix: &prefix,
	})

	for pager.More() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		resp, err := pager.NextPage(ctx)
		if err != nil {
			metric.AZListObjectsCompleted(err)
			return fileNames, err
		}
		for _, blobItem := range resp.ListBlobsHierarchySegmentResponse.Segment.BlobItems {
			name := util.GetStringFromPointer(blobItem.Name)
			name = strings.TrimPrefix(name, prefix)
			if blobItem.Properties != nil {
				contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
				isDir := checkDirectoryMarkers(contentType, blobItem.Metadata)
				if isDir {
					continue
				}
				fileNames[name] = true
			}
		}
	}
	metric.AZListObjectsCompleted(nil)

	return fileNames, nil
}

// CheckMetadata checks the metadata consistency
func (fs *AzureBlobFs) CheckMetadata() error {
	return fsMetadataCheck(fs, fs.getStorageID(), fs.config.KeyPrefix)
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *AzureBlobFs) GetDirSize(dirname string) (int, int64, error) {
	numFiles := 0
	size := int64(0)
	prefix := fs.getPrefix(dirname)

	pager := fs.containerClient.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{
			Metadata: true,
		},
		Prefix: &prefix,
	})

	for pager.More() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		resp, err := pager.NextPage(ctx)
		if err != nil {
			metric.AZListObjectsCompleted(err)
			return numFiles, size, err
		}
		for _, blobItem := range resp.ListBlobsFlatSegmentResponse.Segment.BlobItems {
			if blobItem.Properties != nil {
				contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
				isDir := checkDirectoryMarkers(contentType, blobItem.Metadata)
				blobSize := util.GetIntFromPointer(blobItem.Properties.ContentLength)
				if isDir && blobSize == 0 {
					continue
				}
				numFiles++
				size += blobSize
				if numFiles%1000 == 0 {
					fsLog(fs, logger.LevelDebug, "dirname %q scan in progress, files: %d, size: %d", dirname, numFiles, size)
				}
			}
		}
	}
	metric.AZListObjectsCompleted(nil)

	return numFiles, size, nil
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
	pager := fs.containerClient.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{
			Metadata: true,
		},
		Prefix: &prefix,
	})

	for pager.More() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		resp, err := pager.NextPage(ctx)
		if err != nil {
			metric.AZListObjectsCompleted(err)
			return err
		}
		for _, blobItem := range resp.ListBlobsFlatSegmentResponse.Segment.BlobItems {
			name := util.GetStringFromPointer(blobItem.Name)
			if fs.isEqual(name, prefix) {
				continue
			}
			blobSize := int64(0)
			lastModified := time.Unix(0, 0)
			isDir := false
			if blobItem.Properties != nil {
				contentType := util.GetStringFromPointer(blobItem.Properties.ContentType)
				isDir = checkDirectoryMarkers(contentType, blobItem.Metadata)
				blobSize = util.GetIntFromPointer(blobItem.Properties.ContentLength)
				lastModified = util.GetTimeFromPointer(blobItem.Properties.LastModified)
			}
			err := walkFn(name, NewFileInfo(name, isDir, blobSize, lastModified, false), nil)
			if err != nil {
				return err
			}
		}
	}

	metric.AZListObjectsCompleted(nil)
	return walkFn(root, NewFileInfo(root, true, 0, time.Unix(0, 0), false), nil)
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

func (fs *AzureBlobFs) headObject(name string) (blob.GetPropertiesResponse, error) {
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
	defer cancelFn()

	resp, err := fs.containerClient.NewBlockBlobClient(name).GetProperties(ctx, &blob.GetPropertiesOptions{})

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

// GetAvailableDiskSize returns the available size for the specified path
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

func (fs *AzureBlobFs) mkdirInternal(name string) error {
	_, w, _, err := fs.Create(name, -1, 0)
	if err != nil {
		return err
	}
	return w.Close()
}

func (fs *AzureBlobFs) hasContents(name string) (bool, error) {
	result := false
	prefix := fs.getPrefix(name)

	maxResults := int32(1)
	pager := fs.containerClient.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		MaxResults: &maxResults,
		Prefix:     &prefix,
	})

	if pager.More() {
		ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(fs.ctxTimeout))
		defer cancelFn()

		resp, err := pager.NextPage(ctx)
		if err != nil {
			metric.AZListObjectsCompleted(err)
			return result, err
		}

		result = len(resp.ListBlobsFlatSegmentResponse.Segment.BlobItems) > 0
	}

	metric.AZListObjectsCompleted(nil)
	return result, nil
}

func (fs *AzureBlobFs) downloadPart(ctx context.Context, blockBlob *blockblob.Client, buf []byte,
	w io.WriterAt, offset, count, writeOffset int64,
) error {
	if count == 0 {
		return nil
	}

	resp, err := blockBlob.DownloadStream(ctx, &blob.DownloadStreamOptions{
		Range: blob.HTTPRange{
			Offset: offset,
			Count:  count,
		},
	})
	if err != nil {
		return err
	}
	defer resp.DownloadResponse.Body.Close()

	_, err = io.ReadAtLeast(resp.DownloadResponse.Body, buf, int(count))
	if err != nil {
		return err
	}

	_, err = fs.writeAtFull(w, buf, writeOffset, int(count))
	return err
}

func (fs *AzureBlobFs) handleMultipartDownload(ctx context.Context, blockBlob *blockblob.Client,
	offset int64, writer io.WriterAt,
) error {
	props, err := blockBlob.GetProperties(ctx, &blob.GetPropertiesOptions{})
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
	var hasError atomic.Bool
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
		if hasError.Load() {
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
					fsLog(fs, logger.LevelError, "multipart download error: %+v", err)
					hasError.Store(true)
					poolError = fmt.Errorf("multipart download error: %w", err)
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
	blockBlob *blockblob.Client, httpHeaders *blob.HTTPHeaders, metadata map[string]*string,
) error {
	partSize := fs.config.UploadPartSize
	guard := make(chan struct{}, fs.config.UploadConcurrency)
	blockCtxTimeout := time.Duration(fs.config.UploadPartSize/(1024*1024)) * time.Minute

	// sync.Pool seems to use a lot of memory so prefer our own, very simple, allocator
	// we only need to recycle few byte slices
	pool := newBufferAllocator(int(partSize))
	finished := false
	var blocks []string
	var wg sync.WaitGroup
	var errOnce sync.Once
	var hasError atomic.Bool
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

		// Block IDs are unique values to avoid issue if 2+ clients are uploading blocks
		// at the same time causing CommitBlockList to get a mix of blocks from all the clients.
		generatedUUID, err := uuid.NewRandom()
		if err != nil {
			pool.releaseBuffer(buf)
			pool.free()
			return fmt.Errorf("unable to generate block ID: %w", err)
		}
		blockID := base64.StdEncoding.EncodeToString([]byte(generatedUUID.String()))
		blocks = append(blocks, blockID)

		guard <- struct{}{}
		if hasError.Load() {
			fsLog(fs, logger.LevelError, "pool error, upload for part %d not started", part)
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

			_, err := blockBlob.StageBlock(innerCtx, blockID, bufferReader, &blockblob.StageBlockOptions{})
			if err != nil {
				errOnce.Do(func() {
					fsLog(fs, logger.LevelDebug, "multipart upload error: %+v", err)
					hasError.Store(true)
					poolError = fmt.Errorf("multipart upload error: %w", err)
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

	commitOptions := blockblob.CommitBlockListOptions{
		HTTPHeaders: httpHeaders,
		Metadata:    metadata,
	}
	if fs.config.AccessTier != "" {
		commitOptions.Tier = (*blob.AccessTier)(&fs.config.AccessTier)
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

func (fs *AzureBlobFs) preserveModificationTime(source, target string, fi os.FileInfo) {
	if plugin.Handler.HasMetadater() {
		if !fi.IsDir() {
			err := plugin.Handler.SetModificationTime(fs.getStorageID(), ensureAbsPath(target),
				util.GetTimeAsMsSinceEpoch(fi.ModTime()))
			if err != nil {
				fsLog(fs, logger.LevelWarn, "unable to preserve modification time after renaming %#v -> %#v: %+v",
					source, target, err)
			}
		}
	}
}

func (fs *AzureBlobFs) getCopyOptions() *blob.StartCopyFromURLOptions {
	copyOptions := &blob.StartCopyFromURLOptions{}
	if fs.config.AccessTier != "" {
		copyOptions.Tier = (*blob.AccessTier)(&fs.config.AccessTier)
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

func checkDirectoryMarkers(contentType string, metadata map[string]*string) bool {
	if contentType == dirMimeType {
		return true
	}
	for k, v := range metadata {
		if strings.ToLower(k) == azFolderKey {
			return util.GetStringFromPointer(v) == "true"
		}
	}
	return false
}

func getAzContainerClientOptions() *container.ClientOptions {
	version := version.Get()
	return &container.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Telemetry: policy.TelemetryOptions{
				ApplicationID: fmt.Sprintf("SFTPGo-%s", version.CommitHash),
			},
		},
	}
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
