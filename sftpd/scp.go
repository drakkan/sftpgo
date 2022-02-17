package sftpd

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

var (
	okMsg   = []byte{0x00}
	warnMsg = []byte{0x01} // must be followed by an optional message and a newline
	errMsg  = []byte{0x02} // must be followed by an optional message and a newline
	newLine = []byte{0x0A}
)

type scpCommand struct {
	sshCommand
}

func (c *scpCommand) handle() (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(logSender, "", "panic in handle scp command: %#v stack strace: %v", r, string(debug.Stack()))
			err = common.ErrGenericFailure
		}
	}()
	common.Connections.Add(c.connection)
	defer common.Connections.Remove(c.connection.GetID())

	destPath := c.getDestPath()
	commandType := c.getCommandType()
	c.connection.Log(logger.LevelDebug, "handle scp command, args: %v user: %v command type: %v, dest path: %#v",
		c.args, c.connection.User.Username, commandType, destPath)
	if commandType == "-t" {
		// -t means "to", so upload
		err = c.sendConfirmationMessage()
		if err != nil {
			return err
		}
		err = c.handleRecursiveUpload()
		if err != nil {
			return err
		}
	} else if commandType == "-f" {
		// -f means "from" so download
		err = c.readConfirmationMessage()
		if err != nil {
			return err
		}
		err = c.handleDownload(destPath)
		if err != nil {
			return err
		}
	} else {
		err = fmt.Errorf("scp command not supported, args: %v", c.args)
		c.connection.Log(logger.LevelDebug, "unsupported scp command, args: %v", c.args)
	}
	c.sendExitStatus(err)
	return err
}

func (c *scpCommand) handleRecursiveUpload() error {
	numDirs := 0
	destPath := c.getDestPath()
	for {
		fs, err := c.connection.User.GetFilesystemForPath(destPath, c.connection.ID)
		if err != nil {
			c.connection.Log(logger.LevelError, "error uploading file %#v: %+v", destPath, err)
			c.sendErrorMessage(nil, fmt.Errorf("unable to get fs for path %#v", destPath))
			return err
		}
		command, err := c.getNextUploadProtocolMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			c.sendErrorMessage(fs, err)
			return err
		}
		if strings.HasPrefix(command, "E") {
			numDirs--
			c.connection.Log(logger.LevelDebug, "received end dir command, num dirs: %v", numDirs)
			if numDirs < 0 {
				err = errors.New("unacceptable end dir command")
				c.sendErrorMessage(nil, err)
				return err
			}
			// the destination dir is now the parent directory
			destPath = path.Join(destPath, "..")
		} else {
			sizeToRead, name, err := c.parseUploadMessage(fs, command)
			if err != nil {
				return err
			}
			if strings.HasPrefix(command, "D") {
				numDirs++
				destPath = path.Join(destPath, name)
				fs, err = c.connection.User.GetFilesystemForPath(destPath, c.connection.ID)
				if err != nil {
					c.connection.Log(logger.LevelError, "error uploading file %#v: %+v", destPath, err)
					c.sendErrorMessage(nil, fmt.Errorf("unable to get fs for path %#v", destPath))
					return err
				}
				err = c.handleCreateDir(fs, destPath)
				if err != nil {
					return err
				}
				c.connection.Log(logger.LevelDebug, "received start dir command, num dirs: %v destPath: %#v", numDirs, destPath)
			} else if strings.HasPrefix(command, "C") {
				err = c.handleUpload(c.getFileUploadDestPath(fs, destPath, name), sizeToRead)
				if err != nil {
					return err
				}
			}
		}
		err = c.sendConfirmationMessage()
		if err != nil {
			return err
		}
	}
}

func (c *scpCommand) handleCreateDir(fs vfs.Fs, dirPath string) error {
	c.connection.UpdateLastActivity()

	p, err := fs.ResolvePath(dirPath)
	if err != nil {
		c.connection.Log(logger.LevelError, "error creating dir: %#v, invalid file path, err: %v", dirPath, err)
		c.sendErrorMessage(fs, err)
		return err
	}
	if !c.connection.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(dirPath)) {
		c.connection.Log(logger.LevelError, "error creating dir: %#v, permission denied", dirPath)
		c.sendErrorMessage(fs, common.ErrPermissionDenied)
		return common.ErrPermissionDenied
	}

	info, err := c.connection.DoStat(dirPath, 1, true)
	if err == nil && info.IsDir() {
		return nil
	}

	err = c.createDir(fs, p)
	if err != nil {
		return err
	}
	c.connection.Log(logger.LevelDebug, "created dir %#v", dirPath)
	return nil
}

// we need to close the transfer if we have an error
func (c *scpCommand) getUploadFileData(sizeToRead int64, transfer *transfer) error {
	err := c.sendConfirmationMessage()
	if err != nil {
		transfer.TransferError(err)
		transfer.Close()
		return err
	}

	if sizeToRead > 0 {
		// we could replace this method with io.CopyN implementing "Write" method in transfer struct
		remaining := sizeToRead
		buf := make([]byte, int64(math.Min(32768, float64(sizeToRead))))
		for {
			n, err := c.connection.channel.Read(buf)
			if err != nil {
				c.sendErrorMessage(transfer.Fs, err)
				transfer.TransferError(err)
				transfer.Close()
				return err
			}
			_, err = transfer.WriteAt(buf[:n], sizeToRead-remaining)
			if err != nil {
				c.sendErrorMessage(transfer.Fs, err)
				transfer.Close()
				return err
			}
			remaining -= int64(n)
			if remaining <= 0 {
				break
			}
			if remaining < int64(len(buf)) {
				buf = make([]byte, remaining)
			}
		}
	}
	err = c.readConfirmationMessage()
	if err != nil {
		transfer.TransferError(err)
		transfer.Close()
		return err
	}
	err = transfer.Close()
	if err != nil {
		c.sendErrorMessage(transfer.Fs, err)
		return err
	}
	return nil
}

func (c *scpCommand) handleUploadFile(fs vfs.Fs, resolvedPath, filePath string, sizeToRead int64, isNewFile bool, fileSize int64, requestPath string) error {
	diskQuota, transferQuota := c.connection.HasSpace(isNewFile, false, requestPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() {
		err := fmt.Errorf("denying file write due to quota limits")
		c.connection.Log(logger.LevelError, "error uploading file: %#v, err: %v", filePath, err)
		c.sendErrorMessage(nil, err)
		return err
	}
	err := common.ExecutePreAction(c.connection.BaseConnection, common.OperationPreUpload, resolvedPath, requestPath,
		fileSize, os.O_TRUNC)
	if err != nil {
		c.connection.Log(logger.LevelDebug, "upload for file %#v denied by pre action: %v", requestPath, err)
		err = c.connection.GetPermissionDeniedError()
		c.sendErrorMessage(fs, err)
		return err
	}

	maxWriteSize, _ := c.connection.GetMaxWriteSize(diskQuota, false, fileSize, fs.IsUploadResumeSupported())

	file, w, cancelFn, err := fs.Create(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		c.connection.Log(logger.LevelError, "error creating file %#v: %v", resolvedPath, err)
		c.sendErrorMessage(fs, err)
		return err
	}

	initialSize := int64(0)
	truncatedSize := int64(0) // bytes truncated and not included in quota
	if !isNewFile {
		if vfs.IsLocalOrSFTPFs(fs) {
			vfolder, err := c.connection.User.GetVirtualFolderForPath(path.Dir(requestPath))
			if err == nil {
				dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, 0, -fileSize, false) //nolint:errcheck
				if vfolder.IsIncludedInUserQuota() {
					dataprovider.UpdateUserQuota(&c.connection.User, 0, -fileSize, false) //nolint:errcheck
				}
			} else {
				dataprovider.UpdateUserQuota(&c.connection.User, 0, -fileSize, false) //nolint:errcheck
			}
		} else {
			initialSize = fileSize
			truncatedSize = initialSize
		}
		if maxWriteSize > 0 {
			maxWriteSize += fileSize
		}
	}

	vfs.SetPathPermissions(fs, filePath, c.connection.User.GetUID(), c.connection.User.GetGID())

	baseTransfer := common.NewBaseTransfer(file, c.connection.BaseConnection, cancelFn, resolvedPath, filePath, requestPath,
		common.TransferUpload, 0, initialSize, maxWriteSize, truncatedSize, isNewFile, fs, transferQuota)
	t := newTransfer(baseTransfer, w, nil, nil)

	return c.getUploadFileData(sizeToRead, t)
}

func (c *scpCommand) handleUpload(uploadFilePath string, sizeToRead int64) error {
	c.connection.UpdateLastActivity()

	fs, p, err := c.connection.GetFsAndResolvedPath(uploadFilePath)
	if err != nil {
		c.connection.Log(logger.LevelError, "error uploading file: %#v, err: %v", uploadFilePath, err)
		c.sendErrorMessage(nil, err)
		return err
	}

	if ok, _ := c.connection.User.IsFileAllowed(uploadFilePath); !ok {
		c.connection.Log(logger.LevelWarn, "writing file %#v is not allowed", uploadFilePath)
		c.sendErrorMessage(fs, c.connection.GetPermissionDeniedError())
		return common.ErrPermissionDenied
	}

	filePath := p
	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		filePath = fs.GetAtomicUploadPath(p)
	}
	stat, statErr := fs.Lstat(p)
	if (statErr == nil && stat.Mode()&os.ModeSymlink != 0) || fs.IsNotExist(statErr) {
		if !c.connection.User.HasPerm(dataprovider.PermUpload, path.Dir(uploadFilePath)) {
			c.connection.Log(logger.LevelWarn, "cannot upload file: %#v, permission denied", uploadFilePath)
			c.sendErrorMessage(fs, common.ErrPermissionDenied)
			return common.ErrPermissionDenied
		}
		return c.handleUploadFile(fs, p, filePath, sizeToRead, true, 0, uploadFilePath)
	}

	if statErr != nil {
		c.connection.Log(logger.LevelError, "error performing file stat %#v: %v", p, statErr)
		c.sendErrorMessage(fs, statErr)
		return statErr
	}

	if stat.IsDir() {
		c.connection.Log(logger.LevelError, "attempted to open a directory for writing to: %#v", p)
		err = fmt.Errorf("attempted to open a directory for writing: %#v", p)
		c.sendErrorMessage(fs, err)
		return err
	}

	if !c.connection.User.HasPerm(dataprovider.PermOverwrite, uploadFilePath) {
		c.connection.Log(logger.LevelWarn, "cannot overwrite file: %#v, permission denied", uploadFilePath)
		c.sendErrorMessage(fs, common.ErrPermissionDenied)
		return common.ErrPermissionDenied
	}

	if common.Config.IsAtomicUploadEnabled() && fs.IsAtomicUploadSupported() {
		err = fs.Rename(p, filePath)
		if err != nil {
			c.connection.Log(logger.LevelError, "error renaming existing file for atomic upload, source: %#v, dest: %#v, err: %v",
				p, filePath, err)
			c.sendErrorMessage(fs, err)
			return err
		}
	}

	return c.handleUploadFile(fs, p, filePath, sizeToRead, false, stat.Size(), uploadFilePath)
}

func (c *scpCommand) sendDownloadProtocolMessages(virtualDirPath string, stat os.FileInfo) error {
	var err error
	if c.sendFileTime() {
		modTime := stat.ModTime().UnixNano() / 1000000000
		tCommand := fmt.Sprintf("T%v 0 %v 0\n", modTime, modTime)
		err = c.sendProtocolMessage(tCommand)
		if err != nil {
			return err
		}
		err = c.readConfirmationMessage()
		if err != nil {
			return err
		}
	}

	dirName := path.Base(virtualDirPath)
	if dirName == "/" || dirName == "." {
		dirName = c.connection.User.Username
	}

	fileMode := fmt.Sprintf("D%v 0 %v\n", getFileModeAsString(stat.Mode(), stat.IsDir()), dirName)
	err = c.sendProtocolMessage(fileMode)
	if err != nil {
		return err
	}
	err = c.readConfirmationMessage()
	return err
}

// We send first all the files in the root directory and then the directories.
// For each directory we recursively call this method again
func (c *scpCommand) handleRecursiveDownload(fs vfs.Fs, dirPath, virtualPath string, stat os.FileInfo) error {
	var err error
	if c.isRecursive() {
		c.connection.Log(logger.LevelDebug, "recursive download, dir path %#v virtual path %#v", dirPath, virtualPath)
		err = c.sendDownloadProtocolMessages(virtualPath, stat)
		if err != nil {
			return err
		}
		files, err := fs.ReadDir(dirPath)
		if err != nil {
			c.sendErrorMessage(fs, err)
			return err
		}
		files = c.connection.User.FilterListDir(files, fs.GetRelativePath(dirPath))
		var dirs []string
		for _, file := range files {
			filePath := fs.GetRelativePath(fs.Join(dirPath, file.Name()))
			if file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 {
				err = c.handleDownload(filePath)
				if err != nil {
					break
				}
			} else if file.IsDir() {
				dirs = append(dirs, filePath)
			}
		}
		if err != nil {
			c.sendErrorMessage(fs, err)
			return err
		}
		for _, dir := range dirs {
			err = c.handleDownload(dir)
			if err != nil {
				break
			}
		}
		if err != nil {
			c.sendErrorMessage(fs, err)
			return err
		}
		err = c.sendProtocolMessage("E\n")
		if err != nil {
			return err
		}
		return c.readConfirmationMessage()
	}
	err = fmt.Errorf("unable to send directory for non recursive copy")
	c.sendErrorMessage(nil, err)
	return err
}

func (c *scpCommand) sendDownloadFileData(fs vfs.Fs, filePath string, stat os.FileInfo, transfer *transfer) error {
	var err error
	if c.sendFileTime() {
		modTime := stat.ModTime().UnixNano() / 1000000000
		tCommand := fmt.Sprintf("T%v 0 %v 0\n", modTime, modTime)
		err = c.sendProtocolMessage(tCommand)
		if err != nil {
			return err
		}
		err = c.readConfirmationMessage()
		if err != nil {
			return err
		}
	}
	if vfs.IsCryptOsFs(fs) {
		stat = fs.(*vfs.CryptFs).ConvertFileInfo(stat)
	}

	fileSize := stat.Size()
	readed := int64(0)
	fileMode := fmt.Sprintf("C%v %v %v\n", getFileModeAsString(stat.Mode(), stat.IsDir()), fileSize, filepath.Base(filePath))
	err = c.sendProtocolMessage(fileMode)
	if err != nil {
		return err
	}
	err = c.readConfirmationMessage()
	if err != nil {
		return err
	}

	// we could replace this method with io.CopyN implementing "Read" method in transfer struct
	buf := make([]byte, 32768)
	var n int
	for {
		n, err = transfer.ReadAt(buf, readed)
		if err == nil || err == io.EOF {
			if n > 0 {
				_, err = c.connection.channel.Write(buf[:n])
			}
		}
		readed += int64(n)
		if err != nil {
			break
		}
	}
	if err != io.EOF {
		c.sendErrorMessage(fs, err)
		return err
	}
	err = c.sendConfirmationMessage()
	if err != nil {
		return err
	}
	err = c.readConfirmationMessage()
	return err
}

func (c *scpCommand) handleDownload(filePath string) error {
	c.connection.UpdateLastActivity()
	transferQuota := c.connection.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		c.connection.Log(logger.LevelInfo, "denying file read due to quota limits")
		c.sendErrorMessage(nil, c.connection.GetReadQuotaExceededError())
		return c.connection.GetReadQuotaExceededError()
	}
	var err error

	fs, err := c.connection.User.GetFilesystemForPath(filePath, c.connection.ID)
	if err != nil {
		c.connection.Log(logger.LevelError, "error downloading file %#v: %+v", filePath, err)
		c.sendErrorMessage(nil, fmt.Errorf("unable to get fs for path %#v", filePath))
		return err
	}

	p, err := fs.ResolvePath(filePath)
	if err != nil {
		err := fmt.Errorf("invalid file path %#v", filePath)
		c.connection.Log(logger.LevelError, "error downloading file: %#v, invalid file path", filePath)
		c.sendErrorMessage(fs, err)
		return err
	}

	var stat os.FileInfo
	if stat, err = fs.Stat(p); err != nil {
		c.connection.Log(logger.LevelError, "error downloading file: %#v->%#v, err: %v", filePath, p, err)
		c.sendErrorMessage(fs, err)
		return err
	}

	if stat.IsDir() {
		if !c.connection.User.HasPerm(dataprovider.PermDownload, filePath) {
			c.connection.Log(logger.LevelWarn, "error downloading dir: %#v, permission denied", filePath)
			c.sendErrorMessage(fs, common.ErrPermissionDenied)
			return common.ErrPermissionDenied
		}
		err = c.handleRecursiveDownload(fs, p, filePath, stat)
		return err
	}

	if !c.connection.User.HasPerm(dataprovider.PermDownload, path.Dir(filePath)) {
		c.connection.Log(logger.LevelWarn, "error downloading dir: %#v, permission denied", filePath)
		c.sendErrorMessage(fs, common.ErrPermissionDenied)
		return common.ErrPermissionDenied
	}

	if ok, policy := c.connection.User.IsFileAllowed(filePath); !ok {
		c.connection.Log(logger.LevelWarn, "reading file %#v is not allowed", filePath)
		c.sendErrorMessage(fs, c.connection.GetErrorForDeniedFile(policy))
		return common.ErrPermissionDenied
	}

	if err := common.ExecutePreAction(c.connection.BaseConnection, common.OperationPreDownload, p, filePath, 0, 0); err != nil {
		c.connection.Log(logger.LevelDebug, "download for file %#v denied by pre action: %v", filePath, err)
		c.sendErrorMessage(fs, common.ErrPermissionDenied)
		return common.ErrPermissionDenied
	}

	file, r, cancelFn, err := fs.Open(p, 0)
	if err != nil {
		c.connection.Log(logger.LevelError, "could not open file %#v for reading: %v", p, err)
		c.sendErrorMessage(fs, err)
		return err
	}

	baseTransfer := common.NewBaseTransfer(file, c.connection.BaseConnection, cancelFn, p, p, filePath,
		common.TransferDownload, 0, 0, 0, 0, false, fs, transferQuota)
	t := newTransfer(baseTransfer, nil, r, nil)

	err = c.sendDownloadFileData(fs, p, stat, t)
	// we need to call Close anyway and return close error if any and
	// if we have no previous error
	if err == nil {
		err = t.Close()
	} else {
		t.TransferError(err)
		t.Close()
	}
	return err
}

func (c *scpCommand) getCommandType() string {
	return c.args[len(c.args)-2]
}

func (c *scpCommand) sendFileTime() bool {
	return util.IsStringInSlice("-p", c.args)
}

func (c *scpCommand) isRecursive() bool {
	return util.IsStringInSlice("-r", c.args)
}

// read the SCP confirmation message and the optional text message
// the channel will be closed on errors
func (c *scpCommand) readConfirmationMessage() error {
	var msg strings.Builder
	buf := make([]byte, 1)
	n, err := c.connection.channel.Read(buf)
	if err != nil {
		c.connection.channel.Close()
		return err
	}
	if n == 1 && (buf[0] == warnMsg[0] || buf[0] == errMsg[0]) {
		isError := buf[0] == errMsg[0]
		for {
			n, err = c.connection.channel.Read(buf)
			readed := buf[:n]
			if err != nil || (n == 1 && readed[0] == newLine[0]) {
				break
			}
			if n > 0 {
				msg.Write(readed)
			}
		}
		c.connection.Log(logger.LevelInfo, "scp error message received: %v is error: %v", msg.String(), isError)
		err = fmt.Errorf("%v", msg.String())
		c.connection.channel.Close()
	}
	return err
}

// protool messages are newline terminated
func (c *scpCommand) readProtocolMessage() (string, error) {
	var command strings.Builder
	var err error
	buf := make([]byte, 1)
	for {
		var n int
		n, err = c.connection.channel.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			readed := buf[:n]
			if n == 1 && readed[0] == newLine[0] {
				break
			}
			command.Write(readed)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		c.connection.channel.Close()
	}
	return command.String(), err
}

// send an error message and close the channel
//nolint:errcheck // we don't check write errors here, we have to close the channel anyway
func (c *scpCommand) sendErrorMessage(fs vfs.Fs, err error) {
	c.connection.channel.Write(errMsg)
	if fs != nil {
		c.connection.channel.Write([]byte(c.connection.GetFsError(fs, err).Error()))
	} else {
		c.connection.channel.Write([]byte(err.Error()))
	}
	c.connection.channel.Write(newLine)
	c.connection.channel.Close()
}

// send scp confirmation message and close the channel if an error happen
func (c *scpCommand) sendConfirmationMessage() error {
	_, err := c.connection.channel.Write(okMsg)
	if err != nil {
		c.connection.channel.Close()
	}
	return err
}

// sends a protocol message and close the channel on error
func (c *scpCommand) sendProtocolMessage(message string) error {
	_, err := c.connection.channel.Write([]byte(message))
	if err != nil {
		c.connection.Log(logger.LevelError, "error sending protocol message: %v, err: %v", message, err)
		c.connection.channel.Close()
	}
	return err
}

// get the next upload protocol message ignoring T command if any
func (c *scpCommand) getNextUploadProtocolMessage() (string, error) {
	var command string
	var err error
	for {
		command, err = c.readProtocolMessage()
		if err != nil {
			return command, err
		}
		if strings.HasPrefix(command, "T") {
			err = c.sendConfirmationMessage()
			if err != nil {
				return command, err
			}
		} else {
			break
		}
	}
	return command, err
}

func (c *scpCommand) createDir(fs vfs.Fs, dirPath string) error {
	err := fs.Mkdir(dirPath)
	if err != nil {
		c.connection.Log(logger.LevelError, "error creating dir %#v: %v", dirPath, err)
		c.sendErrorMessage(fs, err)
		return err
	}
	vfs.SetPathPermissions(fs, dirPath, c.connection.User.GetUID(), c.connection.User.GetGID())
	return err
}

// parse protocol messages such as:
// D0755 0 testdir
// or:
// C0644 6 testfile
// and returns file size and file/directory name
func (c *scpCommand) parseUploadMessage(fs vfs.Fs, command string) (int64, string, error) {
	var size int64
	var name string
	var err error
	if !strings.HasPrefix(command, "C") && !strings.HasPrefix(command, "D") {
		err = fmt.Errorf("unknown or invalid upload message: %v args: %v user: %v",
			command, c.args, c.connection.User.Username)
		c.connection.Log(logger.LevelError, "error: %v", err)
		c.sendErrorMessage(fs, err)
		return size, name, err
	}
	parts := strings.SplitN(command, " ", 3)
	if len(parts) == 3 {
		size, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			c.connection.Log(logger.LevelError, "error getting size from upload message: %v", err)
			c.sendErrorMessage(fs, err)
			return size, name, err
		}
		name = parts[2]
		if name == "" {
			err = fmt.Errorf("error getting name from upload message, cannot be empty")
			c.connection.Log(logger.LevelError, "error: %v", err)
			c.sendErrorMessage(fs, err)
			return size, name, err
		}
	} else {
		err = fmt.Errorf("unable to split upload message: %#v", command)
		c.connection.Log(logger.LevelError, "error: %v", err)
		c.sendErrorMessage(fs, err)
		return size, name, err
	}
	return size, name, err
}

func (c *scpCommand) getFileUploadDestPath(fs vfs.Fs, scpDestPath, fileName string) string {
	if !c.isRecursive() {
		// if the upload is not recursive and the destination path does not end with "/"
		// then scpDestPath is the wanted filename, for example:
		// scp fileName.txt user@127.0.0.1:/newFileName.txt
		// or
		// scp fileName.txt user@127.0.0.1:/fileName.txt
		if !strings.HasSuffix(scpDestPath, "/") {
			// but if scpDestPath is an existing directory then we put the uploaded file
			// inside that directory this is as scp command works, for example:
			// scp fileName.txt user@127.0.0.1:/existing_dir
			if p, err := fs.ResolvePath(scpDestPath); err == nil {
				if stat, err := fs.Stat(p); err == nil {
					if stat.IsDir() {
						return path.Join(scpDestPath, fileName)
					}
				}
			}
			return scpDestPath
		}
	}
	// if the upload is recursive or scpDestPath has the "/" suffix then the destination
	// file is relative to scpDestPath
	return path.Join(scpDestPath, fileName)
}

func getFileModeAsString(fileMode os.FileMode, isDir bool) string {
	var defaultMode string
	if isDir {
		defaultMode = "0755"
	} else {
		defaultMode = "0644"
	}
	if fileMode == 0 {
		return defaultMode
	}
	modeString := []byte(fileMode.String())
	nullPerm := []byte("-")
	u := 0
	g := 0
	o := 0
	s := 0
	lastChar := len(modeString) - 1
	if fileMode&os.ModeSticky != 0 {
		s++
	}
	if fileMode&os.ModeSetuid != 0 {
		s += 2
	}
	if fileMode&os.ModeSetgid != 0 {
		s += 4
	}
	if modeString[lastChar-8] != nullPerm[0] {
		u += 4
	}
	if modeString[lastChar-7] != nullPerm[0] {
		u += 2
	}
	if modeString[lastChar-6] != nullPerm[0] {
		u++
	}
	if modeString[lastChar-5] != nullPerm[0] {
		g += 4
	}
	if modeString[lastChar-4] != nullPerm[0] {
		g += 2
	}
	if modeString[lastChar-3] != nullPerm[0] {
		g++
	}
	if modeString[lastChar-2] != nullPerm[0] {
		o += 4
	}
	if modeString[lastChar-1] != nullPerm[0] {
		o += 2
	}
	if modeString[lastChar] != nullPerm[0] {
		o++
	}
	return fmt.Sprintf("%v%v%v%v", s, u, g, o)
}
