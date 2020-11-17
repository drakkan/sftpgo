package sftpd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/google/shlex"
	fscopy "github.com/otiai10/copy"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	scpCmdName          = "scp"
	sshCommandLogSender = "SSHCommand"
)

var (
	errUnsupportedConfig = errors.New("command unsupported for this configuration")
)

type sshCommand struct {
	command    string
	args       []string
	connection *Connection
}

type systemCommand struct {
	cmd            *exec.Cmd
	fsPath         string
	quotaCheckPath string
}

func processSSHCommand(payload []byte, connection *Connection, enabledSSHCommands []string) bool {
	var msg sshSubsystemExecMsg
	if err := ssh.Unmarshal(payload, &msg); err == nil {
		name, args, err := parseCommandPayload(msg.Command)
		connection.Log(logger.LevelDebug, "new ssh command: %#v args: %v num args: %v user: %v, error: %v",
			name, args, len(args), connection.User.Username, err)
		if err == nil && utils.IsStringInSlice(name, enabledSSHCommands) {
			connection.command = msg.Command
			if name == scpCmdName && len(args) >= 2 {
				connection.SetProtocol(common.ProtocolSCP)
				scpCommand := scpCommand{
					sshCommand: sshCommand{
						command:    name,
						connection: connection,
						args:       args},
				}
				go scpCommand.handle() //nolint:errcheck
				return true
			}
			if name != scpCmdName {
				connection.SetProtocol(common.ProtocolSSH)
				sshCommand := sshCommand{
					command:    name,
					connection: connection,
					args:       args,
				}
				go sshCommand.handle() //nolint:errcheck
				return true
			}
		} else {
			connection.Log(logger.LevelInfo, "ssh command not enabled/supported: %#v", name)
		}
	}
	return false
}

func (c *sshCommand) handle() (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(logSender, "", "panic in handle ssh command: %#v stack strace: %v", r, string(debug.Stack()))
			err = common.ErrGenericFailure
		}
	}()
	common.Connections.Add(c.connection)
	defer common.Connections.Remove(c.connection.GetID())

	c.connection.UpdateLastActivity()
	if utils.IsStringInSlice(c.command, sshHashCommands) {
		return c.handleHashCommands()
	} else if utils.IsStringInSlice(c.command, systemCommands) {
		command, err := c.getSystemCommand()
		if err != nil {
			return c.sendErrorResponse(err)
		}
		return c.executeSystemCommand(command)
	} else if c.command == "cd" {
		c.sendExitStatus(nil)
	} else if c.command == "pwd" {
		// hard coded response to "/"
		c.connection.channel.Write([]byte("/\n")) //nolint:errcheck
		c.sendExitStatus(nil)
	} else if c.command == "sftpgo-copy" {
		return c.handeSFTPGoCopy()
	} else if c.command == "sftpgo-remove" {
		return c.handeSFTPGoRemove()
	}
	return
}

func (c *sshCommand) handeSFTPGoCopy() error {
	if !vfs.IsLocalOsFs(c.connection.Fs) {
		return c.sendErrorResponse(errUnsupportedConfig)
	}
	sshSourcePath, sshDestPath, err := c.getCopyPaths()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	fsSourcePath, fsDestPath, err := c.resolveCopyPaths(sshSourcePath, sshDestPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	if err := c.checkCopyDestination(fsDestPath); err != nil {
		return c.sendErrorResponse(err)
	}

	c.connection.Log(logger.LevelDebug, "requested copy %#v -> %#v sftp paths %#v -> %#v",
		fsSourcePath, fsDestPath, sshSourcePath, sshDestPath)

	fi, err := c.connection.Fs.Lstat(fsSourcePath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	if err := c.checkCopyPermissions(fsSourcePath, fsDestPath, sshSourcePath, sshDestPath, fi); err != nil {
		return c.sendErrorResponse(err)
	}
	filesNum := 0
	filesSize := int64(0)
	if fi.IsDir() {
		filesNum, filesSize, err = c.connection.Fs.GetDirSize(fsSourcePath)
		if err != nil {
			return c.sendErrorResponse(err)
		}
		if c.connection.User.HasVirtualFoldersInside(sshSourcePath) {
			err := errors.New("unsupported copy source: the source directory contains virtual folders")
			return c.sendErrorResponse(err)
		}
		if c.connection.User.HasVirtualFoldersInside(sshDestPath) {
			err := errors.New("unsupported copy source: the destination directory contains virtual folders")
			return c.sendErrorResponse(err)
		}
	} else if fi.Mode().IsRegular() {
		if !c.connection.User.IsFileAllowed(sshDestPath) {
			err := errors.New("unsupported copy destination: this file is not allowed")
			return c.sendErrorResponse(err)
		}
		filesNum = 1
		filesSize = fi.Size()
	} else {
		err := errors.New("unsupported copy source: only files and directories are supported")
		return c.sendErrorResponse(err)
	}
	if err := c.checkCopyQuota(filesNum, filesSize, sshDestPath); err != nil {
		return c.sendErrorResponse(err)
	}
	c.connection.Log(logger.LevelDebug, "start copy %#v -> %#v", fsSourcePath, fsDestPath)
	err = fscopy.Copy(fsSourcePath, fsDestPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	c.updateQuota(sshDestPath, filesNum, filesSize)
	c.connection.channel.Write([]byte("OK\n")) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) handeSFTPGoRemove() error {
	if !vfs.IsLocalOsFs(c.connection.Fs) {
		return c.sendErrorResponse(errUnsupportedConfig)
	}
	sshDestPath, err := c.getRemovePath()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	if !c.connection.User.HasPerm(dataprovider.PermDelete, path.Dir(sshDestPath)) {
		return c.sendErrorResponse(common.ErrPermissionDenied)
	}
	fsDestPath, err := c.connection.Fs.ResolvePath(sshDestPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	fi, err := c.connection.Fs.Lstat(fsDestPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	filesNum := 0
	filesSize := int64(0)
	if fi.IsDir() {
		filesNum, filesSize, err = c.connection.Fs.GetDirSize(fsDestPath)
		if err != nil {
			return c.sendErrorResponse(err)
		}
		if sshDestPath == "/" {
			err := errors.New("removing root dir is not allowed")
			return c.sendErrorResponse(err)
		}
		if c.connection.User.HasVirtualFoldersInside(sshDestPath) {
			err := errors.New("unsupported remove source: this directory contains virtual folders")
			return c.sendErrorResponse(err)
		}
		if c.connection.User.IsVirtualFolder(sshDestPath) {
			err := errors.New("unsupported remove source: this directory is a virtual folder")
			return c.sendErrorResponse(err)
		}
		if c.connection.User.IsMappedPath(fsDestPath) {
			err := errors.New("removing a directory mapped as virtual folder is not allowed")
			return c.sendErrorResponse(err)
		}
	} else if fi.Mode().IsRegular() {
		filesNum = 1
		filesSize = fi.Size()
	} else {
		err := errors.New("unsupported remove source: only files and directories are supported")
		return c.sendErrorResponse(err)
	}

	err = os.RemoveAll(fsDestPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}
	c.updateQuota(sshDestPath, -filesNum, -filesSize)
	c.connection.channel.Write([]byte("OK\n")) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) updateQuota(sshDestPath string, filesNum int, filesSize int64) {
	vfolder, err := c.connection.User.GetVirtualFolderForPath(sshDestPath)
	if err == nil {
		dataprovider.UpdateVirtualFolderQuota(vfolder.BaseVirtualFolder, filesNum, filesSize, false) //nolint:errcheck
		if vfolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(c.connection.User, filesNum, filesSize, false) //nolint:errcheck
		}
	} else {
		dataprovider.UpdateUserQuota(c.connection.User, filesNum, filesSize, false) //nolint:errcheck
	}
}

func (c *sshCommand) handleHashCommands() error {
	if !vfs.IsLocalOsFs(c.connection.Fs) {
		return c.sendErrorResponse(errUnsupportedConfig)
	}
	var h hash.Hash
	if c.command == "md5sum" {
		h = md5.New()
	} else if c.command == "sha1sum" {
		h = sha1.New()
	} else if c.command == "sha256sum" {
		h = sha256.New()
	} else if c.command == "sha384sum" {
		h = sha512.New384()
	} else {
		h = sha512.New()
	}
	var response string
	if len(c.args) == 0 {
		// without args we need to read the string to hash from stdin
		buf := make([]byte, 4096)
		n, err := c.connection.channel.Read(buf)
		if err != nil && err != io.EOF {
			return c.sendErrorResponse(err)
		}
		h.Write(buf[:n]) //nolint:errcheck
		response = fmt.Sprintf("%x  -\n", h.Sum(nil))
	} else {
		sshPath := c.getDestPath()
		if !c.connection.User.IsFileAllowed(sshPath) {
			c.connection.Log(logger.LevelInfo, "hash not allowed for file %#v", sshPath)
			return c.sendErrorResponse(common.ErrPermissionDenied)
		}
		fsPath, err := c.connection.Fs.ResolvePath(sshPath)
		if err != nil {
			return c.sendErrorResponse(err)
		}
		if !c.connection.User.HasPerm(dataprovider.PermListItems, sshPath) {
			return c.sendErrorResponse(common.ErrPermissionDenied)
		}
		hash, err := computeHashForFile(h, fsPath)
		if err != nil {
			return c.sendErrorResponse(err)
		}
		response = fmt.Sprintf("%v  %v\n", hash, sshPath)
	}
	c.connection.channel.Write([]byte(response)) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) executeSystemCommand(command systemCommand) error {
	if !vfs.IsLocalOsFs(c.connection.Fs) {
		return c.sendErrorResponse(errUnsupportedConfig)
	}
	sshDestPath := c.getDestPath()
	quotaResult := c.connection.HasSpace(true, command.quotaCheckPath)
	if !quotaResult.HasSpace {
		return c.sendErrorResponse(common.ErrQuotaExceeded)
	}
	perms := []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermCreateDirs, dataprovider.PermListItems,
		dataprovider.PermOverwrite, dataprovider.PermDelete}
	if !c.connection.User.HasPerms(perms, sshDestPath) {
		return c.sendErrorResponse(common.ErrPermissionDenied)
	}

	initialFiles, initialSize, err := c.getSizeForPath(command.fsPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}

	stdin, err := command.cmd.StdinPipe()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	stdout, err := command.cmd.StdoutPipe()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	stderr, err := command.cmd.StderrPipe()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	err = command.cmd.Start()
	if err != nil {
		return c.sendErrorResponse(err)
	}

	closeCmdOnError := func() {
		c.connection.Log(logger.LevelDebug, "kill cmd: %#v and close ssh channel after read or write error",
			c.connection.command)
		killerr := command.cmd.Process.Kill()
		closerr := c.connection.channel.Close()
		c.connection.Log(logger.LevelDebug, "kill cmd error: %v close channel error: %v", killerr, closerr)
	}
	var once sync.Once
	commandResponse := make(chan bool)

	remainingQuotaSize := quotaResult.GetRemainingSize()

	go func() {
		defer stdin.Close()
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, sshDestPath,
			common.TransferUpload, 0, 0, remainingQuotaSize, false, c.connection.Fs)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(stdin, c.connection.channel)
		c.connection.Log(logger.LevelDebug, "command: %#v, copy from remote command to sdtin ended, written: %v, "+
			"initial remaining quota: %v, err: %v", c.connection.command, w, remainingQuotaSize, e)
		if e != nil {
			once.Do(closeCmdOnError)
		}
	}()

	go func() {
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, sshDestPath,
			common.TransferDownload, 0, 0, 0, false, c.connection.Fs)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(c.connection.channel, stdout)
		c.connection.Log(logger.LevelDebug, "command: %#v, copy from sdtout to remote command ended, written: %v err: %v",
			c.connection.command, w, e)
		if e != nil {
			once.Do(closeCmdOnError)
		}
		commandResponse <- true
	}()

	go func() {
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, sshDestPath,
			common.TransferDownload, 0, 0, 0, false, c.connection.Fs)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(c.connection.channel.(ssh.Channel).Stderr(), stderr)
		c.connection.Log(logger.LevelDebug, "command: %#v, copy from sdterr to remote command ended, written: %v err: %v",
			c.connection.command, w, e)
		// os.ErrClosed means that the command is finished so we don't need to do anything
		if (e != nil && !errors.Is(e, os.ErrClosed)) || w > 0 {
			once.Do(closeCmdOnError)
		}
	}()

	<-commandResponse
	err = command.cmd.Wait()
	c.sendExitStatus(err)

	numFiles, dirSize, errSize := c.getSizeForPath(command.fsPath)
	if errSize == nil {
		c.updateQuota(sshDestPath, numFiles-initialFiles, dirSize-initialSize)
	}
	c.connection.Log(logger.LevelDebug, "command %#v finished for path %#v, initial files %v initial size %v "+
		"current files %v current size %v size err: %v", c.connection.command, command.fsPath, initialFiles, initialSize,
		numFiles, dirSize, errSize)
	return err
}

func (c *sshCommand) isSystemCommandAllowed() error {
	sshDestPath := c.getDestPath()
	if c.connection.User.IsVirtualFolder(sshDestPath) {
		// overlapped virtual path are not allowed
		return nil
	}
	if c.connection.User.HasVirtualFoldersInside(sshDestPath) {
		c.connection.Log(logger.LevelDebug, "command %#v is not allowed, path %#v has virtual folders inside it, user %#v",
			c.command, sshDestPath, c.connection.User.Username)
		return errUnsupportedConfig
	}
	for _, f := range c.connection.User.Filters.FileExtensions {
		if f.Path == sshDestPath {
			c.connection.Log(logger.LevelDebug,
				"command %#v is not allowed inside folders with files extensions filters %#v user %#v",
				c.command, sshDestPath, c.connection.User.Username)
			return errUnsupportedConfig
		}
		if len(sshDestPath) > len(f.Path) {
			if strings.HasPrefix(sshDestPath, f.Path+"/") || f.Path == "/" {
				c.connection.Log(logger.LevelDebug,
					"command %#v is not allowed it includes folders with files extensions filters %#v user %#v",
					c.command, sshDestPath, c.connection.User.Username)
				return errUnsupportedConfig
			}
		}
		if len(sshDestPath) < len(f.Path) {
			if strings.HasPrefix(sshDestPath+"/", f.Path) || sshDestPath == "/" {
				c.connection.Log(logger.LevelDebug,
					"command %#v is not allowed inside folder with files extensions filters %#v user %#v",
					c.command, sshDestPath, c.connection.User.Username)
				return errUnsupportedConfig
			}
		}
	}
	return nil
}

func (c *sshCommand) getSystemCommand() (systemCommand, error) {
	command := systemCommand{
		cmd:            nil,
		fsPath:         "",
		quotaCheckPath: "",
	}
	args := make([]string, len(c.args))
	copy(args, c.args)
	var fsPath, quotaPath string
	if len(c.args) > 0 {
		var err error
		sshPath := c.getDestPath()
		fsPath, err = c.connection.Fs.ResolvePath(sshPath)
		if err != nil {
			return command, err
		}
		quotaPath = sshPath
		fi, err := c.connection.Fs.Stat(fsPath)
		if err == nil && fi.IsDir() {
			// if the target is an existing dir the command will write inside this dir
			// so we need to check the quota for this directory and not its parent dir
			quotaPath = path.Join(sshPath, "fakecontent")
		}
		args = args[:len(args)-1]
		args = append(args, fsPath)
	}
	if err := c.isSystemCommandAllowed(); err != nil {
		return command, errUnsupportedConfig
	}
	if c.command == "rsync" {
		// we cannot avoid that rsync creates symlinks so if the user has the permission
		// to create symlinks we add the option --safe-links to the received rsync command if
		// it is not already set. This should prevent to create symlinks that point outside
		// the home dir.
		// If the user cannot create symlinks we add the option --munge-links, if it is not
		// already set. This should make symlinks unusable (but manually recoverable)
		if c.connection.User.HasPerm(dataprovider.PermCreateSymlinks, c.getDestPath()) {
			if !utils.IsStringInSlice("--safe-links", args) {
				args = append([]string{"--safe-links"}, args...)
			}
		} else {
			if !utils.IsStringInSlice("--munge-links", args) {
				args = append([]string{"--munge-links"}, args...)
			}
		}
	}
	c.connection.Log(logger.LevelDebug, "new system command %#v, with args: %+v fs path %#v quota check path %#v",
		c.command, args, fsPath, quotaPath)
	cmd := exec.Command(c.command, args...)
	uid := c.connection.User.GetUID()
	gid := c.connection.User.GetGID()
	cmd = wrapCmd(cmd, uid, gid)
	command.cmd = cmd
	command.fsPath = fsPath
	command.quotaCheckPath = quotaPath
	return command, nil
}

// for the supported commands, the destination path, if any, is the last argument
func (c *sshCommand) getDestPath() string {
	if len(c.args) == 0 {
		return ""
	}
	return cleanCommandPath(c.args[len(c.args)-1])
}

// for the supported commands, the destination path, if any, is the second-last argument
func (c *sshCommand) getSourcePath() string {
	if len(c.args) < 2 {
		return ""
	}
	return cleanCommandPath(c.args[len(c.args)-2])
}

func cleanCommandPath(name string) string {
	name = strings.Trim(name, "'")
	name = strings.Trim(name, "\"")
	result := utils.CleanPath(name)
	if strings.HasSuffix(name, "/") && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func (c *sshCommand) getCopyPaths() (string, string, error) {
	sshSourcePath := strings.TrimSuffix(c.getSourcePath(), "/")
	sshDestPath := c.getDestPath()
	if strings.HasSuffix(sshDestPath, "/") {
		sshDestPath = path.Join(sshDestPath, path.Base(sshSourcePath))
	}
	if len(sshSourcePath) == 0 || len(sshDestPath) == 0 || len(c.args) != 2 {
		err := errors.New("usage sftpgo-copy <source dir path> <destination dir path>")
		return "", "", err
	}
	return sshSourcePath, sshDestPath, nil
}

func (c *sshCommand) hasCopyPermissions(sshSourcePath, sshDestPath string, srcInfo os.FileInfo) bool {
	if !c.connection.User.HasPerm(dataprovider.PermListItems, path.Dir(sshSourcePath)) {
		return false
	}
	if srcInfo.IsDir() {
		return c.connection.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(sshDestPath))
	} else if srcInfo.Mode()&os.ModeSymlink != 0 {
		return c.connection.User.HasPerm(dataprovider.PermCreateSymlinks, path.Dir(sshDestPath))
	}
	return c.connection.User.HasPerm(dataprovider.PermUpload, path.Dir(sshDestPath))
}

// fsSourcePath must be a directory
func (c *sshCommand) checkRecursiveCopyPermissions(fsSourcePath, fsDestPath, sshDestPath string) error {
	if !c.connection.User.HasPerm(dataprovider.PermCreateDirs, path.Dir(sshDestPath)) {
		return common.ErrPermissionDenied
	}
	dstPerms := []string{
		dataprovider.PermCreateDirs,
		dataprovider.PermCreateSymlinks,
		dataprovider.PermUpload,
	}

	err := c.connection.Fs.Walk(fsSourcePath, func(walkedPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		fsDstSubPath := strings.Replace(walkedPath, fsSourcePath, fsDestPath, 1)
		sshSrcSubPath := c.connection.Fs.GetRelativePath(walkedPath)
		sshDstSubPath := c.connection.Fs.GetRelativePath(fsDstSubPath)
		// If the current dir has no subdirs with defined permissions inside it
		// and it has all the possible permissions we can stop scanning
		if !c.connection.User.HasPermissionsInside(path.Dir(sshSrcSubPath)) &&
			!c.connection.User.HasPermissionsInside(path.Dir(sshDstSubPath)) {
			if c.connection.User.HasPerm(dataprovider.PermListItems, path.Dir(sshSrcSubPath)) &&
				c.connection.User.HasPerms(dstPerms, path.Dir(sshDstSubPath)) {
				return common.ErrSkipPermissionsCheck
			}
		}
		if !c.hasCopyPermissions(sshSrcSubPath, sshDstSubPath, info) {
			return common.ErrPermissionDenied
		}
		return nil
	})
	if err == common.ErrSkipPermissionsCheck {
		err = nil
	}
	return err
}

func (c *sshCommand) checkCopyPermissions(fsSourcePath, fsDestPath, sshSourcePath, sshDestPath string, info os.FileInfo) error {
	if info.IsDir() {
		return c.checkRecursiveCopyPermissions(fsSourcePath, fsDestPath, sshDestPath)
	}
	if !c.hasCopyPermissions(sshSourcePath, sshDestPath, info) {
		return common.ErrPermissionDenied
	}
	return nil
}

func (c *sshCommand) getRemovePath() (string, error) {
	sshDestPath := c.getDestPath()
	if len(sshDestPath) == 0 || len(c.args) != 1 {
		err := errors.New("usage sftpgo-remove <destination path>")
		return "", err
	}
	if len(sshDestPath) > 1 {
		sshDestPath = strings.TrimSuffix(sshDestPath, "/")
	}
	return sshDestPath, nil
}

func (c *sshCommand) resolveCopyPaths(sshSourcePath, sshDestPath string) (string, string, error) {
	fsSourcePath, err := c.connection.Fs.ResolvePath(sshSourcePath)
	if err != nil {
		return "", "", err
	}
	fsDestPath, err := c.connection.Fs.ResolvePath(sshDestPath)
	if err != nil {
		return "", "", err
	}
	return fsSourcePath, fsDestPath, nil
}

func (c *sshCommand) checkCopyDestination(fsDestPath string) error {
	_, err := c.connection.Fs.Lstat(fsDestPath)
	if err == nil {
		err := errors.New("invalid copy destination: cannot overwrite an existing file or directory")
		return err
	} else if !c.connection.Fs.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *sshCommand) checkCopyQuota(numFiles int, filesSize int64, requestPath string) error {
	quotaResult := c.connection.HasSpace(true, requestPath)
	if !quotaResult.HasSpace {
		return common.ErrQuotaExceeded
	}
	if quotaResult.QuotaFiles > 0 {
		remainingFiles := quotaResult.GetRemainingFiles()
		if remainingFiles < numFiles {
			c.connection.Log(logger.LevelDebug, "copy not allowed, file limit will be exceeded, "+
				"remaining files: %v to copy: %v", remainingFiles, numFiles)
			return common.ErrQuotaExceeded
		}
	}
	if quotaResult.QuotaSize > 0 {
		remainingSize := quotaResult.GetRemainingSize()
		if remainingSize < filesSize {
			c.connection.Log(logger.LevelDebug, "copy not allowed, size limit will be exceeded, "+
				"remaining size: %v to copy: %v", remainingSize, filesSize)
			return common.ErrQuotaExceeded
		}
	}
	return nil
}

func (c *sshCommand) getSizeForPath(name string) (int, int64, error) {
	if dataprovider.GetQuotaTracking() > 0 {
		fi, err := c.connection.Fs.Lstat(name)
		if err != nil {
			if c.connection.Fs.IsNotExist(err) {
				return 0, 0, nil
			}
			c.connection.Log(logger.LevelDebug, "unable to stat %#v error: %v", name, err)
			return 0, 0, err
		}
		if fi.IsDir() {
			files, size, err := c.connection.Fs.GetDirSize(name)
			if err != nil {
				c.connection.Log(logger.LevelDebug, "unable to get size for dir %#v error: %v", name, err)
			}
			return files, size, err
		} else if fi.Mode().IsRegular() {
			return 1, fi.Size(), nil
		}
	}
	return 0, 0, nil
}

func (c *sshCommand) sendErrorResponse(err error) error {
	errorString := fmt.Sprintf("%v: %v %v\n", c.command, c.getDestPath(), c.connection.GetFsError(err))
	c.connection.channel.Write([]byte(errorString)) //nolint:errcheck
	c.sendExitStatus(err)
	return err
}

func (c *sshCommand) sendExitStatus(err error) {
	status := uint32(0)
	cmdPath := c.getDestPath()
	targetPath := ""
	if c.command == "sftpgo-copy" {
		targetPath = cmdPath
		cmdPath = c.getSourcePath()
	}
	if err != nil {
		status = uint32(1)
		c.connection.Log(logger.LevelWarn, "command failed: %#v args: %v user: %v err: %v",
			c.command, c.args, c.connection.User.Username, err)
	} else {
		logger.CommandLog(sshCommandLogSender, cmdPath, targetPath, c.connection.User.Username, "", c.connection.ID,
			common.ProtocolSSH, -1, -1, "", "", c.connection.command, -1)
	}
	exitStatus := sshSubsystemExitStatus{
		Status: status,
	}
	c.connection.channel.(ssh.Channel).SendRequest("exit-status", false, ssh.Marshal(&exitStatus)) //nolint:errcheck
	c.connection.channel.Close()
	// for scp we notify single uploads/downloads
	if c.command != scpCmdName {
		metrics.SSHCommandCompleted(err)
		if len(cmdPath) > 0 {
			p, e := c.connection.Fs.ResolvePath(cmdPath)
			if e == nil {
				cmdPath = p
			}
		}
		if len(targetPath) > 0 {
			p, e := c.connection.Fs.ResolvePath(targetPath)
			if e == nil {
				targetPath = p
			}
		}
		common.SSHCommandActionNotification(&c.connection.User, cmdPath, targetPath, c.command, err)
	}
}

func computeHashForFile(hasher hash.Hash, path string) (string, error) {
	hash := ""
	f, err := os.Open(path)
	if err != nil {
		return hash, err
	}
	defer f.Close()
	_, err = io.Copy(hasher, f)
	if err == nil {
		hash = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	return hash, err
}

func parseCommandPayload(command string) (string, []string, error) {
	parts, err := shlex.Split(command)
	if err == nil && len(parts) == 0 {
		err = fmt.Errorf("invalid command: %#v", command)
	}
	if err != nil {
		return "", []string{}, err
	}
	if len(parts) < 2 {
		return parts[0], []string{}, nil
	}
	return parts[0], parts[1:], nil
}
