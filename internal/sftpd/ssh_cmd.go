// Copyright (C) 2019 Nicola Murino
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
	"time"

	"github.com/google/shlex"
	"github.com/sftpgo/sdk"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
	startTime  time.Time
}

type systemCommand struct {
	cmd            *exec.Cmd
	fsPath         string
	quotaCheckPath string
	fs             vfs.Fs
}

func (c *systemCommand) GetSTDs() (io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, nil, nil, err
	}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, nil, nil, err
	}
	return stdin, stdout, stderr, nil
}

func processSSHCommand(payload []byte, connection *Connection, enabledSSHCommands []string) bool {
	var msg sshSubsystemExecMsg
	if err := ssh.Unmarshal(payload, &msg); err == nil {
		name, args, err := parseCommandPayload(msg.Command)
		connection.Log(logger.LevelDebug, "new ssh command: %q args: %v num args: %d user: %s, error: %v",
			name, args, len(args), connection.User.Username, err)
		if err == nil && util.Contains(enabledSSHCommands, name) {
			connection.command = msg.Command
			if name == scpCmdName && len(args) >= 2 {
				connection.SetProtocol(common.ProtocolSCP)
				scpCommand := scpCommand{
					sshCommand: sshCommand{
						command:    name,
						connection: connection,
						startTime:  time.Now(),
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
					startTime:  time.Now(),
					args:       args,
				}
				go sshCommand.handle() //nolint:errcheck
				return true
			}
		} else {
			connection.Log(logger.LevelInfo, "ssh command not enabled/supported: %q", name)
		}
	}
	err := connection.CloseFS()
	connection.Log(logger.LevelError, "unable to unmarshal ssh command, close fs, err: %v", err)
	return false
}

func (c *sshCommand) handle() (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(logSender, "", "panic in handle ssh command: %q stack trace: %v", r, string(debug.Stack()))
			err = common.ErrGenericFailure
		}
	}()
	if err := common.Connections.Add(c.connection); err != nil {
		logger.Info(logSender, "", "unable to add SSH command connection: %v", err)
		return err
	}
	defer common.Connections.Remove(c.connection.GetID())

	c.connection.UpdateLastActivity()
	if util.Contains(sshHashCommands, c.command) {
		return c.handleHashCommands()
	} else if util.Contains(systemCommands, c.command) {
		command, err := c.getSystemCommand()
		if err != nil {
			return c.sendErrorResponse(err)
		}
		return c.executeSystemCommand(command)
	} else if c.command == "cd" {
		c.sendExitStatus(nil)
	} else if c.command == "pwd" {
		// hard coded response to the start directory
		c.connection.channel.Write([]byte(util.CleanPath(c.connection.User.Filters.StartDirectory) + "\n")) //nolint:errcheck
		c.sendExitStatus(nil)
	} else if c.command == "sftpgo-copy" {
		return c.handleSFTPGoCopy()
	} else if c.command == "sftpgo-remove" {
		return c.handleSFTPGoRemove()
	}
	return
}

func (c *sshCommand) handleSFTPGoCopy() error {
	sshSourcePath := c.getSourcePath()
	sshDestPath := c.getDestPath()
	if sshSourcePath == "" || sshDestPath == "" || len(c.args) != 2 {
		return c.sendErrorResponse(errors.New("usage sftpgo-copy <source dir path> <destination dir path>"))
	}
	c.connection.Log(logger.LevelDebug, "requested copy %q -> %q", sshSourcePath, sshDestPath)
	if err := c.connection.Copy(sshSourcePath, sshDestPath); err != nil {
		return c.sendErrorResponse(err)
	}
	c.connection.channel.Write([]byte("OK\n")) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) handleSFTPGoRemove() error {
	sshDestPath, err := c.getRemovePath()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	if err := c.connection.RemoveAll(sshDestPath); err != nil {
		return c.sendErrorResponse(err)
	}
	c.connection.channel.Write([]byte("OK\n")) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) updateQuota(sshDestPath string, filesNum int, filesSize int64) {
	vfolder, err := c.connection.User.GetVirtualFolderForPath(sshDestPath)
	if err == nil {
		dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, filesNum, filesSize, false) //nolint:errcheck
		if vfolder.IsIncludedInUserQuota() {
			dataprovider.UpdateUserQuota(&c.connection.User, filesNum, filesSize, false) //nolint:errcheck
		}
	} else {
		dataprovider.UpdateUserQuota(&c.connection.User, filesNum, filesSize, false) //nolint:errcheck
	}
}

func (c *sshCommand) handleHashCommands() error {
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
		if ok, policy := c.connection.User.IsFileAllowed(sshPath); !ok {
			c.connection.Log(logger.LevelInfo, "hash not allowed for file %q", sshPath)
			return c.sendErrorResponse(c.connection.GetErrorForDeniedFile(policy))
		}
		fs, fsPath, err := c.connection.GetFsAndResolvedPath(sshPath)
		if err != nil {
			return c.sendErrorResponse(err)
		}
		if !c.connection.User.HasPerm(dataprovider.PermListItems, sshPath) {
			return c.sendErrorResponse(c.connection.GetPermissionDeniedError())
		}
		hash, err := c.computeHashForFile(fs, h, fsPath)
		if err != nil {
			return c.sendErrorResponse(c.connection.GetFsError(fs, err))
		}
		response = fmt.Sprintf("%v  %v\n", hash, sshPath)
	}
	c.connection.channel.Write([]byte(response)) //nolint:errcheck
	c.sendExitStatus(nil)
	return nil
}

func (c *sshCommand) executeSystemCommand(command systemCommand) error {
	sshDestPath := c.getDestPath()
	if !c.isLocalPath(sshDestPath) {
		return c.sendErrorResponse(errUnsupportedConfig)
	}
	diskQuota, transferQuota := c.connection.HasSpace(true, false, command.quotaCheckPath)
	if !diskQuota.HasSpace || !transferQuota.HasUploadSpace() || !transferQuota.HasDownloadSpace() {
		return c.sendErrorResponse(common.ErrQuotaExceeded)
	}
	perms := []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermCreateDirs, dataprovider.PermListItems,
		dataprovider.PermOverwrite, dataprovider.PermDelete}
	if !c.connection.User.HasPerms(perms, sshDestPath) {
		return c.sendErrorResponse(c.connection.GetPermissionDeniedError())
	}

	initialFiles, initialSize, err := c.getSizeForPath(command.fs, command.fsPath)
	if err != nil {
		return c.sendErrorResponse(err)
	}

	stdin, stdout, stderr, err := command.GetSTDs()
	if err != nil {
		return c.sendErrorResponse(err)
	}
	err = command.cmd.Start()
	if err != nil {
		return c.sendErrorResponse(err)
	}

	closeCmdOnError := func() {
		c.connection.Log(logger.LevelDebug, "kill cmd: %q and close ssh channel after read or write error",
			c.connection.command)
		killerr := command.cmd.Process.Kill()
		closerr := c.connection.channel.Close()
		c.connection.Log(logger.LevelDebug, "kill cmd error: %v close channel error: %v", killerr, closerr)
	}
	var once sync.Once
	commandResponse := make(chan bool)

	remainingQuotaSize := diskQuota.GetRemainingSize()

	go func() {
		defer stdin.Close()
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, command.fsPath, sshDestPath,
			common.TransferUpload, 0, 0, remainingQuotaSize, 0, false, command.fs, transferQuota)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(stdin, c.connection.channel)
		c.connection.Log(logger.LevelDebug, "command: %q, copy from remote command to sdtin ended, written: %v, "+
			"initial remaining quota: %v, err: %v", c.connection.command, w, remainingQuotaSize, e)
		if e != nil {
			once.Do(closeCmdOnError)
		}
	}()

	go func() {
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, command.fsPath, sshDestPath,
			common.TransferDownload, 0, 0, 0, 0, false, command.fs, transferQuota)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(c.connection.channel, stdout)
		c.connection.Log(logger.LevelDebug, "command: %q, copy from sdtout to remote command ended, written: %v err: %v",
			c.connection.command, w, e)
		if e != nil {
			once.Do(closeCmdOnError)
		}
		commandResponse <- true
	}()

	go func() {
		baseTransfer := common.NewBaseTransfer(nil, c.connection.BaseConnection, nil, command.fsPath, command.fsPath, sshDestPath,
			common.TransferDownload, 0, 0, 0, 0, false, command.fs, transferQuota)
		transfer := newTransfer(baseTransfer, nil, nil, nil)

		w, e := transfer.copyFromReaderToWriter(c.connection.channel.(ssh.Channel).Stderr(), stderr)
		c.connection.Log(logger.LevelDebug, "command: %q, copy from sdterr to remote command ended, written: %v err: %v",
			c.connection.command, w, e)
		// os.ErrClosed means that the command is finished so we don't need to do anything
		if (e != nil && !errors.Is(e, os.ErrClosed)) || w > 0 {
			once.Do(closeCmdOnError)
		}
	}()

	<-commandResponse
	err = command.cmd.Wait()
	c.sendExitStatus(err)

	numFiles, dirSize, errSize := c.getSizeForPath(command.fs, command.fsPath)
	if errSize == nil {
		c.updateQuota(sshDestPath, numFiles-initialFiles, dirSize-initialSize)
	}
	c.connection.Log(logger.LevelDebug, "command %q finished for path %q, initial files %v initial size %v "+
		"current files %v current size %v size err: %v", c.connection.command, command.fsPath, initialFiles, initialSize,
		numFiles, dirSize, errSize)
	return c.connection.GetFsError(command.fs, err)
}

func (c *sshCommand) isSystemCommandAllowed() error {
	sshDestPath := c.getDestPath()
	if c.connection.User.IsVirtualFolder(sshDestPath) {
		// overlapped virtual path are not allowed
		return nil
	}
	if c.connection.User.HasVirtualFoldersInside(sshDestPath) {
		c.connection.Log(logger.LevelDebug, "command %q is not allowed, path %q has virtual folders inside it, user %q",
			c.command, sshDestPath, c.connection.User.Username)
		return errUnsupportedConfig
	}
	for _, f := range c.connection.User.Filters.FilePatterns {
		if f.Path == sshDestPath {
			c.connection.Log(logger.LevelDebug,
				"command %q is not allowed inside folders with file patterns filters %q user %q",
				c.command, sshDestPath, c.connection.User.Username)
			return errUnsupportedConfig
		}
		if len(sshDestPath) > len(f.Path) {
			if strings.HasPrefix(sshDestPath, f.Path+"/") || f.Path == "/" {
				c.connection.Log(logger.LevelDebug,
					"command %q is not allowed it includes folders with file patterns filters %q user %q",
					c.command, sshDestPath, c.connection.User.Username)
				return errUnsupportedConfig
			}
		}
		if len(sshDestPath) < len(f.Path) {
			if strings.HasPrefix(sshDestPath+"/", f.Path) || sshDestPath == "/" {
				c.connection.Log(logger.LevelDebug,
					"command %q is not allowed inside folder with file patterns filters %q user %q",
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
		fs:             nil,
		fsPath:         "",
		quotaCheckPath: "",
	}
	if err := common.CheckClosing(); err != nil {
		return command, err
	}
	args := make([]string, len(c.args))
	copy(args, c.args)
	var fsPath, quotaPath string
	sshPath := c.getDestPath()
	fs, err := c.connection.User.GetFilesystemForPath(sshPath, c.connection.ID)
	if err != nil {
		return command, err
	}
	if len(c.args) > 0 {
		var err error
		fsPath, err = fs.ResolvePath(sshPath)
		if err != nil {
			return command, c.connection.GetFsError(fs, err)
		}
		quotaPath = sshPath
		fi, err := fs.Stat(fsPath)
		if err == nil && fi.IsDir() {
			// if the target is an existing dir the command will write inside this dir
			// so we need to check the quota for this directory and not its parent dir
			quotaPath = path.Join(sshPath, "fakecontent")
		}
		if strings.HasSuffix(sshPath, "/") && !strings.HasSuffix(fsPath, string(os.PathSeparator)) {
			fsPath += string(os.PathSeparator)
			c.connection.Log(logger.LevelDebug, "path separator added to fsPath %q", fsPath)
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
			if !util.Contains(args, "--safe-links") {
				args = append([]string{"--safe-links"}, args...)
			}
		} else {
			if !util.Contains(args, "--munge-links") {
				args = append([]string{"--munge-links"}, args...)
			}
		}
	}
	c.connection.Log(logger.LevelDebug, "new system command %q, with args: %+v fs path %q quota check path %q",
		c.command, args, fsPath, quotaPath)
	cmd := exec.Command(c.command, args...)
	uid := c.connection.User.GetUID()
	gid := c.connection.User.GetGID()
	cmd = wrapCmd(cmd, uid, gid)
	command.cmd = cmd
	command.fsPath = fsPath
	command.quotaCheckPath = quotaPath
	command.fs = fs
	return command, nil
}

// for the supported commands, the destination path, if any, is the last argument
func (c *sshCommand) getDestPath() string {
	if len(c.args) == 0 {
		return ""
	}
	return c.cleanCommandPath(c.args[len(c.args)-1])
}

// for the supported commands, the destination path, if any, is the second-last argument
func (c *sshCommand) getSourcePath() string {
	if len(c.args) < 2 {
		return ""
	}
	return c.cleanCommandPath(c.args[len(c.args)-2])
}

func (c *sshCommand) cleanCommandPath(name string) string {
	name = strings.Trim(name, "'")
	name = strings.Trim(name, "\"")
	result := c.connection.User.GetCleanedPath(name)
	if strings.HasSuffix(name, "/") && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func (c *sshCommand) getRemovePath() (string, error) {
	sshDestPath := c.getDestPath()
	if sshDestPath == "" || len(c.args) != 1 {
		err := errors.New("usage sftpgo-remove <destination path>")
		return "", err
	}
	if len(sshDestPath) > 1 {
		sshDestPath = strings.TrimSuffix(sshDestPath, "/")
	}
	return sshDestPath, nil
}

func (c *sshCommand) isLocalPath(virtualPath string) bool {
	folder, err := c.connection.User.GetVirtualFolderForPath(virtualPath)
	if err != nil {
		return c.connection.User.FsConfig.Provider == sdk.LocalFilesystemProvider
	}
	return folder.FsConfig.Provider == sdk.LocalFilesystemProvider
}

func (c *sshCommand) getSizeForPath(fs vfs.Fs, name string) (int, int64, error) {
	if dataprovider.GetQuotaTracking() > 0 {
		fi, err := fs.Lstat(name)
		if err != nil {
			if fs.IsNotExist(err) {
				return 0, 0, nil
			}
			c.connection.Log(logger.LevelDebug, "unable to stat %q error: %v", name, err)
			return 0, 0, err
		}
		if fi.IsDir() {
			files, size, err := fs.GetDirSize(name)
			if err != nil {
				c.connection.Log(logger.LevelDebug, "unable to get size for dir %q error: %v", name, err)
			}
			return files, size, err
		} else if fi.Mode().IsRegular() {
			return 1, fi.Size(), nil
		}
	}
	return 0, 0, nil
}

func (c *sshCommand) sendErrorResponse(err error) error {
	errorString := fmt.Sprintf("%v: %v %v\n", c.command, c.getDestPath(), err)
	c.connection.channel.Write([]byte(errorString)) //nolint:errcheck
	c.sendExitStatus(err)
	return err
}

func (c *sshCommand) sendExitStatus(err error) {
	status := uint32(0)
	vCmdPath := c.getDestPath()
	cmdPath := ""
	targetPath := ""
	vTargetPath := ""
	if c.command == "sftpgo-copy" {
		vTargetPath = vCmdPath
		vCmdPath = c.getSourcePath()
	}
	if err != nil {
		status = uint32(1)
		c.connection.Log(logger.LevelError, "command failed: %q args: %v user: %s err: %v",
			c.command, c.args, c.connection.User.Username, err)
	}
	exitStatus := sshSubsystemExitStatus{
		Status: status,
	}
	_, errClose := c.connection.channel.(ssh.Channel).SendRequest("exit-status", false, ssh.Marshal(&exitStatus))
	c.connection.Log(logger.LevelDebug, "exit status sent, error: %v", errClose)
	c.connection.channel.Close()
	// for scp we notify single uploads/downloads
	if c.command != scpCmdName {
		elapsed := time.Since(c.startTime).Nanoseconds() / 1000000
		metric.SSHCommandCompleted(err)
		if vCmdPath != "" {
			_, p, errFs := c.connection.GetFsAndResolvedPath(vCmdPath)
			if errFs == nil {
				cmdPath = p
			}
		}
		if vTargetPath != "" {
			_, p, errFs := c.connection.GetFsAndResolvedPath(vTargetPath)
			if errFs == nil {
				targetPath = p
			}
		}
		common.ExecuteActionNotification(c.connection.BaseConnection, common.OperationSSHCmd, cmdPath, vCmdPath, //nolint:errcheck
			targetPath, vTargetPath, c.command, 0, err, elapsed, nil)
		if err == nil {
			logger.CommandLog(sshCommandLogSender, cmdPath, targetPath, c.connection.User.Username, "", c.connection.ID,
				common.ProtocolSSH, -1, -1, "", "", c.connection.command, -1, c.connection.GetLocalAddress(),
				c.connection.GetRemoteAddress(), elapsed)
		}
	}
}

func (c *sshCommand) computeHashForFile(fs vfs.Fs, hasher hash.Hash, path string) (string, error) {
	hash := ""
	f, r, _, err := fs.Open(path, 0)
	if err != nil {
		return hash, err
	}
	var reader io.ReadCloser
	if f != nil {
		reader = f
	} else {
		reader = r
	}
	defer reader.Close()
	_, err = io.Copy(hasher, reader)
	if err == nil {
		hash = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	return hash, err
}

func parseCommandPayload(command string) (string, []string, error) {
	parts, err := shlex.Split(command)
	if err == nil && len(parts) == 0 {
		err = fmt.Errorf("invalid command: %q", command)
	}
	if err != nil {
		return "", []string{}, err
	}
	if len(parts) < 2 {
		return parts[0], []string{}, nil
	}
	return parts[0], parts[1:], nil
}
