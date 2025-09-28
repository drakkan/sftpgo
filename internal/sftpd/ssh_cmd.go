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
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/google/shlex"
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

type sshCommand struct {
	command    string
	args       []string
	connection *Connection
	startTime  time.Time
}

func processSSHCommand(payload []byte, connection *Connection, enabledSSHCommands []string) bool {
	var msg sshSubsystemExecMsg
	if err := ssh.Unmarshal(payload, &msg); err == nil {
		name, args, err := parseCommandPayload(msg.Command)
		connection.Log(logger.LevelDebug, "new ssh command: %q args: %v num args: %d user: %s, error: %v",
			name, args, len(args), connection.User.Username, err)
		if err == nil && slices.Contains(enabledSSHCommands, name) {
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
		defer c.connection.CloseFS() //nolint:errcheck
		logger.Info(logSender, "", "unable to add SSH command connection: %v", err)
		return c.sendErrorResponse(err)
	}
	defer common.Connections.Remove(c.connection.GetID())

	c.connection.UpdateLastActivity()
	if slices.Contains(sshHashCommands, c.command) {
		return c.handleHashCommands()
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

func (c *sshCommand) handleHashCommands() error {
	var h hash.Hash
	switch c.command {
	case "md5sum":
		h = md5.New()
	case "sha1sum":
		h = sha1.New()
	case "sha256sum":
		h = sha256.New()
	case "sha384sum":
		h = sha512.New384()
	default:
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
