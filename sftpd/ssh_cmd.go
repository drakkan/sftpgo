package sftpd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"golang.org/x/crypto/ssh"
)

type sshCommand struct {
	command    string
	args       []string
	connection Connection
}

func processSSHCommand(payload []byte, connection *Connection, channel ssh.Channel, enabledSSHCommands []string) bool {
	var msg sshSubsystemExecMsg
	if err := ssh.Unmarshal(payload, &msg); err == nil {
		name, args, err := parseCommandPayload(msg.Command)
		connection.Log(logger.LevelDebug, logSenderSSH, "new ssh command: %#v args: %v user: %v, error: %v",
			name, args, connection.User.Username, err)
		if err == nil && utils.IsStringInSlice(name, enabledSSHCommands) {
			connection.command = fmt.Sprintf("%v %v", name, strings.Join(args, " "))
			if name == "scp" && len(args) >= 2 {
				connection.protocol = protocolSCP
				connection.channel = channel
				scpCommand := scpCommand{
					sshCommand: sshCommand{
						command:    name,
						connection: *connection,
						args:       args},
				}
				go scpCommand.handle()
				return true
			}
			if name != "scp" {
				connection.protocol = protocolSSH
				connection.channel = channel
				sshCommand := sshCommand{
					command:    name,
					connection: *connection,
					args:       args,
				}
				go sshCommand.handle()
				return true
			}
		} else {
			connection.Log(logger.LevelInfo, logSenderSSH, "ssh command not enabled/supported: %#v", name)
		}
	}
	return false
}

func (c *sshCommand) handle() error {
	addConnection(c.connection)
	defer removeConnection(c.connection)
	updateConnectionActivity(c.connection.ID)
	if utils.IsStringInSlice(c.command, sshHashCommands) {
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
			h.Write(buf[:n])
			response = fmt.Sprintf("%x  -\n", h.Sum(nil))
		} else {
			sshPath := c.getDestPath()
			path, err := c.connection.buildPath(sshPath)
			if err != nil {
				return c.sendErrorResponse(err)
			}
			hash, err := computeHashForFile(h, path)
			if err != nil {
				return c.sendErrorResponse(err)
			}
			response = fmt.Sprintf("%v  %v\n", hash, sshPath)
		}
		c.connection.channel.Write([]byte(response))
		c.sendExitStatus(nil)
	} else if c.command == "cd" {
		c.sendExitStatus(nil)
	} else if c.command == "pwd" {
		// hard coded response to "/"
		c.connection.channel.Write([]byte("/\n"))
		c.sendExitStatus(nil)
	}
	return nil
}

// for the supported command, the path, if any, is the last argument
func (c *sshCommand) getDestPath() string {
	if len(c.args) == 0 {
		return ""
	}
	destPath := filepath.ToSlash(c.args[len(c.args)-1])
	if !path.IsAbs(destPath) {
		destPath = "/" + destPath
	}
	result := path.Clean(destPath)
	if strings.HasSuffix(destPath, "/") && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func (c *sshCommand) sendErrorResponse(err error) error {
	errorString := fmt.Sprintf("%v: %v %v\n", c.command, c.getDestPath(), err)
	c.connection.channel.Write([]byte(errorString))
	c.sendExitStatus(err)
	return err
}

func (c *sshCommand) sendExitStatus(err error) {
	status := uint32(0)
	if err != nil {
		status = uint32(1)
	}
	exitStatus := sshSubsystemExitStatus{
		Status: status,
	}
	c.connection.Log(logger.LevelDebug, logSenderSSH, "send exit status for command %#v with args: %v user: %v err: %v",
		c.command, c.args, c.connection.User.Username, err)
	c.connection.channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatus))
	c.connection.channel.Close()
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
	parts := strings.Split(command, " ")
	if len(parts) < 2 {
		return parts[0], []string{}, nil
	}
	return parts[0], parts[1:], nil
}
