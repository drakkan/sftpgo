// Package sftpd implements the SSH File Transfer Protocol as described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02.
// It uses pkg/sftp library:
// https://github.com/pkg/sftp
package sftpd

import (
	"time"
)

const (
	logSender        = "sftpd"
	handshakeTimeout = 2 * time.Minute
)

var (
	supportedSSHCommands = []string{"scp", "md5sum", "sha1sum", "sha256sum", "sha384sum", "sha512sum", "cd", "pwd",
		"git-receive-pack", "git-upload-pack", "git-upload-archive", "rsync", "sftpgo-copy", "sftpgo-remove"}
	defaultSSHCommands = []string{"md5sum", "sha1sum", "cd", "pwd", "scp"}
	sshHashCommands    = []string{"md5sum", "sha1sum", "sha256sum", "sha384sum", "sha512sum"}
	systemCommands     = []string{"git-receive-pack", "git-upload-pack", "git-upload-archive", "rsync"}
)

type sshSubsystemExitStatus struct {
	Status uint32
}

type sshSubsystemExecMsg struct {
	Command string
}

// GetDefaultSSHCommands returns the SSH commands enabled as default
func GetDefaultSSHCommands() []string {
	result := make([]string, len(defaultSSHCommands))
	copy(result, defaultSSHCommands)
	return result
}

// GetSupportedSSHCommands returns the supported SSH commands
func GetSupportedSSHCommands() []string {
	result := make([]string, len(supportedSSHCommands))
	copy(result, supportedSSHCommands)
	return result
}
