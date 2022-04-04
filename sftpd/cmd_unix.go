//go:build !windows
// +build !windows

package sftpd

import (
	"os/exec"
	"syscall"
)

func wrapCmd(cmd *exec.Cmd, uid, gid int) *exec.Cmd {
	if uid > 0 || gid > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	return cmd
}
