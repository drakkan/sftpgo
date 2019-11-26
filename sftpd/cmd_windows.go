package sftpd

import (
	"os/exec"
)

func wrapCmd(cmd *exec.Cmd, uid, gid int) *exec.Cmd {
	return cmd
}
