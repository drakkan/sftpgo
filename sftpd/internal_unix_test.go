// +build !windows

package sftpd

import (
	"os/exec"
	"testing"
)

func TestWrapCmd(t *testing.T) {
	cmd := exec.Command("ls")
	cmd = wrapCmd(cmd, 1000, 1001)
	if cmd.SysProcAttr.Credential.Uid != 1000 {
		t.Errorf("unexpected uid")
	}
	if cmd.SysProcAttr.Credential.Gid != 1001 {
		t.Errorf("unexpected gid")
	}
}
