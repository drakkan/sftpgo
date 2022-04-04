//go:build !windows
// +build !windows

package sftpd

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrapCmd(t *testing.T) {
	cmd := exec.Command("ls")
	cmd = wrapCmd(cmd, 1000, 1001)
	assert.Equal(t, uint32(1000), cmd.SysProcAttr.Credential.Uid)
	assert.Equal(t, uint32(1001), cmd.SysProcAttr.Credential.Gid)
}
