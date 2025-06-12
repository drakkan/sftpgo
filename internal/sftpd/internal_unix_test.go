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

//go:build !windows

package sftpd

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrapCmd(t *testing.T) {
	cmd := exec.Command("ls")
	cmd = wrapCmd(cmd, 3001, 3002)
	assert.Equal(t, uint32(3001), cmd.SysProcAttr.Credential.Uid)
	assert.Equal(t, uint32(3002), cmd.SysProcAttr.Credential.Gid)

	cmd = exec.Command("cd")
	cmd = wrapCmd(cmd, processUID, processGID)
	assert.Nil(t, cmd.SysProcAttr)
}
