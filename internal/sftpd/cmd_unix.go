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
// +build !windows

package sftpd

import (
	"os"
	"os/exec"
	"syscall"
)

var (
	processUID = os.Geteuid()
	processGID = os.Getegid()
)

func wrapCmd(cmd *exec.Cmd, uid, gid int) *exec.Cmd {
	isCurrentUser := processUID == uid && processGID == gid
	if (uid > 0 || gid > 0) && !isCurrentUser {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	return cmd
}
