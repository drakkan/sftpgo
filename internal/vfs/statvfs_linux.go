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

//go:build linux

package vfs

import (
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

func getStatFS(f *os.File, _ string) (*sftp.StatVFS, error) {
	stat := unix.Statfs_t{}
	err := unix.Fstatfs(int(f.Fd()), &stat)
	if err != nil {
		return nil, err
	}
	return &sftp.StatVFS{
		Bsize:   uint64(stat.Bsize),
		Frsize:  uint64(stat.Frsize),
		Blocks:  stat.Blocks,
		Bfree:   stat.Bfree,
		Bavail:  stat.Bavail,
		Files:   stat.Files,
		Ffree:   stat.Ffree,
		Favail:  stat.Ffree, // not sure how to calculate Favail
		Flag:    uint64(stat.Flags),
		Namemax: uint64(stat.Namelen),
	}, nil
}
