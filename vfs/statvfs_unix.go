//go:build freebsd || darwin
// +build freebsd darwin

package vfs

import (
	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

func getStatFS(path string) (*sftp.StatVFS, error) {
	stat := unix.Statfs_t{}
	err := unix.Statfs(path, &stat)
	if err != nil {
		return nil, err
	}
	return &sftp.StatVFS{
		Bsize:   uint64(stat.Bsize),
		Frsize:  uint64(stat.Bsize),
		Blocks:  stat.Blocks,
		Bfree:   stat.Bfree,
		Bavail:  uint64(stat.Bavail),
		Files:   stat.Files,
		Ffree:   uint64(stat.Ffree),
		Favail:  uint64(stat.Ffree), // not sure how to calculate Favail
		Flag:    uint64(stat.Flags),
		Namemax: 255, // we use a conservative value here
	}, nil
}
