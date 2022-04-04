//go:build !darwin && !linux && !freebsd
// +build !darwin,!linux,!freebsd

package vfs

import (
	"github.com/pkg/sftp"
	"github.com/shirou/gopsutil/v3/disk"
)

const bsize = uint64(4096)

func getStatFS(path string) (*sftp.StatVFS, error) {
	usage, err := disk.Usage(path)
	if err != nil {
		return nil, err
	}
	// we assume block size = 4096
	blocks := usage.Total / bsize
	bfree := usage.Free / bsize
	files := usage.InodesTotal
	ffree := usage.InodesFree
	if files == 0 {
		// these assumptions are wrong but still better than returning 0
		files = blocks / 4
		ffree = bfree / 4
	}
	return &sftp.StatVFS{
		Bsize:   bsize,
		Frsize:  bsize,
		Blocks:  blocks,
		Bfree:   bfree,
		Bavail:  bfree,
		Files:   files,
		Ffree:   ffree,
		Favail:  ffree,
		Namemax: 255,
	}, nil
}
