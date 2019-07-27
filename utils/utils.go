package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/drakkan/sftpgo/logger"
)

const logSender = "utils"

// IsStringInSlice search a string in a slice
func IsStringInSlice(obj string, list []string) bool {
	for _, v := range list {
		if v == obj {
			return true
		}
	}
	return false
}

// GetTimeAsMsSinceEpoch returns unix timestamp as milliseconds from a time struct
func GetTimeAsMsSinceEpoch(t time.Time) int64 {
	return t.UnixNano() / 1000000
}

// ScanDirContents returns the number of files contained in a directory and their size
func ScanDirContents(path string) (int, int64, []string, error) {
	var numFiles int
	var size int64
	var fileList []string
	var err error
	numFiles = 0
	size = 0
	isDir, err := isDirectory(path)
	if err == nil && isDir {
		err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
				fileList = append(fileList, path)
			}
			return err
		})
	}

	return numFiles, size, fileList, err
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

// SetPathPermissions call os.Chown on unix does nothing on windows
func SetPathPermissions(path string, uid int, gid int) {
	if runtime.GOOS != "windows" {
		if err := os.Chown(path, uid, gid); err != nil {
			logger.Warn(logSender, "error chowning path %v: %v", path, err)
		}
	}
}
