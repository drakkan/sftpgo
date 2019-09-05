// Package utils provides some common utility methods
package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/logger"
)

const logSender = "utils"

// IsStringInSlice searches a string in a slice and returns true if the string is found
func IsStringInSlice(obj string, list []string) bool {
	for _, v := range list {
		if v == obj {
			return true
		}
	}
	return false
}

// IsStringPrefixInSlice searches a string prefix in a slice and returns true
// if a matching prefix is found
func IsStringPrefixInSlice(obj string, list []string) bool {
	for _, v := range list {
		if strings.HasPrefix(obj, v) {
			return true
		}
	}
	return false
}

// GetTimeAsMsSinceEpoch returns unix timestamp as milliseconds from a time struct
func GetTimeAsMsSinceEpoch(t time.Time) int64 {
	return t.UnixNano() / 1000000
}

// ScanDirContents returns the number of files contained in a directory, their size and a slice with the file paths
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

// SetPathPermissions call os.Chown on unix, it does nothing on windows
func SetPathPermissions(path string, uid int, gid int) {
	if runtime.GOOS != "windows" {
		if err := os.Chown(path, uid, gid); err != nil {
			logger.Warn(logSender, "", "error chowning path %v: %v", path, err)
		}
	}
}

// GetAppVersion returns VersionInfo struct
func GetAppVersion() VersionInfo {
	return versionInfo
}
