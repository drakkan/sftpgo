// Package utils provides some common utility methods
package utils

import (
	"fmt"
	"net"
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

// GetTimeFromMsecSinceEpoch return a time struct from a unix timestamp with millisecond precision
func GetTimeFromMsecSinceEpoch(msec int64) time.Time {
	return time.Unix(0, msec*1000000)
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

// GetDurationAsString returns a string representation for a time.Duration
func GetDurationAsString(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// ByteCountSI returns humanized size in SI (decimal) format
func ByteCountSI(b int64) string {
	return byteCount(b, 1000)
}

// ByteCountIEC returns humanized size in IEC (binary) format
func ByteCountIEC(b int64) string {
	return byteCount(b, 1024)
}

func byteCount(b int64, unit int64) string {
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	if unit == 1000 {
		return fmt.Sprintf("%.1f %cB",
			float64(b)/float64(div), "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

// GetIPFromRemoteAddress returns the IP from the remote address.
// If the given remote address cannot be parsed it will be returned unchanged
func GetIPFromRemoteAddress(remoteAddress string) string {
	ip, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return ip
	}
	return remoteAddress
}
