//go:build nos3
// +build nos3

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-s3")
}

// NewS3Fs returns an error, S3 is disabled
func NewS3Fs(connectionID, localTempDir, mountPath string, config S3FsConfig) (Fs, error) {
	return nil, errors.New("S3 disabled at build time")
}
