//go:build noazblob
// +build noazblob

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-azblob")
}

// NewAzBlobFs returns an error, Azure Blob storage is disabled
func NewAzBlobFs(connectionID, localTempDir string, config AzBlobFsConfig) (Fs, error) {
	return nil, errors.New("Azure Blob Storage disabled at build time")
}
