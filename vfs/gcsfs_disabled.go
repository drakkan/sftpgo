// +build nogcs

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-gcs")
}

// NewGCSFs returns an error, GCS is disabled
func NewGCSFs(connectionID, localTempDir, mountPath string, config GCSFsConfig) (Fs, error) {
	return nil, errors.New("Google Cloud Storage disabled at build time")
}
