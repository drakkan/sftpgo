// +build nogcpkms

package gcp

import (
	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-gcpkms")
}
