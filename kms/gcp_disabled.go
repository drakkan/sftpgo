// +build nogcpkms

package kms

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-gcpkms")
}

func newGCPSecret(base baseSecret, url, masterKey string) SecretProvider {
	return newDisabledSecret(errors.New("GCP KMS disabled at build time"))
}
