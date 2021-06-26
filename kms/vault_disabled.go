// +build novaultkms

package kms

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-vaultkms")
}

func newVaultSecret(base baseSecret, url, masterKey string) SecretProvider {
	return newDisabledSecret(errors.New("Vault KMS disabled at build time"))
}
