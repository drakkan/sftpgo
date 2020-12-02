// +build noawskms

package kms

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-awskms")
}

func newAWSSecret(base baseSecret, url, masterKey string) SecretProvider {
	return newDisabledSecret(errors.New("AWS KMS disabled at build time"))
}
