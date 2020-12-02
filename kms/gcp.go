// +build !nogcpkms

package kms

import (
	// we import gcpkms here to be able to disable GCP KMS support using a build tag
	_ "gocloud.dev/secrets/gcpkms"

	"github.com/drakkan/sftpgo/version"
)

type gcpSecret struct {
	baseGCloudSecret
}

func init() {
	version.AddFeature("+gcpkms")
}

func newGCPSecret(base baseSecret, url, masterKey string) SecretProvider {
	return &gcpSecret{
		baseGCloudSecret{
			baseSecret: base,
			url:        url,
			masterKey:  masterKey,
		},
	}
}

func (s *gcpSecret) Name() string {
	return gcpProviderName
}

func (s *gcpSecret) IsEncrypted() bool {
	return s.Status == SecretStatusGCP
}

func (s *gcpSecret) Encrypt() error {
	if err := s.baseGCloudSecret.Encrypt(); err != nil {
		return err
	}
	s.Status = SecretStatusGCP
	return nil
}

func (s *gcpSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return errWrongSecretStatus
	}
	return s.baseGCloudSecret.Decrypt()
}
