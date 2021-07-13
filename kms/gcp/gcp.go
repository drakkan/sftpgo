// +build !nogcpkms

package gcp

import (
	// we import gcpkms here to be able to disable GCP KMS support using a build tag
	_ "gocloud.dev/secrets/gcpkms"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/kms/gocloud"
	"github.com/drakkan/sftpgo/v2/version"
)

const encryptedStatus = kms.SecretStatusGCP

type gcpSecret struct {
	gocloud.Secret
}

func init() {
	version.AddFeature("+gcpkms")
	kms.RegisterSecretProvider(kms.SchemeGCP, encryptedStatus, newGCPSecret)
}

func newGCPSecret(base kms.BaseSecret, url, masterKey string) kms.SecretProvider {
	return &gcpSecret{
		gocloud.Secret{
			BaseSecret: base,
			URL:        url,
			MasterKey:  masterKey,
		},
	}
}

func (s *gcpSecret) Name() string {
	return "GCP"
}

func (s *gcpSecret) IsEncrypted() bool {
	return s.Status == encryptedStatus
}

func (s *gcpSecret) Encrypt() error {
	if err := s.Secret.Encrypt(); err != nil {
		return err
	}
	s.Status = encryptedStatus
	return nil
}

func (s *gcpSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return kms.ErrWrongSecretStatus
	}
	return s.Secret.Decrypt()
}

func (s *gcpSecret) Clone() kms.SecretProvider {
	baseSecret := kms.BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return newGCPSecret(baseSecret, s.URL, s.MasterKey)
}
