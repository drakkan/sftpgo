// +build !novaultkms

package vault

import (
	// we import hashivault here to be able to disable Vault support using a build tag
	_ "gocloud.dev/secrets/hashivault"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/kms/gocloud"
	"github.com/drakkan/sftpgo/v2/version"
)

const encryptedStatus = kms.SecretStatusVaultTransit

type vaultSecret struct {
	gocloud.Secret
}

func init() {
	version.AddFeature("+vaultkms")
	kms.RegisterSecretProvider(kms.SchemeVaultTransit, encryptedStatus, newVaultSecret)
}

func newVaultSecret(base kms.BaseSecret, url, masterKey string) kms.SecretProvider {
	return &vaultSecret{
		gocloud.Secret{
			BaseSecret: base,
			URL:        url,
			MasterKey:  masterKey,
		},
	}
}

func (s *vaultSecret) Name() string {
	return "VaultTransit"
}

func (s *vaultSecret) IsEncrypted() bool {
	return s.Status == encryptedStatus
}

func (s *vaultSecret) Encrypt() error {
	if err := s.Secret.Encrypt(); err != nil {
		return err
	}
	s.Status = encryptedStatus
	return nil
}

func (s *vaultSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return kms.ErrWrongSecretStatus
	}
	return s.Secret.Decrypt()
}

func (s *vaultSecret) Clone() kms.SecretProvider {
	baseSecret := kms.BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return newVaultSecret(baseSecret, s.URL, s.MasterKey)
}
