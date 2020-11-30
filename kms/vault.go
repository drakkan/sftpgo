package kms

const (
	vaultProviderName = "VaultTransit"
)

type vaultSecret struct {
	baseGCloudSecret
}

func newVaultSecret(base baseSecret, url, masterKey string) SecretProvider {
	return &vaultSecret{
		baseGCloudSecret{
			baseSecret: base,
			url:        url,
			masterKey:  masterKey,
		},
	}
}

func (s *vaultSecret) Name() string {
	return vaultProviderName
}

func (s *vaultSecret) IsEncrypted() bool {
	return s.Status == SecretStatusVaultTransit
}

func (s *vaultSecret) Encrypt() error {
	if err := s.baseGCloudSecret.Encrypt(); err != nil {
		return err
	}
	s.Status = SecretStatusVaultTransit
	return nil
}

func (s *vaultSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return errWrongSecretStatus
	}
	return s.baseGCloudSecret.Decrypt()
}
