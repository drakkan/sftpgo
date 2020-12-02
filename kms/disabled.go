// +build noawskms nogcpkms novaultkms

package kms

const disabledProviderName = "Disabled"

type disabledSecret struct {
	baseSecret
	err error
}

func newDisabledSecret(err error) SecretProvider {
	return &disabledSecret{
		baseSecret: baseSecret{},
		err:        err,
	}
}

func (s *disabledSecret) Name() string {
	return disabledProviderName
}

func (s *disabledSecret) IsEncrypted() bool {
	return false
}

func (s *disabledSecret) Encrypt() error {
	return s.err
}

func (s *disabledSecret) Decrypt() error {
	return s.err
}
