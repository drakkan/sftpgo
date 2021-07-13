// +build !noawskms

package aws

import (
	// we import awskms here to be able to disable AWS KMS support using a build tag
	_ "gocloud.dev/secrets/awskms"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/kms/gocloud"
	"github.com/drakkan/sftpgo/v2/version"
)

const encryptedStatus = kms.SecretStatusAWS

type awsSecret struct {
	gocloud.Secret
}

func init() {
	version.AddFeature("+awskms")
	kms.RegisterSecretProvider(kms.SchemeAWS, encryptedStatus, newAWSSecret)
}

func newAWSSecret(base kms.BaseSecret, url, masterKey string) kms.SecretProvider {
	return &awsSecret{
		gocloud.Secret{
			BaseSecret: base,
			URL:        url,
			MasterKey:  masterKey,
		},
	}
}

func (s *awsSecret) Name() string {
	return "AWS"
}

func (s *awsSecret) IsEncrypted() bool {
	return s.Status == encryptedStatus
}

func (s *awsSecret) Encrypt() error {
	if err := s.Secret.Encrypt(); err != nil {
		return err
	}
	s.Status = encryptedStatus
	return nil
}

func (s *awsSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return kms.ErrWrongSecretStatus
	}
	return s.Secret.Decrypt()
}

func (s *awsSecret) Clone() kms.SecretProvider {
	baseSecret := kms.BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return newAWSSecret(baseSecret, s.URL, s.MasterKey)
}
