package kms

const (
	awsProviderName = "AWS"
)

type awsSecret struct {
	baseGCloudSecret
}

func newAWSSecret(base baseSecret, url, masterKey string) SecretProvider {
	return &awsSecret{
		baseGCloudSecret{
			baseSecret: base,
			url:        url,
			masterKey:  masterKey,
		},
	}
}

func (s *awsSecret) Name() string {
	return awsProviderName
}

func (s *awsSecret) IsEncrypted() bool {
	return s.Status == SecretStatusAWS
}

func (s *awsSecret) Encrypt() error {
	if err := s.baseGCloudSecret.Encrypt(); err != nil {
		return err
	}
	s.Status = SecretStatusAWS
	return nil
}

func (s *awsSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return errWrongSecretStatus
	}
	return s.baseGCloudSecret.Decrypt()
}
