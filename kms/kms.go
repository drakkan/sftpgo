// Package kms provides Key Management Services support
package kms

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/utils"
)

// SecretProvider defines the interface for a KMS secrets provider
type SecretProvider interface {
	Name() string
	Encrypt() error
	Decrypt() error
	IsEncrypted() bool
	GetStatus() SecretStatus
	GetPayload() string
	GetKey() string
	GetAdditionalData() string
	GetMode() int
	SetKey(string)
	SetAdditionalData(string)
	SetStatus(SecretStatus)
}

// SecretStatus defines the statuses of a Secret object
type SecretStatus = string

const (
	// SecretStatusPlain means the secret is in plain text and must be encrypted
	SecretStatusPlain SecretStatus = "Plain"
	// SecretStatusAES256GCM means the secret is encrypted using AES-256-GCM
	SecretStatusAES256GCM SecretStatus = "AES-256-GCM"
	// SecretStatusSecretBox means the secret is encrypted using a locally provided symmetric key
	SecretStatusSecretBox SecretStatus = "Secretbox"
	// SecretStatusGCP means we use keys from Google Cloud Platform’s Key Management Service
	// (GCP KMS) to keep information secret
	SecretStatusGCP SecretStatus = "GCP"
	// SecretStatusAWS means we use customer master keys from Amazon Web Service’s
	// Key Management Service (AWS KMS) to keep information secret
	SecretStatusAWS SecretStatus = "AWS"
	// SecretStatusVaultTransit means we use the transit secrets engine in Vault
	// to keep information secret
	SecretStatusVaultTransit SecretStatus = "VaultTransit"
	// SecretStatusRedacted means the secret is redacted
	SecretStatusRedacted SecretStatus = "Redacted"
)

const (
	localProviderName   = "Local"
	builtinProviderName = "Builtin"
	awsProviderName     = "AWS"
	gcpProviderName     = "GCP"
	vaultProviderName   = "VaultTransit"
)

// Configuration defines the KMS configuration
type Configuration struct {
	Secrets Secrets `json:"secrets" mapstructure:"secrets"`
}

// Secrets define the KMS configuration for encryption/decryption
type Secrets struct {
	URL           string `json:"url" mapstructure:"url"`
	MasterKeyPath string `json:"master_key_path" mapstructure:"master_key_path"`
	masterKey     string
}

var (
	errWrongSecretStatus   = errors.New("wrong secret status")
	errMalformedCiphertext = errors.New("malformed ciphertext")
	errInvalidSecret       = errors.New("invalid secret")
	validSecretStatuses    = []string{SecretStatusPlain, SecretStatusAES256GCM, SecretStatusSecretBox,
		SecretStatusVaultTransit, SecretStatusAWS, SecretStatusGCP, SecretStatusRedacted}
	config         Configuration
	defaultTimeout = 10 * time.Second
)

// NewSecret builds a new Secret using the provided arguments
func NewSecret(status SecretStatus, payload, key, data string) *Secret {
	return config.newSecret(status, payload, key, data)
}

// NewEmptySecret returns an empty secret
func NewEmptySecret() *Secret {
	return NewSecret("", "", "", "")
}

// NewPlainSecret stores the give payload in a plain text secret
func NewPlainSecret(payload string) *Secret {
	return NewSecret(SecretStatusPlain, payload, "", "")
}

// GetSecretFromCompatString returns a secret from the previous format
func GetSecretFromCompatString(secret string) (*Secret, error) {
	plain, err := utils.DecryptData(secret)
	if err != nil {
		return &Secret{}, errMalformedCiphertext
	}
	return NewSecret(SecretStatusPlain, plain, "", ""), nil
}

// Initialize configures the KMS support
func (c *Configuration) Initialize() error {
	if c.Secrets.MasterKeyPath != "" {
		mKey, err := ioutil.ReadFile(c.Secrets.MasterKeyPath)
		if err != nil {
			return err
		}
		c.Secrets.masterKey = strings.TrimSpace(string(mKey))
	}
	config = *c
	return nil
}

func (c *Configuration) newSecret(status SecretStatus, payload, key, data string) *Secret {
	base := baseSecret{
		Status:         status,
		Key:            key,
		Payload:        payload,
		AdditionalData: data,
	}
	return &Secret{
		provider: c.getSecretProvider(base),
	}
}

func (c *Configuration) getSecretProvider(base baseSecret) SecretProvider {
	if strings.HasPrefix(c.Secrets.URL, "hashivault://") {
		return newVaultSecret(base, c.Secrets.URL, c.Secrets.masterKey)
	}
	if strings.HasPrefix(c.Secrets.URL, "awskms://") {
		return newAWSSecret(base, c.Secrets.URL, c.Secrets.masterKey)
	}
	if strings.HasPrefix(c.Secrets.URL, "gcpkms://") {
		return newGCPSecret(base, c.Secrets.URL, c.Secrets.masterKey)
	}
	return newLocalSecret(base, c.Secrets.masterKey)
}

// Secret defines the struct used to store confidential data
type Secret struct {
	provider SecretProvider
}

// MarshalJSON return the JSON encoding of the Secret object
func (s *Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(&baseSecret{
		Status:         s.provider.GetStatus(),
		Payload:        s.provider.GetPayload(),
		Key:            s.provider.GetKey(),
		AdditionalData: s.provider.GetAdditionalData(),
		Mode:           s.provider.GetMode(),
	})
}

// UnmarshalJSON parses the JSON-encoded data and stores the result
// in the Secret object
func (s *Secret) UnmarshalJSON(data []byte) error {
	baseSecret := baseSecret{}
	err := json.Unmarshal(data, &baseSecret)
	if err != nil {
		return err
	}
	if baseSecret.isEmpty() {
		s.provider = config.getSecretProvider(baseSecret)
		return nil
	}
	switch baseSecret.Status {
	case SecretStatusAES256GCM:
		s.provider = newBuiltinSecret(baseSecret)
	case SecretStatusSecretBox:
		s.provider = newLocalSecret(baseSecret, config.Secrets.masterKey)
	case SecretStatusVaultTransit:
		s.provider = newVaultSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey)
	case SecretStatusAWS:
		s.provider = newAWSSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey)
	case SecretStatusGCP:
		s.provider = newGCPSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey)
	case SecretStatusPlain, SecretStatusRedacted:
		s.provider = config.getSecretProvider(baseSecret)
	default:
		return errInvalidSecret
	}
	return nil
}

// Clone returns a copy of the secret object
func (s *Secret) Clone() *Secret {
	baseSecret := baseSecret{
		Status:         s.provider.GetStatus(),
		Payload:        s.provider.GetPayload(),
		Key:            s.provider.GetKey(),
		AdditionalData: s.provider.GetAdditionalData(),
		Mode:           s.provider.GetMode(),
	}
	switch s.provider.Name() {
	case builtinProviderName:
		return &Secret{
			provider: newBuiltinSecret(baseSecret),
		}
	case awsProviderName:
		return &Secret{
			provider: newAWSSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey),
		}
	case gcpProviderName:
		return &Secret{
			provider: newGCPSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey),
		}
	case localProviderName:
		return &Secret{
			provider: newLocalSecret(baseSecret, config.Secrets.masterKey),
		}
	case vaultProviderName:
		return &Secret{
			provider: newVaultSecret(baseSecret, config.Secrets.URL, config.Secrets.masterKey),
		}
	}
	return NewSecret(s.GetStatus(), s.GetPayload(), s.GetKey(), s.GetAdditionalData())
}

// IsEncrypted returns true if the secret is encrypted
// This isn't a pointer receiver because we don't want to pass
// a pointer to html template
func (s *Secret) IsEncrypted() bool {
	return s.provider.IsEncrypted()
}

// IsPlain returns true if the secret is in plain text
func (s *Secret) IsPlain() bool {
	return s.provider.GetStatus() == SecretStatusPlain
}

// IsRedacted returns true if the secret is redacted
func (s *Secret) IsRedacted() bool {
	return s.provider.GetStatus() == SecretStatusRedacted
}

// GetPayload returns the secret payload
func (s *Secret) GetPayload() string {
	return s.provider.GetPayload()
}

// GetAdditionalData returns the secret additional data
func (s *Secret) GetAdditionalData() string {
	return s.provider.GetAdditionalData()
}

// GetStatus returns the secret status
func (s *Secret) GetStatus() SecretStatus {
	return s.provider.GetStatus()
}

// GetKey returns the secret key
func (s *Secret) GetKey() string {
	return s.provider.GetKey()
}

// GetMode returns the secret mode
func (s *Secret) GetMode() int {
	return s.provider.GetMode()
}

// SetAdditionalData sets the given additional data
func (s *Secret) SetAdditionalData(value string) {
	s.provider.SetAdditionalData(value)
}

// SetStatus sets the status for this secret
func (s *Secret) SetStatus(value SecretStatus) {
	s.provider.SetStatus(value)
}

// SetKey sets the key for this secret
func (s *Secret) SetKey(value string) {
	s.provider.SetKey(value)
}

// IsEmpty returns true if all fields are empty
func (s *Secret) IsEmpty() bool {
	if s.provider.GetStatus() != "" {
		return false
	}
	if s.provider.GetPayload() != "" {
		return false
	}
	if s.provider.GetKey() != "" {
		return false
	}
	if s.provider.GetAdditionalData() != "" {
		return false
	}
	return true
}

// IsValid returns true if the secret is not empty and valid
func (s *Secret) IsValid() bool {
	if !s.IsValidInput() {
		return false
	}
	switch s.provider.GetStatus() {
	case SecretStatusAES256GCM, SecretStatusSecretBox:
		if len(s.provider.GetKey()) != 64 {
			return false
		}
	case SecretStatusAWS, SecretStatusGCP, SecretStatusVaultTransit:
		key := s.provider.GetKey()
		if key != "" && len(key) != 64 {
			return false
		}
	}
	return true
}

// IsValidInput returns true if the secret is a valid user input
func (s *Secret) IsValidInput() bool {
	if !utils.IsStringInSlice(s.provider.GetStatus(), validSecretStatuses) {
		return false
	}
	if s.provider.GetPayload() == "" {
		return false
	}
	return true
}

// Hide hides info to decrypt data
func (s *Secret) Hide() {
	s.provider.SetKey("")
	s.provider.SetAdditionalData("")
}

// Encrypt encrypts a plain text Secret object
func (s *Secret) Encrypt() error {
	return s.provider.Encrypt()
}

// Decrypt decrypts a Secret object
func (s *Secret) Decrypt() error {
	return s.provider.Decrypt()
}
