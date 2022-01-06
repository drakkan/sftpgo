// Package kms provides Key Management Services support
package kms

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"

	sdkkms "github.com/sftpgo/sdk/kms"

	"github.com/drakkan/sftpgo/v2/logger"
)

// SecretProvider defines the interface for a KMS secrets provider
type SecretProvider interface {
	Name() string
	Encrypt() error
	Decrypt() error
	IsEncrypted() bool
	GetStatus() sdkkms.SecretStatus
	GetPayload() string
	GetKey() string
	GetAdditionalData() string
	GetMode() int
	SetKey(string)
	SetAdditionalData(string)
	SetStatus(sdkkms.SecretStatus)
	Clone() SecretProvider
}

const (
	logSender = "kms"
)

// Configuration defines the KMS configuration
type Configuration struct {
	Secrets Secrets `json:"secrets" mapstructure:"secrets"`
}

// Secrets define the KMS configuration for encryption/decryption
type Secrets struct {
	URL             string `json:"url" mapstructure:"url"`
	MasterKeyPath   string `json:"master_key_path" mapstructure:"master_key_path"`
	MasterKeyString string `json:"master_key" mapstructure:"master_key"`
	masterKey       string
}

type registeredSecretProvider struct {
	encryptedStatus sdkkms.SecretStatus
	newFn           func(base BaseSecret, url, masterKey string) SecretProvider
}

var (
	// ErrWrongSecretStatus defines the error to return if the secret status is not appropriate
	// for the request operation
	ErrWrongSecretStatus = errors.New("wrong secret status")
	// ErrInvalidSecret defines the error to return if a secret is not valid
	ErrInvalidSecret    = errors.New("invalid secret")
	validSecretStatuses = []string{sdkkms.SecretStatusPlain, sdkkms.SecretStatusAES256GCM, sdkkms.SecretStatusSecretBox,
		sdkkms.SecretStatusVaultTransit, sdkkms.SecretStatusAWS, sdkkms.SecretStatusGCP, sdkkms.SecretStatusRedacted}
	config          Configuration
	secretProviders = make(map[string]registeredSecretProvider)
)

// RegisterSecretProvider register a new secret provider
func RegisterSecretProvider(scheme string, encryptedStatus sdkkms.SecretStatus,
	fn func(base BaseSecret, url, masterKey string) SecretProvider,
) {
	secretProviders[scheme] = registeredSecretProvider{
		encryptedStatus: encryptedStatus,
		newFn:           fn,
	}
}

// NewSecret builds a new Secret using the provided arguments
func NewSecret(status sdkkms.SecretStatus, payload, key, data string) *Secret {
	return config.newSecret(status, payload, key, data)
}

// NewEmptySecret returns an empty secret
func NewEmptySecret() *Secret {
	return NewSecret("", "", "", "")
}

// NewPlainSecret stores the give payload in a plain text secret
func NewPlainSecret(payload string) *Secret {
	return NewSecret(sdkkms.SecretStatusPlain, payload, "", "")
}

// Initialize configures the KMS support
func (c *Configuration) Initialize() error {
	if c.Secrets.MasterKeyString != "" {
		c.Secrets.masterKey = c.Secrets.MasterKeyString
	}
	if c.Secrets.masterKey == "" && c.Secrets.MasterKeyPath != "" {
		mKey, err := os.ReadFile(c.Secrets.MasterKeyPath)
		if err != nil {
			return err
		}
		c.Secrets.masterKey = strings.TrimSpace(string(mKey))
	}
	config = *c
	if config.Secrets.URL == "" {
		config.Secrets.URL = sdkkms.SchemeLocal + "://"
	}
	for k, v := range secretProviders {
		logger.Info(logSender, "", "secret provider registered for scheme: %#v, encrypted status: %#v",
			k, v.encryptedStatus)
	}
	return nil
}

func (c *Configuration) newSecret(status sdkkms.SecretStatus, payload, key, data string) *Secret {
	base := BaseSecret{
		Status:         status,
		Key:            key,
		Payload:        payload,
		AdditionalData: data,
	}
	return &Secret{
		provider: c.getSecretProvider(base),
	}
}

func (c *Configuration) getSecretProvider(base BaseSecret) SecretProvider {
	for k, v := range secretProviders {
		if strings.HasPrefix(c.Secrets.URL, k) {
			return v.newFn(base, c.Secrets.URL, c.Secrets.masterKey)
		}
	}
	logger.Warn(logSender, "", "no secret provider registered for URL %v, fallback to local provider", c.Secrets.URL)
	return NewLocalSecret(base, c.Secrets.URL, c.Secrets.masterKey)
}

// Secret defines the struct used to store confidential data
type Secret struct {
	sync.RWMutex
	provider SecretProvider
}

// MarshalJSON return the JSON encoding of the Secret object
func (s *Secret) MarshalJSON() ([]byte, error) {
	s.RLock()
	defer s.RUnlock()

	return json.Marshal(&BaseSecret{
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
	s.Lock()
	defer s.Unlock()

	baseSecret := BaseSecret{}
	err := json.Unmarshal(data, &baseSecret)
	if err != nil {
		return err
	}
	if baseSecret.isEmpty() {
		s.provider = config.getSecretProvider(baseSecret)
		return nil
	}

	if baseSecret.Status == sdkkms.SecretStatusPlain || baseSecret.Status == sdkkms.SecretStatusRedacted {
		s.provider = config.getSecretProvider(baseSecret)
		return nil
	}

	for _, v := range secretProviders {
		if v.encryptedStatus == baseSecret.Status {
			s.provider = v.newFn(baseSecret, config.Secrets.URL, config.Secrets.masterKey)
			return nil
		}
	}
	logger.Error(logSender, "", "no provider registered for status %#v", baseSecret.Status)
	return ErrInvalidSecret
}

// IsEqual returns true if all the secrets fields are equal
func (s *Secret) IsEqual(other *Secret) bool {
	if s.GetStatus() != other.GetStatus() {
		return false
	}
	if s.GetPayload() != other.GetPayload() {
		return false
	}
	if s.GetKey() != other.GetKey() {
		return false
	}
	if s.GetAdditionalData() != other.GetAdditionalData() {
		return false
	}
	if s.GetMode() != other.GetMode() {
		return false
	}
	return true
}

// Clone returns a copy of the secret object
func (s *Secret) Clone() *Secret {
	s.RLock()
	defer s.RUnlock()

	return &Secret{
		provider: s.provider.Clone(),
	}
}

// IsEncrypted returns true if the secret is encrypted
// This isn't a pointer receiver because we don't want to pass
// a pointer to html template
func (s *Secret) IsEncrypted() bool {
	s.RLock()
	defer s.RUnlock()

	return s.provider.IsEncrypted()
}

// IsPlain returns true if the secret is in plain text
func (s *Secret) IsPlain() bool {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetStatus() == sdkkms.SecretStatusPlain
}

// IsNotPlainAndNotEmpty returns true if the secret is not plain and not empty.
// This is an utility method, we update the secret for an existing user
// if it is empty or plain
func (s *Secret) IsNotPlainAndNotEmpty() bool {
	s.RLock()
	defer s.RUnlock()

	return !s.IsPlain() && !s.IsEmpty()
}

// IsRedacted returns true if the secret is redacted
func (s *Secret) IsRedacted() bool {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetStatus() == sdkkms.SecretStatusRedacted
}

// GetPayload returns the secret payload
func (s *Secret) GetPayload() string {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetPayload()
}

// GetAdditionalData returns the secret additional data
func (s *Secret) GetAdditionalData() string {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetAdditionalData()
}

// GetStatus returns the secret status
func (s *Secret) GetStatus() sdkkms.SecretStatus {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetStatus()
}

// GetKey returns the secret key
func (s *Secret) GetKey() string {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetKey()
}

// GetMode returns the secret mode
func (s *Secret) GetMode() int {
	s.RLock()
	defer s.RUnlock()

	return s.provider.GetMode()
}

// SetAdditionalData sets the given additional data
func (s *Secret) SetAdditionalData(value string) {
	s.Lock()
	defer s.Unlock()

	s.provider.SetAdditionalData(value)
}

// SetStatus sets the status for this secret
func (s *Secret) SetStatus(value sdkkms.SecretStatus) {
	s.Lock()
	defer s.Unlock()

	s.provider.SetStatus(value)
}

// SetKey sets the key for this secret
func (s *Secret) SetKey(value string) {
	s.Lock()
	defer s.Unlock()

	s.provider.SetKey(value)
}

// IsEmpty returns true if all fields are empty
func (s *Secret) IsEmpty() bool {
	s.RLock()
	defer s.RUnlock()

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
	s.RLock()
	defer s.RUnlock()

	if !s.IsValidInput() {
		return false
	}
	switch s.provider.GetStatus() {
	case sdkkms.SecretStatusAES256GCM, sdkkms.SecretStatusSecretBox:
		if len(s.provider.GetKey()) != 64 {
			return false
		}
	case sdkkms.SecretStatusAWS, sdkkms.SecretStatusGCP, sdkkms.SecretStatusVaultTransit:
		key := s.provider.GetKey()
		if key != "" && len(key) != 64 {
			return false
		}
	}
	return true
}

// IsValidInput returns true if the secret is a valid user input
func (s *Secret) IsValidInput() bool {
	s.RLock()
	defer s.RUnlock()

	if !isSecretStatusValid(s.provider.GetStatus()) {
		return false
	}
	if s.provider.GetPayload() == "" {
		return false
	}
	return true
}

// Hide hides info to decrypt data
func (s *Secret) Hide() {
	s.Lock()
	defer s.Unlock()

	s.provider.SetKey("")
	s.provider.SetAdditionalData("")
}

// Encrypt encrypts a plain text Secret object
func (s *Secret) Encrypt() error {
	s.Lock()
	defer s.Unlock()

	return s.provider.Encrypt()
}

// Decrypt decrypts a Secret object
func (s *Secret) Decrypt() error {
	s.Lock()
	defer s.Unlock()

	return s.provider.Decrypt()
}

// TryDecrypt decrypts a Secret object if encrypted.
// It returns a nil error if the object is not encrypted
func (s *Secret) TryDecrypt() error {
	s.Lock()
	defer s.Unlock()

	if s.provider.IsEncrypted() {
		return s.provider.Decrypt()
	}
	return nil
}

func isSecretStatusValid(status string) bool {
	for idx := range validSecretStatuses {
		if validSecretStatuses[idx] == status {
			return true
		}
	}
	return false
}
