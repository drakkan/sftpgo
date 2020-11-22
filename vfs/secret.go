package vfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/drakkan/sftpgo/utils"
)

// SecretStatus defines the statuses of a Secret object
type SecretStatus = string

const (
	// SecretStatusPlain means the secret is in plain text and must be encrypted
	SecretStatusPlain SecretStatus = "Plain"
	// SecretStatusAES256GCM means the secret is encrypted using AES-256-GCM
	SecretStatusAES256GCM SecretStatus = "AES-256-GCM"
	// SecretStatusRedacted means the secret is redacted
	SecretStatusRedacted SecretStatus = "Redacted"
)

var (
	errWrongSecretStatus   = errors.New("wrong secret status")
	errMalformedCiphertext = errors.New("malformed ciphertext")
	errInvalidSecret       = errors.New("invalid secret")
	validSecretStatuses    = []string{SecretStatusPlain, SecretStatusAES256GCM, SecretStatusRedacted}
)

// Secret defines the struct used to store confidential data
type Secret struct {
	Status         SecretStatus `json:"status,omitempty"`
	Payload        string       `json:"payload,omitempty"`
	Key            string       `json:"key,omitempty"`
	AdditionalData string       `json:"additional_data,omitempty"`
}

// GetSecretFromCompatString returns a secret from the previous format
func GetSecretFromCompatString(secret string) (Secret, error) {
	s := Secret{}
	plain, err := utils.DecryptData(secret)
	if err != nil {
		return s, errMalformedCiphertext
	}
	s.Status = SecretStatusPlain
	s.Payload = plain
	return s, nil
}

// IsEncrypted returns true if the secret is encrypted
// This isn't a pointer receiver because we don't want to pass
// a pointer to html template
func (s *Secret) IsEncrypted() bool {
	return s.Status == SecretStatusAES256GCM
}

// IsPlain returns true if the secret is in plain text
func (s *Secret) IsPlain() bool {
	return s.Status == SecretStatusPlain
}

// IsRedacted returns true if the secret is redacted
func (s *Secret) IsRedacted() bool {
	return s.Status == SecretStatusRedacted
}

// IsEmpty returns true if all fields are empty
func (s *Secret) IsEmpty() bool {
	if s.Status != "" {
		return false
	}
	if s.Payload != "" {
		return false
	}
	if s.Key != "" {
		return false
	}
	if s.AdditionalData != "" {
		return false
	}
	return true
}

// IsValid returns true if the secret is not empty and valid
func (s *Secret) IsValid() bool {
	if !s.IsValidInput() {
		return false
	}
	if s.Status == SecretStatusAES256GCM {
		if len(s.Key) != 64 {
			return false
		}
	}
	return true
}

// IsValidInput returns true if the secret is a valid user input
func (s *Secret) IsValidInput() bool {
	if !utils.IsStringInSlice(s.Status, validSecretStatuses) {
		return false
	}
	if s.Payload == "" {
		return false
	}
	return true
}

// Hide hides info to decrypt data
func (s *Secret) Hide() {
	s.Key = ""
	s.AdditionalData = ""
}

// deriveKey is a weak method of deriving a key but it is still better than using the key as it is.
// We should use a KMS in future
func (s *Secret) deriveKey(key []byte) []byte {
	var combined []byte
	combined = append(combined, key...)
	if s.AdditionalData != "" {
		combined = append(combined, []byte(s.AdditionalData)...)
	}
	combined = append(combined, key...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// Encrypt encrypts a plain text Secret object
func (s *Secret) Encrypt() error {
	if s.Payload == "" {
		return errInvalidSecret
	}
	switch s.Status {
	case SecretStatusPlain:
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		block, err := aes.NewCipher(s.deriveKey(key))
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		var aad []byte
		if s.AdditionalData != "" {
			aad = []byte(s.AdditionalData)
		}
		ciphertext := gcm.Seal(nonce, nonce, []byte(s.Payload), aad)
		s.Key = hex.EncodeToString(key)
		s.Payload = hex.EncodeToString(ciphertext)
		s.Status = SecretStatusAES256GCM
		return nil
	default:
		return errWrongSecretStatus
	}
}

// Decrypt decrypts a Secret object
func (s *Secret) Decrypt() error {
	switch s.Status {
	case SecretStatusAES256GCM:
		encrypted, err := hex.DecodeString(s.Payload)
		if err != nil {
			return err
		}
		key, err := hex.DecodeString(s.Key)
		if err != nil {
			return err
		}
		block, err := aes.NewCipher(s.deriveKey(key))
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonceSize := gcm.NonceSize()
		if len(encrypted) < nonceSize {
			return errMalformedCiphertext
		}
		nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
		var aad []byte
		if s.AdditionalData != "" {
			aad = []byte(s.AdditionalData)
		}
		plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return err
		}
		s.Status = SecretStatusPlain
		s.Payload = string(plaintext)
		s.Key = ""
		s.AdditionalData = ""
		return nil
	default:
		return errWrongSecretStatus
	}
}
