package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/minio/sha256-simd"
)

type builtinSecret struct {
	baseSecret
}

func newBuiltinSecret(base baseSecret) SecretProvider {
	return &builtinSecret{
		baseSecret: base,
	}
}

func (s *builtinSecret) Name() string {
	return builtinProviderName
}

func (s *builtinSecret) IsEncrypted() bool {
	return s.Status == SecretStatusAES256GCM
}

func (s *builtinSecret) deriveKey(key []byte) []byte {
	var combined []byte
	combined = append(combined, key...)
	if s.AdditionalData != "" {
		combined = append(combined, []byte(s.AdditionalData)...)
	}
	combined = append(combined, key...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

func (s *builtinSecret) Encrypt() error {
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

func (s *builtinSecret) Decrypt() error {
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
