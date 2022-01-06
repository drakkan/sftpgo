package kms

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"

	sdkkms "github.com/sftpgo/sdk/kms"
	"gocloud.dev/secrets/localsecrets"
	"golang.org/x/crypto/hkdf"
)

func init() {
	RegisterSecretProvider(sdkkms.SchemeLocal, sdkkms.SecretStatusSecretBox, NewLocalSecret)
}

type localSecret struct {
	BaseSecret
	masterKey string
}

// NewLocalSecret returns a SecretProvider that use a locally provided symmetric key
func NewLocalSecret(base BaseSecret, url, masterKey string) SecretProvider {
	return &localSecret{
		BaseSecret: base,
		masterKey:  masterKey,
	}
}

func (s *localSecret) Name() string {
	return "Local"
}

func (s *localSecret) IsEncrypted() bool {
	return s.Status == sdkkms.SecretStatusSecretBox
}

func (s *localSecret) Encrypt() error {
	if s.Status != sdkkms.SecretStatusPlain {
		return ErrWrongSecretStatus
	}
	if s.Payload == "" {
		return ErrInvalidSecret
	}
	secretKey, err := localsecrets.NewRandomKey()
	if err != nil {
		return err
	}
	key, err := s.deriveKey(secretKey[:], false)
	if err != nil {
		return err
	}
	keeper := localsecrets.NewKeeper(key)
	defer keeper.Close()

	ciphertext, err := keeper.Encrypt(context.Background(), []byte(s.Payload))
	if err != nil {
		return err
	}
	s.Key = hex.EncodeToString(secretKey[:])
	s.Payload = base64.StdEncoding.EncodeToString(ciphertext)
	s.Status = sdkkms.SecretStatusSecretBox
	s.Mode = s.getEncryptionMode()
	return nil
}

func (s *localSecret) Decrypt() error {
	if !s.IsEncrypted() {
		return ErrWrongSecretStatus
	}
	encrypted, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return err
	}
	secretKey, err := hex.DecodeString(s.Key)
	if err != nil {
		return err
	}
	key, err := s.deriveKey(secretKey[:], true)
	if err != nil {
		return err
	}
	keeper := localsecrets.NewKeeper(key)
	defer keeper.Close()

	plaintext, err := keeper.Decrypt(context.Background(), encrypted)
	if err != nil {
		return err
	}
	s.Status = sdkkms.SecretStatusPlain
	s.Payload = string(plaintext)
	s.Key = ""
	s.AdditionalData = ""
	s.Mode = 0
	return nil
}

func (s *localSecret) deriveKey(key []byte, isForDecryption bool) ([32]byte, error) {
	var masterKey []byte
	if s.masterKey == "" || (isForDecryption && s.Mode == 0) {
		var combined []byte
		combined = append(combined, key...)
		if s.AdditionalData != "" {
			combined = append(combined, []byte(s.AdditionalData)...)
		}
		combined = append(combined, key...)
		hash := sha256.Sum256(combined)
		masterKey = hash[:]
	} else {
		masterKey = []byte(s.masterKey)
	}
	var derivedKey [32]byte
	var info []byte
	if s.AdditionalData != "" {
		info = []byte(s.AdditionalData)
	}
	kdf := hkdf.New(sha256.New, masterKey, key, info)
	if _, err := io.ReadFull(kdf, derivedKey[:]); err != nil {
		return derivedKey, err
	}
	return derivedKey, nil
}

func (s *localSecret) getEncryptionMode() int {
	if s.masterKey == "" {
		return 0
	}
	return 1
}

func (s *localSecret) Clone() SecretProvider {
	baseSecret := BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return NewLocalSecret(baseSecret, "", s.masterKey)
}
