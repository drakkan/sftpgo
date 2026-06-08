// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	sdkkms "github.com/sftpgo/sdk/kms"
)

var (
	errMalformedCiphertext = errors.New("malformed ciphertext")
)

type builtinSecret struct {
	BaseSecret
}

func init() {
	RegisterSecretProvider(sdkkms.SchemeBuiltin, sdkkms.SecretStatusAES256GCM, newBuiltinSecret)
}

func newBuiltinSecret(base BaseSecret, _, _ string) SecretProvider {
	return &builtinSecret{
		BaseSecret: base,
	}
}

func (s *builtinSecret) Name() string {
	return "Builtin"
}

func (s *builtinSecret) IsEncrypted() bool {
	return s.Status == sdkkms.SecretStatusAES256GCM
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
		return ErrInvalidSecret
	}
	switch s.Status {
	case sdkkms.SecretStatusPlain:
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
		s.Status = sdkkms.SecretStatusAES256GCM
		return nil
	default:
		return ErrWrongSecretStatus
	}
}

func (s *builtinSecret) Decrypt() error {
	switch s.Status {
	case sdkkms.SecretStatusAES256GCM:
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
		s.Status = sdkkms.SecretStatusPlain
		s.Payload = string(plaintext)
		s.Key = ""
		s.AdditionalData = ""
		return nil
	default:
		return ErrWrongSecretStatus
	}
}

func (s *builtinSecret) Clone() SecretProvider {
	baseSecret := BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return newBuiltinSecret(baseSecret, "", "")
}
