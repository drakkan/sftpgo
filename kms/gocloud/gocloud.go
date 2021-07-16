package gocloud

import (
	"context"
	"encoding/base64"
	"time"

	"gocloud.dev/secrets"

	"github.com/drakkan/sftpgo/v2/kms"
)

const (
	defaultTimeout = 10 * time.Second
)

// Secret defines common methods for go-cloud based kms
type Secret struct {
	kms.BaseSecret
	MasterKey string
	URL       string
}

func (s *Secret) Encrypt() error {
	if s.Status != kms.SecretStatusPlain {
		return kms.ErrWrongSecretStatus
	}
	if s.Payload == "" {
		return kms.ErrInvalidSecret
	}

	payload := s.Payload
	key := ""
	mode := 0
	if s.MasterKey != "" {
		localSecret := kms.NewLocalSecret(s.BaseSecret, "", s.MasterKey)
		err := localSecret.Encrypt()
		if err != nil {
			return err
		}
		payload = localSecret.GetPayload()
		key = localSecret.GetKey()
		mode = localSecret.GetMode()
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancelFn()

	keeper, err := secrets.OpenKeeper(ctx, s.URL)
	if err != nil {
		return err
	}

	defer keeper.Close()
	ciphertext, err := keeper.Encrypt(context.Background(), []byte(payload))
	if err != nil {
		return err
	}
	s.Payload = base64.StdEncoding.EncodeToString(ciphertext)
	s.Key = key
	s.Mode = mode
	return nil
}

func (s *Secret) Decrypt() error {
	encrypted, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancelFn()

	keeper, err := secrets.OpenKeeper(ctx, s.URL)
	if err != nil {
		return err
	}

	defer keeper.Close()
	plaintext, err := keeper.Decrypt(context.Background(), encrypted)
	if err != nil {
		return err
	}
	payload := string(plaintext)
	if s.Key != "" {
		baseSecret := kms.BaseSecret{
			Status:         kms.SecretStatusSecretBox,
			Payload:        payload,
			Key:            s.Key,
			AdditionalData: s.AdditionalData,
			Mode:           s.Mode,
		}
		localSecret := kms.NewLocalSecret(baseSecret, "", s.MasterKey)
		err = localSecret.Decrypt()
		if err != nil {
			return err
		}
		payload = localSecret.GetPayload()
	}
	s.Status = kms.SecretStatusPlain
	s.Payload = payload
	s.Key = ""
	s.AdditionalData = ""
	s.Mode = 0
	return nil
}
