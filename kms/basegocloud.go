package kms

import (
	"context"
	"encoding/base64"
	"time"

	"gocloud.dev/secrets"
	// import awskms package
	_ "gocloud.dev/secrets/awskms"
	// import gcpkms package
	_ "gocloud.dev/secrets/gcpkms"
	// import hashivault package
	_ "gocloud.dev/secrets/hashivault"
)

type baseGCloudSecret struct {
	baseSecret
	masterKey string
	url       string
}

func (s *baseGCloudSecret) Encrypt() error {
	if s.Status != SecretStatusPlain {
		return errWrongSecretStatus
	}
	if s.Payload == "" {
		return errInvalidSecret
	}

	payload := s.Payload
	key := ""
	if s.masterKey != "" {
		localSecret := newLocalSecret(s.baseSecret, s.masterKey)
		err := localSecret.Encrypt()
		if err != nil {
			return err
		}
		payload = localSecret.GetPayload()
		key = localSecret.GetKey()
	}

	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancelFn()

	keeper, err := secrets.OpenKeeper(ctx, s.url)
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
	return nil
}

func (s *baseGCloudSecret) Decrypt() error {
	encrypted, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(defaultTimeout))
	defer cancelFn()

	keeper, err := secrets.OpenKeeper(ctx, s.url)
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
		baseSecret := baseSecret{
			Status:         SecretStatusSecretBox,
			Payload:        string(plaintext),
			Key:            s.Key,
			AdditionalData: s.AdditionalData,
		}
		localSecret := newLocalSecret(baseSecret, s.masterKey)
		err = localSecret.Decrypt()
		if err != nil {
			return err
		}
		payload = localSecret.GetPayload()
	}
	s.Status = SecretStatusPlain
	s.Payload = payload
	s.Key = ""
	s.AdditionalData = ""
	return nil
}
