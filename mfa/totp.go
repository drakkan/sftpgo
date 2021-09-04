package mfa

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPHMacAlgo is the enumerable for the possible HMAC algorithms for Time-based one time passwords
type TOTPHMacAlgo = string

// supported TOTP HMAC algorithms
const (
	TOTPAlgoSHA1   TOTPHMacAlgo = "sha1"
	TOTPAlgoSHA256 TOTPHMacAlgo = "sha256"
	TOTPAlgoSHA512 TOTPHMacAlgo = "sha512"
)

var (
	cleanupTicker   *time.Ticker
	cleanupDone     chan bool
	usedPasscodes   sync.Map
	errPasscodeUsed = errors.New("this passcode was already used")
)

// TOTPConfig defines the configuration for a Time-based one time password
type TOTPConfig struct {
	Name   string       `json:"name" mapstructure:"name"`
	Issuer string       `json:"issuer" mapstructure:"issuer"`
	Algo   TOTPHMacAlgo `json:"algo" mapstructure:"algo"`
	algo   otp.Algorithm
}

func (c *TOTPConfig) validate() error {
	if c.Name == "" {
		return errors.New("totp: name is mandatory")
	}
	if c.Issuer == "" {
		return errors.New("totp: issuer is mandatory")
	}
	switch c.Algo {
	case TOTPAlgoSHA1:
		c.algo = otp.AlgorithmSHA1
	case TOTPAlgoSHA256:
		c.algo = otp.AlgorithmSHA256
	case TOTPAlgoSHA512:
		c.algo = otp.AlgorithmSHA512
	default:
		return fmt.Errorf("unsupported totp algo %#v", c.Algo)
	}
	return nil
}

// validatePasscode validates a TOTP passcode
func (c *TOTPConfig) validatePasscode(passcode, secret string) (bool, error) {
	key := fmt.Sprintf("%v_%v", secret, passcode)
	if _, ok := usedPasscodes.Load(key); ok {
		return false, errPasscodeUsed
	}
	match, err := totp.ValidateCustom(passcode, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: c.algo,
	})
	if match && err == nil {
		usedPasscodes.Store(key, time.Now().Add(1*time.Minute).UTC())
	}
	return match, err
}

// generate generates a new TOTP secret and QR code for the given username
func (c *TOTPConfig) generate(username string, qrCodeWidth, qrCodeHeight int) (string, string, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      c.Issuer,
		AccountName: username,
		Digits:      otp.DigitsSix,
		Algorithm:   c.algo,
	})
	if err != nil {
		return "", "", nil, err
	}
	var buf bytes.Buffer
	img, err := key.Image(qrCodeWidth, qrCodeHeight)
	if err != nil {
		return "", "", nil, err
	}
	err = png.Encode(&buf, img)
	return key.Issuer(), key.Secret(), buf.Bytes(), err
}

func cleanupUsedPasscodes() {
	usedPasscodes.Range(func(key, value interface{}) bool {
		exp, ok := value.(time.Time)
		if !ok || exp.Before(time.Now().UTC()) {
			usedPasscodes.Delete(key)
		}
		return true
	})
}
