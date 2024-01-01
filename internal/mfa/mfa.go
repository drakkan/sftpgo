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

// Package mfa provides supports for Multi-Factor authentication modules
package mfa

import (
	"bytes"
	"fmt"
	"image/png"
	"time"

	"github.com/pquerna/otp"
)

var (
	totpConfigs   []*TOTPConfig
	serviceStatus ServiceStatus
)

// ServiceStatus defines the service status
type ServiceStatus struct {
	IsActive    bool         `json:"is_active"`
	TOTPConfigs []TOTPConfig `json:"totp_configs"`
}

// GetStatus returns the service status
func GetStatus() ServiceStatus {
	return serviceStatus
}

// Config defines configuration parameters for Multi-Factor authentication modules
type Config struct {
	// Time-based one time passwords configurations
	TOTP []TOTPConfig `json:"totp" mapstructure:"totp"`
}

// Initialize configures the MFA support
func (c *Config) Initialize() error {
	totpConfigs = nil
	serviceStatus.IsActive = false
	serviceStatus.TOTPConfigs = nil
	totp := make(map[string]bool)
	for _, totpConfig := range c.TOTP {
		totpConfig := totpConfig //pin
		if err := totpConfig.validate(); err != nil {
			totpConfigs = nil
			return fmt.Errorf("invalid TOTP config %+v: %v", totpConfig, err)
		}
		if _, ok := totp[totpConfig.Name]; ok {
			totpConfigs = nil
			return fmt.Errorf("totp: duplicate configuration name %q", totpConfig.Name)
		}
		totp[totpConfig.Name] = true
		totpConfigs = append(totpConfigs, &totpConfig)
		serviceStatus.IsActive = true
		serviceStatus.TOTPConfigs = append(serviceStatus.TOTPConfigs, totpConfig)
	}
	startCleanupTicker(2 * time.Minute)
	return nil
}

// GetAvailableTOTPConfigs returns the available TOTP configs
func GetAvailableTOTPConfigs() []*TOTPConfig {
	return totpConfigs
}

// GetAvailableTOTPConfigNames returns the available TOTP config names
func GetAvailableTOTPConfigNames() []string {
	var result []string
	for _, c := range totpConfigs {
		result = append(result, c.Name)
	}
	return result
}

// ValidateTOTPPasscode validates a TOTP passcode using the given secret and configName
func ValidateTOTPPasscode(configName, passcode, secret string) (bool, error) {
	for _, config := range totpConfigs {
		if config.Name == configName {
			return config.validatePasscode(passcode, secret)
		}
	}

	return false, fmt.Errorf("totp: no configuration %q", configName)
}

// GenerateTOTPSecret generates a new TOTP secret and QR code for the given username
// using the configuration with configName
func GenerateTOTPSecret(configName, username string) (string, *otp.Key, []byte, error) {
	for _, config := range totpConfigs {
		if config.Name == configName {
			key, qrCode, err := config.generate(username, 200, 200)
			return configName, key, qrCode, err
		}
	}

	return "", nil, nil, fmt.Errorf("totp: no configuration %q", configName)
}

// GenerateQRCodeFromURL generates a QR code from a TOTP URL
func GenerateQRCodeFromURL(url string, width, height int) ([]byte, error) {
	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	img, err := key.Image(width, height)
	if err != nil {
		return nil, err
	}
	err = png.Encode(&buf, img)
	return buf.Bytes(), err
}

// the ticker cannot be started/stopped from multiple goroutines
func startCleanupTicker(duration time.Duration) {
	stopCleanupTicker()
	cleanupTicker = time.NewTicker(duration)
	cleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				cleanupUsedPasscodes()
			}
		}
	}()
}

func stopCleanupTicker() {
	if cleanupTicker != nil {
		cleanupTicker.Stop()
		cleanupDone <- true
		cleanupTicker = nil
	}
}
