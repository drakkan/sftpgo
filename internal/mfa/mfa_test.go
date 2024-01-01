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

package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMFAConfig(t *testing.T) {
	config := Config{
		TOTP: []TOTPConfig{
			{},
		},
	}
	configName1 := "config1"
	configName2 := "config2"
	configName3 := "config3"
	err := config.Initialize()
	assert.Error(t, err)
	config.TOTP[0].Name = configName1
	err = config.Initialize()
	assert.Error(t, err)
	config.TOTP[0].Issuer = "issuer"
	err = config.Initialize()
	assert.Error(t, err)
	config.TOTP[0].Algo = TOTPAlgoSHA1
	err = config.Initialize()
	assert.NoError(t, err)
	config.TOTP = append(config.TOTP, TOTPConfig{
		Name:   configName1,
		Issuer: "SFTPGo",
		Algo:   TOTPAlgoSHA512,
	})
	err = config.Initialize()
	assert.Error(t, err)
	config.TOTP[1].Name = configName2
	err = config.Initialize()
	assert.NoError(t, err)
	assert.Len(t, GetAvailableTOTPConfigs(), 2)
	assert.Len(t, GetAvailableTOTPConfigNames(), 2)
	config.TOTP = append(config.TOTP, TOTPConfig{
		Name:   configName3,
		Issuer: "SFTPGo",
		Algo:   TOTPAlgoSHA256,
	})
	err = config.Initialize()
	assert.NoError(t, err)
	assert.Len(t, GetAvailableTOTPConfigs(), 3)
	if assert.Len(t, GetAvailableTOTPConfigNames(), 3) {
		assert.Contains(t, GetAvailableTOTPConfigNames(), configName1)
		assert.Contains(t, GetAvailableTOTPConfigNames(), configName2)
		assert.Contains(t, GetAvailableTOTPConfigNames(), configName3)
	}
	status := GetStatus()
	assert.True(t, status.IsActive)
	if assert.Len(t, status.TOTPConfigs, 3) {
		assert.Equal(t, configName1, status.TOTPConfigs[0].Name)
		assert.Equal(t, configName2, status.TOTPConfigs[1].Name)
		assert.Equal(t, configName3, status.TOTPConfigs[2].Name)
	}
	// now generate some secrets and validate some passcodes
	_, _, _, err = GenerateTOTPSecret("", "") //nolint:dogsled
	assert.Error(t, err)
	match, err := ValidateTOTPPasscode("", "", "")
	assert.Error(t, err)
	assert.False(t, match)
	cfgName, key, _, err := GenerateTOTPSecret(configName1, "user1")
	assert.NoError(t, err)
	assert.NotEmpty(t, key.Secret())
	assert.Equal(t, configName1, cfgName)
	passcode, err := generatePasscode(key.Secret(), otp.AlgorithmSHA1)
	assert.NoError(t, err)
	match, err = ValidateTOTPPasscode(configName1, passcode, key.Secret())
	assert.NoError(t, err)
	assert.True(t, match)
	match, err = ValidateTOTPPasscode(configName1, passcode, key.Secret())
	assert.ErrorIs(t, err, errPasscodeUsed)
	assert.False(t, match)

	passcode, err = generatePasscode(key.Secret(), otp.AlgorithmSHA256)
	assert.NoError(t, err)
	// config1 uses sha1 algo
	match, err = ValidateTOTPPasscode(configName1, passcode, key.Secret())
	assert.NoError(t, err)
	assert.False(t, match)
	// config3 use the expected algo
	match, err = ValidateTOTPPasscode(configName3, passcode, key.Secret())
	assert.NoError(t, err)
	assert.True(t, match)

	stopCleanupTicker()
}

func TestGenerateQRCodeFromURL(t *testing.T) {
	_, err := GenerateQRCodeFromURL("http://foo\x7f.cloud", 200, 200)
	assert.Error(t, err)
	config := TOTPConfig{
		Name:   "config name",
		Issuer: "SFTPGo",
		Algo:   TOTPAlgoSHA256,
	}
	key, qrCode, err := config.generate("a", 150, 150)
	require.NoError(t, err)

	qrCode1, err := GenerateQRCodeFromURL(key.URL(), 150, 150)
	require.NoError(t, err)
	assert.Equal(t, qrCode, qrCode1)
	_, err = GenerateQRCodeFromURL(key.URL(), 10, 10)
	assert.Error(t, err)
}

func TestCleanupPasscodes(t *testing.T) {
	usedPasscodes.Store("key", time.Now().Add(-24*time.Hour).UTC())
	startCleanupTicker(30 * time.Millisecond)
	assert.Eventually(t, func() bool {
		_, ok := usedPasscodes.Load("key")
		return !ok
	}, 1000*time.Millisecond, 100*time.Millisecond)
	stopCleanupTicker()
}

func TestTOTPGenerateErrors(t *testing.T) {
	config := TOTPConfig{
		Name:   "name",
		Issuer: "",
		algo:   otp.AlgorithmSHA1,
	}
	// issuer cannot be empty
	_, _, err := config.generate("username", 200, 200) //nolint:dogsled
	assert.Error(t, err)
	config.Issuer = "issuer"
	// we cannot encode an image smaller than 45x45
	_, _, err = config.generate("username", 30, 30) //nolint:dogsled
	assert.Error(t, err)
}

func generatePasscode(secret string, algo otp.Algorithm) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: algo,
	})
}
