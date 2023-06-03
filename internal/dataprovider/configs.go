// Copyright (C) 2019-2023 Nicola Murino
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

package dataprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// Supported values for host keys, KEXs, ciphers, MACs
var (
	supportedHostKeyAlgos = []string{ssh.KeyAlgoRSA, ssh.CertAlgoRSAv01}
	supportedKexAlgos     = []string{
		"diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
	}
	supportedCiphers = []string{
		"aes128-cbc", "aes192-cbc", "aes256-cbc",
		"3des-cbc",
	}
	supportedMACs = []string{
		"hmac-sha2-512-etm@openssh.com", "hmac-sha2-512",
		"hmac-sha1", "hmac-sha1-96",
	}
)

// SFTPDConfigs defines configurations for SFTPD
type SFTPDConfigs struct {
	HostKeyAlgos  []string `json:"host_key_algos,omitempty"`
	Moduli        []string `json:"moduli,omitempty"`
	KexAlgorithms []string `json:"kex_algorithms,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	MACs          []string `json:"macs,omitempty"`
}

func (c *SFTPDConfigs) isEmpty() bool {
	if len(c.HostKeyAlgos) > 0 {
		return false
	}
	if len(c.Moduli) > 0 {
		return false
	}
	if len(c.KexAlgorithms) > 0 {
		return false
	}
	if len(c.Ciphers) > 0 {
		return false
	}
	if len(c.MACs) > 0 {
		return false
	}
	return true
}

// GetSupportedHostKeyAlgos returns the supported legacy host key algos
func (*SFTPDConfigs) GetSupportedHostKeyAlgos() []string {
	return supportedHostKeyAlgos
}

// GetSupportedKEXAlgos returns the supported KEX algos
func (*SFTPDConfigs) GetSupportedKEXAlgos() []string {
	return supportedKexAlgos
}

// GetSupportedCiphers returns the supported ciphers
func (*SFTPDConfigs) GetSupportedCiphers() []string {
	return supportedCiphers
}

// GetSupportedMACs returns the supported MACs algos
func (*SFTPDConfigs) GetSupportedMACs() []string {
	return supportedMACs
}

// GetModuliAsString returns moduli files as comma separated string
func (c *SFTPDConfigs) GetModuliAsString() string {
	return strings.Join(c.Moduli, ",")
}

func (c *SFTPDConfigs) validate() error {
	for _, algo := range c.HostKeyAlgos {
		if !util.Contains(supportedHostKeyAlgos, algo) {
			return util.NewValidationError(fmt.Sprintf("unsupported host key algorithm %q", algo))
		}
	}
	for _, algo := range c.KexAlgorithms {
		if !util.Contains(supportedKexAlgos, algo) {
			return util.NewValidationError(fmt.Sprintf("unsupported KEX algorithm %q", algo))
		}
	}
	for _, cipher := range c.Ciphers {
		if !util.Contains(supportedCiphers, cipher) {
			return util.NewValidationError(fmt.Sprintf("unsupported cipher %q", cipher))
		}
	}
	for _, mac := range c.MACs {
		if !util.Contains(supportedMACs, mac) {
			return util.NewValidationError(fmt.Sprintf("unsupported MAC algorithm %q", mac))
		}
	}
	return nil
}

func (c *SFTPDConfigs) getACopy() *SFTPDConfigs {
	hostKeys := make([]string, len(c.HostKeyAlgos))
	copy(hostKeys, c.HostKeyAlgos)
	moduli := make([]string, len(c.Moduli))
	copy(moduli, c.Moduli)
	kexs := make([]string, len(c.KexAlgorithms))
	copy(kexs, c.KexAlgorithms)
	ciphers := make([]string, len(c.Ciphers))
	copy(ciphers, c.Ciphers)
	macs := make([]string, len(c.MACs))
	copy(macs, c.MACs)

	return &SFTPDConfigs{
		HostKeyAlgos:  hostKeys,
		Moduli:        moduli,
		KexAlgorithms: kexs,
		Ciphers:       ciphers,
		MACs:          macs,
	}
}

func validateSMTPSecret(secret *kms.Secret, name string) error {
	if secret.IsRedacted() {
		return util.NewValidationError(fmt.Sprintf("cannot save a redacted smtp %s", name))
	}
	if secret.IsEncrypted() && !secret.IsValid() {
		return util.NewValidationError(fmt.Sprintf("invalid encrypted smtp %s", name))
	}
	if !secret.IsEmpty() && !secret.IsValidInput() {
		return util.NewValidationError(fmt.Sprintf("invalid smtp %s", name))
	}
	if secret.IsPlain() {
		secret.SetAdditionalData("smtp")
		if err := secret.Encrypt(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt smtp %s: %v", name, err))
		}
	}
	return nil
}

// SMTPOAuth2 defines the SMTP related OAuth2 configurations
type SMTPOAuth2 struct {
	Provider     int         `json:"provider,omitempty"`
	Tenant       string      `json:"tenant,omitempty"`
	ClientID     string      `json:"client_id,omitempty"`
	ClientSecret *kms.Secret `json:"client_secret,omitempty"`
	RefreshToken *kms.Secret `json:"refresh_token,omitempty"`
}

func (c *SMTPOAuth2) validate() error {
	if c.Provider < 0 || c.Provider > 1 {
		return util.NewValidationError("smtp oauth2: unsupported provider")
	}
	if c.ClientID == "" {
		return util.NewValidationError("smtp oauth2: client id is required")
	}
	if c.ClientSecret == nil {
		return util.NewValidationError("smtp oauth2: client secret is required")
	}
	if c.RefreshToken == nil {
		return util.NewValidationError("smtp oauth2: refresh token is required")
	}
	if err := validateSMTPSecret(c.ClientSecret, "oauth2 client secret"); err != nil {
		return err
	}
	return validateSMTPSecret(c.RefreshToken, "oauth2 refresh token")
}

func (c *SMTPOAuth2) getACopy() SMTPOAuth2 {
	var clientSecret, refreshToken *kms.Secret
	if c.ClientSecret != nil {
		clientSecret = c.ClientSecret.Clone()
	}
	if c.RefreshToken != nil {
		refreshToken = c.RefreshToken.Clone()
	}
	return SMTPOAuth2{
		Provider:     c.Provider,
		Tenant:       c.Tenant,
		ClientID:     c.ClientID,
		ClientSecret: clientSecret,
		RefreshToken: refreshToken,
	}
}

// SMTPConfigs defines configuration for SMTP
type SMTPConfigs struct {
	Host       string      `json:"host,omitempty"`
	Port       int         `json:"port,omitempty"`
	From       string      `json:"from,omitempty"`
	User       string      `json:"user,omitempty"`
	Password   *kms.Secret `json:"password,omitempty"`
	AuthType   int         `json:"auth_type,omitempty"`
	Encryption int         `json:"encryption,omitempty"`
	Domain     string      `json:"domain,omitempty"`
	Debug      int         `json:"debug,omitempty"`
	OAuth2     SMTPOAuth2  `json:"oauth2"`
}

// IsEmpty returns true if the configuration is empty
func (c *SMTPConfigs) IsEmpty() bool {
	return c.Host == ""
}

func (c *SMTPConfigs) validate() error {
	if c.IsEmpty() {
		return nil
	}
	if c.Port <= 0 || c.Port > 65535 {
		return util.NewValidationError(fmt.Sprintf("smtp: invalid port %d", c.Port))
	}
	if c.Password != nil && c.AuthType != 3 {
		if err := validateSMTPSecret(c.Password, "password"); err != nil {
			return err
		}
	}
	if c.User == "" && c.From == "" {
		return util.NewValidationError("smtp: from address and user cannot both be empty")
	}
	if c.AuthType < 0 || c.AuthType > 3 {
		return util.NewValidationError(fmt.Sprintf("smtp: invalid auth type %d", c.AuthType))
	}
	if c.Encryption < 0 || c.Encryption > 2 {
		return util.NewValidationError(fmt.Sprintf("smtp: invalid encryption %d", c.Encryption))
	}
	if c.AuthType == 3 {
		c.Password = kms.NewEmptySecret()
		return c.OAuth2.validate()
	}
	c.OAuth2 = SMTPOAuth2{}
	return nil
}

// TryDecrypt tries to decrypt the encrypted secrets
func (c *SMTPConfigs) TryDecrypt() error {
	if c.Password == nil {
		c.Password = kms.NewEmptySecret()
	}
	if c.OAuth2.ClientSecret == nil {
		c.OAuth2.ClientSecret = kms.NewEmptySecret()
	}
	if c.OAuth2.RefreshToken == nil {
		c.OAuth2.RefreshToken = kms.NewEmptySecret()
	}
	if err := c.Password.TryDecrypt(); err != nil {
		return fmt.Errorf("unable to decrypt smtp password: %w", err)
	}
	if err := c.OAuth2.ClientSecret.TryDecrypt(); err != nil {
		return fmt.Errorf("unable to decrypt smtp oauth2 client secret: %w", err)
	}
	if err := c.OAuth2.RefreshToken.TryDecrypt(); err != nil {
		return fmt.Errorf("unable to decrypt smtp oauth2 refresh token: %w", err)
	}
	return nil
}

func (c *SMTPConfigs) getACopy() *SMTPConfigs {
	var password *kms.Secret
	if c.Password != nil {
		password = c.Password.Clone()
	}
	return &SMTPConfigs{
		Host:       c.Host,
		Port:       c.Port,
		From:       c.From,
		User:       c.User,
		Password:   password,
		AuthType:   c.AuthType,
		Encryption: c.Encryption,
		Domain:     c.Domain,
		Debug:      c.Debug,
		OAuth2:     c.OAuth2.getACopy(),
	}
}

// ACMEHTTP01Challenge defines the configuration for HTTP-01 challenge type
type ACMEHTTP01Challenge struct {
	Port int `json:"port"`
}

// ACMEConfigs defines ACME related configuration
type ACMEConfigs struct {
	Domain          string              `json:"domain"`
	Email           string              `json:"email"`
	HTTP01Challenge ACMEHTTP01Challenge `json:"http01_challenge"`
	// apply the certificate for the specified protocols:
	//
	// 1 means HTTP
	// 2 means FTP
	// 4 means WebDAV
	//
	// Protocols can be combined
	Protocols int `json:"protocols"`
}

func (c *ACMEConfigs) isEmpty() bool {
	return c.Domain == ""
}

func (c *ACMEConfigs) validate() error {
	if c.Domain == "" {
		return nil
	}
	if c.Email == "" && !util.IsEmailValid(c.Email) {
		return util.NewValidationError(fmt.Sprintf("acme: invalid email %q", c.Email))
	}
	if c.HTTP01Challenge.Port <= 0 || c.HTTP01Challenge.Port > 65535 {
		return util.NewValidationError(fmt.Sprintf("acme: invalid HTTP-01 challenge port %d", c.HTTP01Challenge.Port))
	}
	return nil
}

// HasProtocol returns true if the ACME certificate must be used for the specified protocol
func (c *ACMEConfigs) HasProtocol(protocol string) bool {
	switch protocol {
	case protocolHTTP:
		return c.Protocols&1 != 0
	case protocolFTP:
		return c.Protocols&2 != 0
	case protocolWebDAV:
		return c.Protocols&4 != 0
	default:
		return false
	}
}

func (c *ACMEConfigs) getACopy() *ACMEConfigs {
	return &ACMEConfigs{
		Email:           c.Email,
		Domain:          c.Domain,
		HTTP01Challenge: ACMEHTTP01Challenge{Port: c.HTTP01Challenge.Port},
		Protocols:       c.Protocols,
	}
}

// Configs allows to set configuration keys disabled by default without
// modifying the config file or setting env vars
type Configs struct {
	SFTPD     *SFTPDConfigs `json:"sftpd,omitempty"`
	SMTP      *SMTPConfigs  `json:"smtp,omitempty"`
	ACME      *ACMEConfigs  `json:"acme,omitempty"`
	UpdatedAt int64         `json:"updated_at,omitempty"`
}

func (c *Configs) validate() error {
	if c.SFTPD != nil {
		if err := c.SFTPD.validate(); err != nil {
			return err
		}
	}
	if c.SMTP != nil {
		if err := c.SMTP.validate(); err != nil {
			return err
		}
	}
	if c.ACME != nil {
		if err := c.ACME.validate(); err != nil {
			return err
		}
	}
	return nil
}

// PrepareForRendering prepares configs for rendering.
// It hides confidential data and set to nil the empty structs/secrets
// so they are not serialized
func (c *Configs) PrepareForRendering() {
	if c.SFTPD != nil && c.SFTPD.isEmpty() {
		c.SFTPD = nil
	}
	if c.SMTP != nil && c.SMTP.IsEmpty() {
		c.SMTP = nil
	}
	if c.ACME != nil && c.ACME.isEmpty() {
		c.ACME = nil
	}
	if c.SMTP != nil {
		if c.SMTP.Password != nil {
			c.SMTP.Password.Hide()
			if c.SMTP.Password.IsEmpty() {
				c.SMTP.Password = nil
			}
		}
		if c.SMTP.OAuth2.ClientSecret != nil {
			c.SMTP.OAuth2.ClientSecret.Hide()
			if c.SMTP.OAuth2.ClientSecret.IsEmpty() {
				c.SMTP.OAuth2.ClientSecret = nil
			}
		}
		if c.SMTP.OAuth2.RefreshToken != nil {
			c.SMTP.OAuth2.RefreshToken.Hide()
			if c.SMTP.OAuth2.RefreshToken.IsEmpty() {
				c.SMTP.OAuth2.RefreshToken = nil
			}
		}
	}
}

// SetNilsToEmpty sets nil fields to empty
func (c *Configs) SetNilsToEmpty() {
	if c.SFTPD == nil {
		c.SFTPD = &SFTPDConfigs{}
	}
	if c.SMTP == nil {
		c.SMTP = &SMTPConfigs{}
	}
	if c.SMTP.Password == nil {
		c.SMTP.Password = kms.NewEmptySecret()
	}
	if c.SMTP.OAuth2.ClientSecret == nil {
		c.SMTP.OAuth2.ClientSecret = kms.NewEmptySecret()
	}
	if c.SMTP.OAuth2.RefreshToken == nil {
		c.SMTP.OAuth2.RefreshToken = kms.NewEmptySecret()
	}
	if c.ACME == nil {
		c.ACME = &ACMEConfigs{}
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (c *Configs) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		config, err := provider.getConfigs()
		if err != nil {
			providerLog(logger.LevelError, "unable to reload config overrides before rendering as json: %v", err)
			return nil, err
		}
		config.PrepareForRendering()
		return json.Marshal(config)
	}
	c.PrepareForRendering()
	return json.Marshal(c)
}

func (c *Configs) getACopy() Configs {
	var result Configs
	if c.SFTPD != nil {
		result.SFTPD = c.SFTPD.getACopy()
	}
	if c.SMTP != nil {
		result.SMTP = c.SMTP.getACopy()
	}
	if c.ACME != nil {
		result.ACME = c.ACME.getACopy()
	}
	result.UpdatedAt = c.UpdatedAt
	return result
}
