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

// Package smtp provides supports for sending emails
package smtp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/wneessen/go-mail"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	logSender = "smtp"
)

// EmailContentType defines the support content types for email body
type EmailContentType int

// Supported email body content type
const (
	EmailContentTypeTextPlain EmailContentType = iota
	EmailContentTypeTextHTML
)

const (
	templateEmailDir           = "email"
	templatePasswordReset      = "reset-password.html"
	templatePasswordExpiration = "password-expiration.html"
	dialTimeout                = 10 * time.Second
)

var (
	config         = &activeConfig{}
	initialConfig  *Config
	emailTemplates = make(map[string]*template.Template)
)

type activeConfig struct {
	sync.RWMutex
	config *Config
}

func (c *activeConfig) isEnabled() bool {
	c.RLock()
	defer c.RUnlock()

	return c.config != nil && c.config.Host != ""
}

func (c *activeConfig) Set(cfg *dataprovider.SMTPConfigs) {
	var config *Config
	if cfg != nil {
		config = &Config{
			Host:       cfg.Host,
			Port:       cfg.Port,
			From:       cfg.From,
			User:       cfg.User,
			Password:   cfg.Password.GetPayload(),
			AuthType:   cfg.AuthType,
			Encryption: cfg.Encryption,
			Domain:     cfg.Domain,
			Debug:      cfg.Debug,
			OAuth2: OAuth2Config{
				Provider:     cfg.OAuth2.Provider,
				Tenant:       cfg.OAuth2.Tenant,
				ClientID:     cfg.OAuth2.ClientID,
				ClientSecret: cfg.OAuth2.ClientSecret.GetPayload(),
				RefreshToken: cfg.OAuth2.RefreshToken.GetPayload(),
			},
		}
		config.OAuth2.initialize()
	}

	c.Lock()
	defer c.Unlock()

	if config != nil && config.Host != "" {
		if c.config != nil && c.config.isEqual(config) {
			return
		}
		c.config = config
		logger.Info(logSender, "", "activated new config, server %s:%d", c.config.Host, c.config.Port)
	} else {
		logger.Debug(logSender, "", "activating initial config")
		c.config = initialConfig
		if c.config == nil || c.config.Host == "" {
			logger.Debug(logSender, "", "configuration disabled, email capabilities will not be available")
		}
	}
}

func (c *activeConfig) getSMTPClientAndMsg(to, bcc []string, subject, body string, contentType EmailContentType,
	attachments ...*mail.File,
) (*mail.Client, *mail.Msg, error) {
	c.RLock()
	defer c.RUnlock()

	if c.config == nil || c.config.Host == "" {
		return nil, nil, errors.New("smtp: not configured")
	}

	return c.config.getSMTPClientAndMsg(to, bcc, subject, body, contentType, attachments...)
}

func (c *activeConfig) sendEmail(to, bcc []string, subject, body string, contentType EmailContentType, attachments ...*mail.File) error {
	client, msg, err := c.getSMTPClientAndMsg(to, bcc, subject, body, contentType, attachments...)
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), dialTimeout)
	defer cancelFn()

	return client.DialAndSendWithContext(ctx, msg)
}

// IsEnabled returns true if an SMTP server is configured
func IsEnabled() bool {
	return config.isEnabled()
}

// Activate sets the specified config as active
func Activate(c *dataprovider.SMTPConfigs) {
	config.Set(c)
}

// Config defines the SMTP configuration to use to send emails
type Config struct {
	// Location of SMTP email server. Leavy empty to disable email sending capabilities
	Host string `json:"host" mapstructure:"host"`
	// Port of SMTP email server
	Port int `json:"port" mapstructure:"port"`
	// From address, for example "SFTPGo <sftpgo@example.com>".
	// Many SMTP servers reject emails without a `From` header so, if not set,
	// SFTPGo will try to use the username as fallback, this may or may not be appropriate
	From string `json:"from" mapstructure:"from"`
	// SMTP username
	User string `json:"user" mapstructure:"user"`
	// SMTP password. Leaving both username and password empty the SMTP authentication
	// will be disabled
	Password string `json:"password" mapstructure:"password"`
	// 0 Plain
	// 1 Login
	// 2 CRAM-MD5
	// 3 OAuth2
	AuthType int `json:"auth_type" mapstructure:"auth_type"`
	// 0 no encryption
	// 1 TLS
	// 2 start TLS
	Encryption int `json:"encryption" mapstructure:"encryption"`
	// Domain to use for HELO command, if empty localhost will be used
	Domain string `json:"domain" mapstructure:"domain"`
	// Path to the email templates. This can be an absolute path or a path relative to the config dir.
	// Templates are searched within a subdirectory named "email" in the specified path
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Set to 1 to enable debug logs
	Debug int `json:"debug" mapstructure:"debug"`
	// OAuth2 related settings
	OAuth2 OAuth2Config `json:"oauth2" mapstructure:"oauth2"`
}

func (c *Config) isEqual(other *Config) bool {
	if c.Host != other.Host {
		return false
	}
	if c.Port != other.Port {
		return false
	}
	if c.From != other.From {
		return false
	}
	if c.User != other.User {
		return false
	}
	if c.Password != other.Password {
		return false
	}
	if c.AuthType != other.AuthType {
		return false
	}
	if c.Encryption != other.Encryption {
		return false
	}
	if c.Domain != other.Domain {
		return false
	}
	if c.Debug != other.Debug {
		return false
	}
	return c.OAuth2.isEqual(&other.OAuth2)
}

func (c *Config) validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("smtp: invalid port %d", c.Port)
	}
	if c.AuthType < 0 || c.AuthType > 3 {
		return fmt.Errorf("smtp: invalid auth type %d", c.AuthType)
	}
	if c.Encryption < 0 || c.Encryption > 2 {
		return fmt.Errorf("smtp: invalid encryption %d", c.Encryption)
	}
	if c.From == "" && c.User == "" {
		return errors.New(`smtp: from address and user cannot both be empty`)
	}
	if c.AuthType == 3 {
		return c.OAuth2.Validate()
	}
	return nil
}

func (c *Config) loadTemplates(configDir string) error {
	if c.TemplatesPath == "" {
		logger.Debug(logSender, "", "templates path empty, using default")
		c.TemplatesPath = "templates"
	}
	templatesPath := util.FindSharedDataPath(c.TemplatesPath, configDir)
	if templatesPath == "" {
		return fmt.Errorf("smtp: invalid templates path %q", templatesPath)
	}
	loadTemplates(filepath.Join(templatesPath, templateEmailDir))
	return nil
}

// Initialize initialized and validates the SMTP configuration
func (c *Config) Initialize(configDir string, isService bool) error {
	if !isService && c.Host == "" {
		if err := loadConfigFromProvider(); err != nil {
			return err
		}
		if !config.isEnabled() {
			return nil
		}
		return c.loadTemplates(configDir)
	}
	if err := c.loadTemplates(configDir); err != nil {
		return err
	}
	if c.Host == "" {
		return loadConfigFromProvider()
	}
	if err := c.validate(); err != nil {
		return err
	}
	initialConfig = c
	config.Set(nil)
	logger.Debug(logSender, "", "configuration successfully initialized, host: %q, port: %d, username: %q, auth: %d, encryption: %d, helo: %q",
		c.Host, c.Port, c.User, c.AuthType, c.Encryption, c.Domain)
	return loadConfigFromProvider()
}

func (c *Config) getMailClientOptions() []mail.Option {
	options := []mail.Option{mail.WithoutNoop()}

	switch c.Encryption {
	case 1:
		options = append(options, mail.WithSSLPort(false))
	case 2:
		options = append(options, mail.WithTLSPortPolicy(mail.TLSMandatory))
	default:
		options = append(options, mail.WithTLSPortPolicy(mail.NoTLS))
	}
	if c.User != "" {
		options = append(options, mail.WithUsername(c.User))
	}
	if c.Password != "" {
		options = append(options, mail.WithPassword(c.Password))
	}
	if c.User != "" || c.Password != "" {
		switch c.AuthType {
		case 1:
			options = append(options, mail.WithSMTPAuth(mail.SMTPAuthLogin))
		case 2:
			options = append(options, mail.WithSMTPAuth(mail.SMTPAuthCramMD5))
		case 3:
			options = append(options, mail.WithSMTPAuth(mail.SMTPAuthXOAUTH2))
		default:
			options = append(options, mail.WithSMTPAuth(mail.SMTPAuthPlain))
		}
	}
	if c.Domain != "" {
		options = append(options, mail.WithHELO(c.Domain))
	}
	if c.Debug > 0 {
		options = append(options,
			mail.WithLogger(&logger.MailAdapter{
				ConnectionID: xid.New().String(),
			}),
			mail.WithDebugLog())
	}
	options = append(options, mail.WithPort(c.Port))
	return options
}

func (c *Config) getSMTPClientAndMsg(to, bcc []string, subject, body string, contentType EmailContentType,
	attachments ...*mail.File) (*mail.Client, *mail.Msg, error) {
	version := version.Get()
	msg := mail.NewMsg()
	msg.SetUserAgent(fmt.Sprintf("SFTPGo-%s-%s", version.Version, version.CommitHash))

	var from string
	if c.From != "" {
		from = c.From
	} else {
		from = c.User
	}
	if err := msg.From(from); err != nil {
		return nil, nil, fmt.Errorf("invalid from address: %w", err)
	}
	if err := msg.To(to...); err != nil {
		return nil, nil, err
	}
	if len(bcc) > 0 {
		if err := msg.Bcc(bcc...); err != nil {
			return nil, nil, err
		}
	}
	msg.Subject(subject)
	msg.SetDate()
	msg.SetMessageID()
	msg.SetAttachements(attachments)

	switch contentType {
	case EmailContentTypeTextPlain:
		msg.SetBodyString(mail.TypeTextPlain, body)
	case EmailContentTypeTextHTML:
		msg.SetBodyString(mail.TypeTextHTML, body)
	default:
		return nil, nil, fmt.Errorf("smtp: unsupported body content type %v", contentType)
	}

	client, err := mail.NewClient(c.Host, c.getMailClientOptions()...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create mail client: %w", err)
	}
	if c.AuthType == 3 {
		token, err := c.OAuth2.getAccessToken()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get oauth2 access token: %w", err)
		}
		client.SetPassword(token)
	}
	return client, msg, nil
}

// SendEmail tries to send an email using the specified parameters
func (c *Config) SendEmail(to, bcc []string, subject, body string, contentType EmailContentType, attachments ...*mail.File) error {
	client, msg, err := c.getSMTPClientAndMsg(to, bcc, subject, body, contentType, attachments...)
	if err != nil {
		return err
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), dialTimeout)
	defer cancelFn()

	return client.DialAndSendWithContext(ctx, msg)
}

func loadTemplates(templatesPath string) {
	logger.Debug(logSender, "", "loading templates from %q", templatesPath)

	passwordResetPath := filepath.Join(templatesPath, templatePasswordReset)
	pwdResetTmpl := util.LoadTemplate(nil, passwordResetPath)
	passwordExpirationPath := filepath.Join(templatesPath, templatePasswordExpiration)
	pwdExpirationTmpl := util.LoadTemplate(nil, passwordExpirationPath)

	emailTemplates[templatePasswordReset] = pwdResetTmpl
	emailTemplates[templatePasswordExpiration] = pwdExpirationTmpl
}

// RenderPasswordResetTemplate executes the password reset template
func RenderPasswordResetTemplate(buf *bytes.Buffer, data any) error {
	if !IsEnabled() {
		return errors.New("smtp: not configured")
	}
	return emailTemplates[templatePasswordReset].Execute(buf, data)
}

// RenderPasswordExpirationTemplate executes the password expiration template
func RenderPasswordExpirationTemplate(buf *bytes.Buffer, data any) error {
	if !IsEnabled() {
		return errors.New("smtp: not configured")
	}
	return emailTemplates[templatePasswordExpiration].Execute(buf, data)
}

// SendEmail tries to send an email using the specified parameters.
func SendEmail(to, bcc []string, subject, body string, contentType EmailContentType, attachments ...*mail.File) error {
	return config.sendEmail(to, bcc, subject, body, contentType, attachments...)
}

// ReloadProviderConf reloads the configuration from the provider
// and apply it if different from the active one
func ReloadProviderConf() {
	loadConfigFromProvider() //nolint:errcheck
}

func loadConfigFromProvider() error {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		logger.Error(logSender, "", "unable to load config from provider: %v", err)
		return fmt.Errorf("smtp: unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	if err := configs.SMTP.TryDecrypt(); err != nil {
		logger.Error(logSender, "", "unable to decrypt smtp config: %v", err)
		return fmt.Errorf("smtp: unable to decrypt smtp config: %w", err)
	}
	config.Set(configs.SMTP)
	return nil
}

func updateRefreshToken(token string) {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		logger.Error(logSender, "", "unable to load config from provider, updating refresh token not possible: %v", err)
		return
	}
	configs.SetNilsToEmpty()
	if configs.SMTP.IsEmpty() {
		logger.Warn(logSender, "", "unable to update refresh token, smtp not configured in the data provider")
		return
	}
	configs.SMTP.OAuth2.RefreshToken = kms.NewPlainSecret(token)
	if err := dataprovider.UpdateConfigs(&configs, dataprovider.ActionExecutorSystem, "", ""); err != nil {
		logger.Error(logSender, "", "unable to save new refresh token: %v", err)
		return
	}
	logger.Info(logSender, "", "refresh token updated")
}
