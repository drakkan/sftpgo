// Package smtp provides supports for sending emails
package smtp

import (
	"errors"
	"fmt"
	"time"

	mail "github.com/xhit/go-simple-mail/v2"

	"github.com/drakkan/sftpgo/v2/logger"
)

const (
	logSender = "smtp"
)

// EmailContentType defines the support content types for email body
type EmailContentType int

// Supporte email body content type
const (
	EmailContentTypeTextPlain EmailContentType = iota
	EmailContentTypeTextHTML
)

var (
	smtpServer *mail.SMTPServer
	from       string
)

// Config defines the SMTP configuration to use to send emails
type Config struct {
	// Location of SMTP email server. Leavy empty to disable email sending capabilities
	Host string `json:"host" mapstructure:"host"`
	// Port of SMTP email server
	Port int `json:"port" mapstructure:"port"`
	// From address, for example "SFTPGo <sftpgo@example.com>"
	From string `json:"from" mapstructure:"from"`
	// SMTP username
	User string `json:"user" mapstructure:"user"`
	// SMTP password. Leaving both username and password empty the SMTP authentication
	// will be disabled
	Password string `json:"password" mapstructure:"password"`
	// 0 Plain
	// 1 Login
	// 2 CRAM-MD5
	AuthType int `json:"auth_type" mapstructure:"auth_type"`
	// 0 no encryption
	// 1 TLS
	// 2 start TLS
	Encryption int `json:"encryption" mapstructure:"encryption"`
	// Domain to use for HELO command, if empty localhost will be used
	Domain string `json:"domain" mapstructure:"domain"`
}

// Initialize initialized and validates the SMTP configuration
func (c *Config) Initialize() error {
	smtpServer = nil
	if c.Host == "" {
		logger.Debug(logSender, "", "configuration disabled, email capabilities will not be available")
		return nil
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("smtp: invalid port %v", c.Port)
	}
	if c.AuthType < 0 || c.AuthType > 2 {
		return fmt.Errorf("smtp: invalid auth type %v", c.AuthType)
	}
	if c.Encryption < 0 || c.Encryption > 2 {
		return fmt.Errorf("smtp: invalid encryption %v", c.Encryption)
	}
	from = c.From
	smtpServer = mail.NewSMTPClient()
	smtpServer.Host = c.Host
	smtpServer.Port = c.Port
	smtpServer.Username = c.User
	smtpServer.Password = c.Password
	smtpServer.Authentication = c.getAuthType()
	smtpServer.Encryption = c.getEncryption()
	smtpServer.KeepAlive = false
	smtpServer.ConnectTimeout = 10 * time.Second
	smtpServer.SendTimeout = 30 * time.Second
	if c.Domain != "" {
		smtpServer.Helo = c.Domain
	}
	logger.Debug(logSender, "", "configuration successfully initialized, host: %#v, port: %v, username: %#v, auth: %v, encryption: %v, helo: %#v",
		smtpServer.Host, smtpServer.Port, smtpServer.Username, smtpServer.Authentication, smtpServer.Encryption, smtpServer.Helo)
	return nil
}

func (c *Config) getEncryption() mail.Encryption {
	switch c.Encryption {
	case 1:
		return mail.EncryptionSSLTLS
	case 2:
		return mail.EncryptionSTARTTLS
	default:
		return mail.EncryptionNone
	}
}

func (c *Config) getAuthType() mail.AuthType {
	if c.User == "" && c.Password == "" {
		return mail.AuthNone
	}
	switch c.AuthType {
	case 1:
		return mail.AuthLogin
	case 2:
		return mail.AuthCRAMMD5
	default:
		return mail.AuthPlain
	}
}

// SendEmail tries to send an email using the specified parameters.
func SendEmail(to, subject, body string, contentType EmailContentType) error {
	if smtpServer == nil {
		return errors.New("smtp: not configured")
	}
	smtpClient, err := smtpServer.Connect()
	if err != nil {
		return fmt.Errorf("smtp: unable to connect: %w", err)
	}

	email := mail.NewMSG()
	if from != "" {
		email.SetFrom(from)
	}
	email.AddTo(to).SetSubject(subject)
	switch contentType {
	case EmailContentTypeTextPlain:
		email.SetBody(mail.TextPlain, body)
	case EmailContentTypeTextHTML:
		email.SetBody(mail.TextHTML, body)
	default:
		return fmt.Errorf("smtp: unsupported body content type %v", contentType)
	}
	if email.Error != nil {
		return fmt.Errorf("smtp: email error: %w", email.Error)
	}
	return email.Send(smtpClient)
}
