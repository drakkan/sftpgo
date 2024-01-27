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

// Package acme provides automatic access to certificates from Let's Encrypt and any other ACME-based CA
// The code here is largely coiped from https://github.com/go-acme/lego/tree/master/cmd
// This package is intended to provide basic functionality for obtaining and renewing certificates
// and implements the "HTTP-01" and "TLSALPN-01" challenge types.
// For more advanced features use external tools such as "lego"
package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/telemetry"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

const (
	logSender = "acme"
)

var (
	config            *Configuration
	initialConfig     Configuration
	scheduler         *cron.Cron
	logMode           int
	supportedKeyTypes = []string{
		string(certcrypto.EC256),
		string(certcrypto.EC384),
		string(certcrypto.RSA2048),
		string(certcrypto.RSA3072),
		string(certcrypto.RSA4096),
		string(certcrypto.RSA8192),
	}
	fnReloadHTTPDCerts func() error
)

// SetReloadHTTPDCertsFn set the function to call to reload HTTPD certificates
func SetReloadHTTPDCertsFn(fn func() error) {
	fnReloadHTTPDCerts = fn
}

// GetCertificates tries to obtain the certificates using the global configuration
func GetCertificates() error {
	if config == nil {
		return errors.New("acme is disabled")
	}
	return config.getCertificates()
}

// GetCertificatesForConfig tries to obtain the certificates using the provided
// configuration override. This is a NOOP if we already have certificates
func GetCertificatesForConfig(c *dataprovider.ACMEConfigs, configDir string) error {
	if c.Domain == "" {
		acmeLog(logger.LevelDebug, "no domain configured, nothing to do")
		return nil
	}
	config := mergeConfig(getConfiguration(), c)
	if err := config.Initialize(configDir); err != nil {
		return err
	}
	hasCerts, err := config.hasCertificates(c.Domain)
	if err != nil {
		return fmt.Errorf("unable to check if we already have certificates for domain %q: %w", c.Domain, err)
	}
	if hasCerts {
		return nil
	}
	return config.getCertificates()
}

// GetHTTP01WebRoot returns the web root for HTTP-01 challenge
func GetHTTP01WebRoot() string {
	return initialConfig.HTTP01Challenge.WebRoot
}

func mergeConfig(config Configuration, c *dataprovider.ACMEConfigs) Configuration {
	config.Domains = []string{c.Domain}
	config.Email = c.Email
	config.HTTP01Challenge.Port = c.HTTP01Challenge.Port
	config.TLSALPN01Challenge.Port = 0
	return config
}

// getConfiguration returns the configuration set using config file and env vars
func getConfiguration() Configuration {
	return initialConfig
}

func loadProviderConf(c Configuration) (Configuration, error) {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		return c, fmt.Errorf("unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	if configs.ACME.Domain == "" {
		return c, nil
	}
	return mergeConfig(c, configs.ACME), nil
}

// Initialize validates and set the configuration
func Initialize(c Configuration, configDir string, checkRenew bool) error {
	config = nil
	initialConfig = c
	c, err := loadProviderConf(c)
	if err != nil {
		return err
	}
	util.CertsBasePath = ""
	setLogMode(checkRenew)

	if err := c.Initialize(configDir); err != nil {
		return err
	}
	if len(c.Domains) == 0 {
		return nil
	}
	util.CertsBasePath = c.CertsPath
	acmeLog(logger.LevelInfo, "configured domains: %+v, certs base path %q", c.Domains, c.CertsPath)
	config = &c
	if checkRenew {
		return startScheduler()
	}
	return nil
}

// HTTP01Challenge defines the configuration for HTTP-01 challenge type
type HTTP01Challenge struct {
	Port        int    `json:"port" mapstructure:"port"`
	WebRoot     string `json:"webroot" mapstructure:"webroot"`
	ProxyHeader string `json:"proxy_header" mapstructure:"proxy_header"`
}

func (c *HTTP01Challenge) isEnabled() bool {
	return c.Port > 0 || c.WebRoot != ""
}

func (c *HTTP01Challenge) validate() error {
	if !c.isEnabled() {
		return nil
	}
	if c.WebRoot != "" {
		if !filepath.IsAbs(c.WebRoot) {
			return fmt.Errorf("invalid HTTP-01 challenge web root, please set an absolute path")
		}
		_, err := os.Stat(c.WebRoot)
		if err != nil {
			return fmt.Errorf("invalid HTTP-01 challenge web root: %w", err)
		}
	} else {
		if c.Port > 65535 {
			return fmt.Errorf("invalid HTTP-01 challenge port: %d", c.Port)
		}
	}
	return nil
}

// TLSALPN01Challenge defines the configuration for TLSALPN-01 challenge type
type TLSALPN01Challenge struct {
	Port int `json:"port" mapstructure:"port"`
}

func (c *TLSALPN01Challenge) isEnabled() bool {
	return c.Port > 0
}

func (c *TLSALPN01Challenge) validate() error {
	if !c.isEnabled() {
		return nil
	}
	if c.Port > 65535 {
		return fmt.Errorf("invalid TLSALPN-01 challenge port: %d", c.Port)
	}
	return nil
}

// Configuration holds the ACME configuration
type Configuration struct {
	Email      string `json:"email" mapstructure:"email"`
	KeyType    string `json:"key_type" mapstructure:"key_type"`
	CertsPath  string `json:"certs_path" mapstructure:"certs_path"`
	CAEndpoint string `json:"ca_endpoint" mapstructure:"ca_endpoint"`
	// if a certificate is to be valid for multiple domains specify the names separated by commas,
	// for example: example.com,www.example.com
	Domains            []string           `json:"domains" mapstructure:"domains"`
	RenewDays          int                `json:"renew_days" mapstructure:"renew_days"`
	HTTP01Challenge    HTTP01Challenge    `json:"http01_challenge" mapstructure:"http01_challenge"`
	TLSALPN01Challenge TLSALPN01Challenge `json:"tls_alpn01_challenge" mapstructure:"tls_alpn01_challenge"`
	accountConfigPath  string
	accountKeyPath     string
	lockPath           string
	tempDir            string
}

// Initialize validates and initialize the configuration
func (c *Configuration) Initialize(configDir string) error {
	c.checkDomains()
	if len(c.Domains) == 0 {
		acmeLog(logger.LevelInfo, "no domains configured, acme disabled")
		return nil
	}
	if c.Email == "" || !util.IsEmailValid(c.Email) {
		return util.NewI18nError(
			fmt.Errorf("invalid email address %q", c.Email),
			util.I18nErrorInvalidEmail,
		)
	}
	if c.RenewDays < 1 {
		return fmt.Errorf("invalid number of days remaining before renewal: %d", c.RenewDays)
	}
	if !util.Contains(supportedKeyTypes, c.KeyType) {
		return fmt.Errorf("invalid key type %q", c.KeyType)
	}
	caURL, err := url.Parse(c.CAEndpoint)
	if err != nil {
		return fmt.Errorf("invalid CA endopoint: %w", err)
	}
	if !util.IsFileInputValid(c.CertsPath) {
		return fmt.Errorf("invalid certs path %q", c.CertsPath)
	}
	if !filepath.IsAbs(c.CertsPath) {
		c.CertsPath = filepath.Join(configDir, c.CertsPath)
	}
	err = os.MkdirAll(c.CertsPath, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certs path %q: %w", c.CertsPath, err)
	}
	c.tempDir = filepath.Join(c.CertsPath, "temp")
	err = os.MkdirAll(c.CertsPath, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certs temp path %q: %w", c.tempDir, err)
	}
	serverPath := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(caURL.Host)
	accountPath := filepath.Join(c.CertsPath, serverPath)
	err = os.MkdirAll(accountPath, 0700)
	if err != nil {
		return fmt.Errorf("unable to create account path %q: %w", accountPath, err)
	}
	c.accountConfigPath = filepath.Join(accountPath, c.Email+".json")
	c.accountKeyPath = filepath.Join(accountPath, c.Email+".key")
	c.lockPath = filepath.Join(c.CertsPath, "lock")

	return c.validateChallenges()
}

func (c *Configuration) validateChallenges() error {
	if !c.HTTP01Challenge.isEnabled() && !c.TLSALPN01Challenge.isEnabled() {
		return fmt.Errorf("no challenge type defined")
	}
	if err := c.HTTP01Challenge.validate(); err != nil {
		return err
	}
	return c.TLSALPN01Challenge.validate()
}

func (c *Configuration) checkDomains() {
	var domains []string
	for _, domain := range c.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if d, ok := isDomainValid(domain); ok {
			domains = append(domains, d)
		}
	}
	c.Domains = util.RemoveDuplicates(domains, true)
}

func (c *Configuration) setLockTime() error {
	lockTime := fmt.Sprintf("%v", util.GetTimeAsMsSinceEpoch(time.Now()))
	err := os.WriteFile(c.lockPath, []byte(lockTime), 0600)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save lock time to %q: %v", c.lockPath, err)
		return fmt.Errorf("unable to save lock time: %w", err)
	}
	acmeLog(logger.LevelDebug, "lock time saved: %q", lockTime)
	return nil
}

func (c *Configuration) getLockTime() (time.Time, error) {
	content, err := os.ReadFile(c.lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			acmeLog(logger.LevelDebug, "lock file %q not found", c.lockPath)
			return time.Time{}, nil
		}
		acmeLog(logger.LevelError, "unable to read lock file %q: %v", c.lockPath, err)
		return time.Time{}, err
	}
	msec, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		acmeLog(logger.LevelError, "unable to parse lock time: %v", err)
		return time.Time{}, fmt.Errorf("unable to parse lock time: %w", err)
	}
	return util.GetTimeFromMsecSinceEpoch(msec), nil
}

func (c *Configuration) saveAccount(account *account) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}
	err = os.WriteFile(c.accountConfigPath, jsonBytes, 0600)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save account to file %q: %v", c.accountConfigPath, err)
		return fmt.Errorf("unable to save account: %w", err)
	}
	return nil
}

func (c *Configuration) getAccount(privateKey crypto.PrivateKey) (account, error) {
	_, err := os.Stat(c.accountConfigPath)
	if err != nil && os.IsNotExist(err) {
		acmeLog(logger.LevelDebug, "account does not exist")
		return account{Email: c.Email, key: privateKey}, nil
	}
	var account account
	fileBytes, err := os.ReadFile(c.accountConfigPath)
	if err != nil {
		acmeLog(logger.LevelError, "unable to read account from file %q: %v", c.accountConfigPath, err)
		return account, fmt.Errorf("unable to read account from file: %w", err)
	}
	err = json.Unmarshal(fileBytes, &account)
	if err != nil {
		acmeLog(logger.LevelError, "invalid account file content: %v", err)
		return account, fmt.Errorf("unable to parse account file as JSON: %w", err)
	}
	account.key = privateKey
	if account.Registration == nil || account.Registration.Body.Status == "" {
		acmeLog(logger.LevelInfo, "couldn't load account but got a key. Try to look the account up")
		reg, err := c.tryRecoverRegistration(privateKey)
		if err != nil {
			acmeLog(logger.LevelError, "unable to look the account up: %v", err)
			return account, fmt.Errorf("unable to look the account up: %w", err)
		}
		account.Registration = reg
		err = c.saveAccount(&account)
		if err != nil {
			return account, err
		}
	}

	return account, nil
}

func (c *Configuration) loadPrivateKey() (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(c.accountKeyPath)
	if err != nil {
		acmeLog(logger.LevelError, "unable to read account key from file %q: %v", c.accountKeyPath, err)
		return nil, fmt.Errorf("unable to read account key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		acmeLog(logger.LevelError, "unable to parse private key from file %q: pem decoding failed", c.accountKeyPath)
		return nil, errors.New("pem decoding failed")
	}

	var privateKey crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		err = fmt.Errorf("unknown private key type %q", keyBlock.Type)
	}
	if err != nil {
		acmeLog(logger.LevelError, "unable to parse private key from file %q: %v", c.accountKeyPath, err)
		return privateKey, fmt.Errorf("unable to parse private key: %w", err)
	}
	return privateKey, nil
}

func (c *Configuration) generatePrivateKey() (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.KeyType(c.KeyType))
	if err != nil {
		acmeLog(logger.LevelError, "unable to generate private key: %v", err)
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}
	certOut, err := os.Create(c.accountKeyPath)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save private key to file %q: %v", c.accountKeyPath, err)
		return nil, fmt.Errorf("unable to save private key: %w", err)
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		acmeLog(logger.LevelError, "unable to encode private key: %v", err)
		return nil, fmt.Errorf("unable to encode private key: %w", err)
	}
	acmeLog(logger.LevelDebug, "new account private key generated")

	return privateKey, nil
}

func (c *Configuration) getPrivateKey() (crypto.PrivateKey, error) {
	_, err := os.Stat(c.accountKeyPath)
	if err != nil && os.IsNotExist(err) {
		acmeLog(logger.LevelDebug, "private key file %q does not exist, generating new private key", c.accountKeyPath)
		return c.generatePrivateKey()
	}
	acmeLog(logger.LevelDebug, "loading private key from file %q, stat error: %v", c.accountKeyPath, err)
	return c.loadPrivateKey()
}

func (c *Configuration) loadCertificatesForDomain(domain string) ([]*x509.Certificate, error) {
	domain = util.SanitizeDomain(domain)
	acmeLog(logger.LevelDebug, "loading certificates for domain %q", domain)
	content, err := os.ReadFile(filepath.Join(c.CertsPath, domain+".crt"))
	if err != nil {
		acmeLog(logger.LevelError, "unable to load certificates for domain %q: %v", domain, err)
		return nil, fmt.Errorf("unable to load certificates for domain %q: %w", domain, err)
	}
	certs, err := certcrypto.ParsePEMBundle(content)
	if err != nil {
		acmeLog(logger.LevelError, "unable to parse certificates for domain %q: %v", domain, err)
		return certs, fmt.Errorf("unable to parse certificates for domain %q: %w", domain, err)
	}
	return certs, nil
}

func (c *Configuration) needRenewal(x509Cert *x509.Certificate, domain string) bool {
	if x509Cert.IsCA {
		acmeLog(logger.LevelError, "certificate bundle starts with a CA certificate, cannot renew domain %v", domain)
		return false
	}
	notAfter := int(time.Until(x509Cert.NotAfter).Hours() / 24.0)
	if notAfter > c.RenewDays {
		acmeLog(logger.LevelDebug, "the certificate for domain %q expires in %d days, no renewal", domain, notAfter)
		return false
	}
	return true
}

func (c *Configuration) setup() (*account, *lego.Client, error) {
	privateKey, err := c.getPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	account, err := c.getAccount(privateKey)
	if err != nil {
		return nil, nil, err
	}
	config := lego.NewConfig(&account)
	config.CADirURL = c.CAEndpoint
	config.Certificate.KeyType = certcrypto.KeyType(c.KeyType)
	config.UserAgent = fmt.Sprintf("SFTPGo/%v", version.Get().Version)
	client, err := lego.NewClient(config)
	if err != nil {
		acmeLog(logger.LevelError, "unable to get ACME client: %v", err)
		return nil, nil, fmt.Errorf("unable to get ACME client: %w", err)
	}
	err = c.setupChalleges(client)
	if err != nil {
		return nil, nil, err
	}
	return &account, client, nil
}

func (c *Configuration) setupChalleges(client *lego.Client) error {
	client.Challenge.Remove(challenge.DNS01)
	if c.HTTP01Challenge.isEnabled() {
		if c.HTTP01Challenge.WebRoot != "" {
			acmeLog(logger.LevelDebug, "configuring HTTP-01 web root challenge, path %q", c.HTTP01Challenge.WebRoot)
			providerServer, err := webroot.NewHTTPProvider(c.HTTP01Challenge.WebRoot)
			if err != nil {
				acmeLog(logger.LevelError, "unable to create HTTP-01 web root challenge provider from path %q: %v",
					c.HTTP01Challenge.WebRoot, err)
				return fmt.Errorf("unable to create HTTP-01 web root challenge provider: %w", err)
			}
			err = client.Challenge.SetHTTP01Provider(providerServer)
			if err != nil {
				acmeLog(logger.LevelError, "unable to set HTTP-01 challenge provider: %v", err)
				return fmt.Errorf("unable to set HTTP-01 challenge provider: %w", err)
			}
		} else {
			acmeLog(logger.LevelDebug, "configuring HTTP-01 challenge, port %d", c.HTTP01Challenge.Port)
			providerServer := http01.NewProviderServer("", fmt.Sprintf("%d", c.HTTP01Challenge.Port))
			if c.HTTP01Challenge.ProxyHeader != "" {
				acmeLog(logger.LevelDebug, "setting proxy header to \"%s\"", c.HTTP01Challenge.ProxyHeader)
				providerServer.SetProxyHeader(c.HTTP01Challenge.ProxyHeader)
			}
			err := client.Challenge.SetHTTP01Provider(providerServer)
			if err != nil {
				acmeLog(logger.LevelError, "unable to set HTTP-01 challenge provider: %v", err)
				return fmt.Errorf("unable to set HTTP-01 challenge provider: %w", err)
			}
		}
	} else {
		client.Challenge.Remove(challenge.HTTP01)
	}
	if c.TLSALPN01Challenge.isEnabled() {
		acmeLog(logger.LevelDebug, "configuring TLSALPN-01 challenge, port %d", c.TLSALPN01Challenge.Port)
		err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", fmt.Sprintf("%d", c.TLSALPN01Challenge.Port)))
		if err != nil {
			acmeLog(logger.LevelError, "unable to set TLSALPN-01 challenge provider: %v", err)
			return fmt.Errorf("unable to set TLSALPN-01 challenge provider: %w", err)
		}
	} else {
		client.Challenge.Remove(challenge.TLSALPN01)
	}

	return nil
}

func (c *Configuration) register(client *lego.Client) (*registration.Resource, error) {
	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func (c *Configuration) tryRecoverRegistration(privateKey crypto.PrivateKey) (*registration.Resource, error) {
	config := lego.NewConfig(&account{key: privateKey})
	config.CADirURL = c.CAEndpoint
	config.UserAgent = fmt.Sprintf("SFTPGo/%v", version.Get().Version)

	client, err := lego.NewClient(config)
	if err != nil {
		acmeLog(logger.LevelError, "unable to get the ACME client: %v", err)
		return nil, err
	}

	return client.Registration.ResolveAccountByKey()
}

func (c *Configuration) getCrtPath(domain string) string {
	return filepath.Join(c.CertsPath, domain+".crt")
}

func (c *Configuration) getKeyPath(domain string) string {
	return filepath.Join(c.CertsPath, domain+".key")
}

func (c *Configuration) getResourcePath(domain string) string {
	return filepath.Join(c.CertsPath, domain+".json")
}

func (c *Configuration) obtainAndSaveCertificate(client *lego.Client, domain string) error {
	domains := getDomains(domain)
	acmeLog(logger.LevelInfo, "requesting certificates for domains %+v", domains)
	request := certificate.ObtainRequest{
		Domains:                        domains,
		Bundle:                         true,
		MustStaple:                     false,
		PreferredChain:                 "",
		AlwaysDeactivateAuthorizations: false,
	}
	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		acmeLog(logger.LevelError, "unable to obtain certificates for domains %+v: %v", domains, err)
		return fmt.Errorf("unable to obtain certificates: %w", err)
	}
	domain = util.SanitizeDomain(domain)
	err = os.WriteFile(c.getCrtPath(domain), cert.Certificate, 0600)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save certificate for domain %s: %v", domain, err)
		return fmt.Errorf("unable to save certificate: %w", err)
	}
	err = os.WriteFile(c.getKeyPath(domain), cert.PrivateKey, 0600)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save private key for domain %s: %v", domain, err)
		return fmt.Errorf("unable to save private key: %w", err)
	}
	jsonBytes, err := json.MarshalIndent(cert, "", "\t")
	if err != nil {
		acmeLog(logger.LevelError, "unable to marshal certificate resources for domain %v: %v", domain, err)
		return err
	}
	err = os.WriteFile(c.getResourcePath(domain), jsonBytes, 0600)
	if err != nil {
		acmeLog(logger.LevelError, "unable to save certificate resources for domain %v: %v", domain, err)
		return fmt.Errorf("unable to save certificate resources: %w", err)
	}

	acmeLog(logger.LevelInfo, "certificates for domains %+v saved", domains)
	return nil
}

// hasCertificates returns true if certificates for the specified domain has already been issued
func (c *Configuration) hasCertificates(domain string) (bool, error) {
	domain = util.SanitizeDomain(domain)
	if _, err := os.Stat(c.getCrtPath(domain)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := os.Stat(c.getKeyPath(domain)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// getCertificates tries to obtain the certificates for the configured domains
func (c *Configuration) getCertificates() error {
	account, client, err := c.setup()
	if err != nil {
		return err
	}
	if account.Registration == nil {
		reg, err := c.register(client)
		if err != nil {
			acmeLog(logger.LevelError, "unable to register account: %v", err)
			return fmt.Errorf("unable to register account: %w", err)
		}
		account.Registration = reg
		err = c.saveAccount(account)
		if err != nil {
			return err
		}
	}
	for _, domain := range c.Domains {
		err = c.obtainAndSaveCertificate(client, domain)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Configuration) notifyCertificateRenewal(domain string, err error) {
	if domain == "" {
		domain = strings.Join(c.Domains, ",")
	}
	params := common.EventParams{
		Name:      domain,
		Event:     "Certificate renewal",
		Timestamp: time.Now().UnixNano(),
	}
	if err != nil {
		params.Status = 2
		params.AddError(err)
	} else {
		params.Status = 1
	}
	common.HandleCertificateEvent(params)
}

func (c *Configuration) renewCertificates() error {
	lockTime, err := c.getLockTime()
	if err != nil {
		return err
	}
	acmeLog(logger.LevelDebug, "certificate renew lock time %v", lockTime)
	if lockTime.Add(-30*time.Second).Before(time.Now()) && lockTime.Add(5*time.Minute).After(time.Now()) {
		acmeLog(logger.LevelInfo, "certificate renew skipped, lock time too close: %v", lockTime)
		return nil
	}
	err = c.setLockTime()
	if err != nil {
		c.notifyCertificateRenewal("", err)
		return err
	}
	account, client, err := c.setup()
	if err != nil {
		c.notifyCertificateRenewal("", err)
		return err
	}
	if account.Registration == nil {
		acmeLog(logger.LevelError, "cannot renew certificates, your account is not registered")
		err = errors.New("cannot renew certificates, your account is not registered")
		c.notifyCertificateRenewal("", err)
		return err
	}
	var errRenew error
	needReload := false
	for _, domain := range c.Domains {
		certificates, err := c.loadCertificatesForDomain(domain)
		if err != nil {
			c.notifyCertificateRenewal(domain, err)
			errRenew = err
			continue
		}
		cert := certificates[0]
		if !c.needRenewal(cert, domain) {
			continue
		}
		err = c.obtainAndSaveCertificate(client, domain)
		if err != nil {
			c.notifyCertificateRenewal(domain, err)
			errRenew = err
		} else {
			c.notifyCertificateRenewal(domain, nil)
			needReload = true
		}
	}
	if needReload {
		// at least one certificate has been renewed, sends a reload to all services that may be using certificates
		err = ftpd.ReloadCertificateMgr()
		acmeLog(logger.LevelInfo, "ftpd certificate manager reloaded , error: %v", err)
		if fnReloadHTTPDCerts != nil {
			err = fnReloadHTTPDCerts()
			acmeLog(logger.LevelInfo, "httpd certificates manager reloaded , error: %v", err)
		}
		err = webdavd.ReloadCertificateMgr()
		acmeLog(logger.LevelInfo, "webdav certificates manager reloaded , error: %v", err)
		err = telemetry.ReloadCertificateMgr()
		acmeLog(logger.LevelInfo, "telemetry certificates manager reloaded , error: %v", err)
	}

	return errRenew
}

func isDomainValid(domain string) (string, bool) {
	isValid := false
	for _, d := range strings.Split(domain, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			isValid = true
			break
		}
	}
	return domain, isValid
}

func getDomains(domain string) []string {
	var domains []string

	delimiter := ","
	if !strings.Contains(domain, ",") && strings.Contains(domain, " ") {
		delimiter = " "
	}

	for _, d := range strings.Split(domain, delimiter) {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}
	return util.RemoveDuplicates(domains, false)
}

func stopScheduler() {
	if scheduler != nil {
		scheduler.Stop()
		scheduler = nil
	}
}

func startScheduler() error {
	stopScheduler()

	randSecs := rand.Intn(59)
	scheduler = cron.New(cron.WithLocation(time.UTC), cron.WithLogger(cron.DiscardLogger))
	_, err := scheduler.AddFunc(fmt.Sprintf("@every 12h0m%ds", randSecs), renewCertificates)
	if err != nil {
		return fmt.Errorf("unable to schedule certificates renewal: %w", err)
	}

	acmeLog(logger.LevelInfo, "starting scheduler, initial certificates check in %d seconds", randSecs)
	initialTimer := time.NewTimer(time.Duration(randSecs) * time.Second)
	go func() {
		<-initialTimer.C
		renewCertificates()
	}()

	scheduler.Start()
	return nil
}

func renewCertificates() {
	if config != nil {
		if err := config.renewCertificates(); err != nil {
			acmeLog(logger.LevelError, "unable to renew certificates: %v", err)
		}
	}
}

func setLogMode(checkRenew bool) {
	if checkRenew {
		logMode = 1
	} else {
		logMode = 2
	}
	log.Logger = &logger.LegoAdapter{
		LogToConsole: logMode != 1,
	}
}

func acmeLog(level logger.LogLevel, format string, v ...any) {
	if logMode == 1 {
		logger.Log(level, logSender, "", format, v...)
	} else {
		switch level {
		case logger.LevelDebug:
			logger.DebugToConsole(format, v...)
		case logger.LevelInfo:
			logger.InfoToConsole(format, v...)
		case logger.LevelWarn:
			logger.WarnToConsole(format, v...)
		default:
			logger.ErrorToConsole(format, v...)
		}
	}
}
