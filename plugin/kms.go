package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	sdkkms "github.com/sftpgo/sdk/kms"
	kmsplugin "github.com/sftpgo/sdk/plugin/kms"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	validKMSSchemes           = []string{sdkkms.SchemeAWS, sdkkms.SchemeGCP, sdkkms.SchemeVaultTransit, sdkkms.SchemeAzureKeyVault}
	validKMSEncryptedStatuses = []string{sdkkms.SecretStatusVaultTransit, sdkkms.SecretStatusAWS, sdkkms.SecretStatusGCP,
		sdkkms.SecretStatusAzureKeyVault}
)

// KMSConfig defines configuration parameters for kms plugins
type KMSConfig struct {
	Scheme          string `json:"scheme" mapstructure:"scheme"`
	EncryptedStatus string `json:"encrypted_status" mapstructure:"encrypted_status"`
}

func (c *KMSConfig) validate() error {
	if !util.IsStringInSlice(c.Scheme, validKMSSchemes) {
		return fmt.Errorf("invalid kms scheme: %v", c.Scheme)
	}
	if !util.IsStringInSlice(c.EncryptedStatus, validKMSEncryptedStatuses) {
		return fmt.Errorf("invalid kms encrypted status: %v", c.EncryptedStatus)
	}
	return nil
}

type kmsPlugin struct {
	config  Config
	service kmsplugin.Service
	client  *plugin.Client
}

func newKMSPlugin(config Config) (*kmsPlugin, error) {
	p := &kmsPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create kms plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *kmsPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new kms plugin %#v", p.config.Cmd)
	if err := p.config.KMSOptions.validate(); err != nil {
		return fmt.Errorf("invalid options for kms plugin %#v: %v", p.config.Cmd, err)
	}
	var secureConfig *plugin.SecureConfig
	if p.config.SHA256Sum != "" {
		secureConfig.Checksum = []byte(p.config.SHA256Sum)
		secureConfig.Hash = sha256.New()
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: kmsplugin.Handshake,
		Plugins:         kmsplugin.PluginMap,
		Cmd:             exec.Command(p.config.Cmd, p.config.Args...),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, kmsplugin.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for kms plugin %#v: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(kmsplugin.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %#v: %v",
			kmsplugin.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.service = raw.(kmsplugin.Service)

	return nil
}

func (p *kmsPlugin) exited() bool {
	return p.client.Exited()
}

func (p *kmsPlugin) cleanup() {
	p.client.Kill()
}

func (p *kmsPlugin) Encrypt(secret kms.BaseSecret, url string, masterKey string) (string, string, int32, error) {
	return p.service.Encrypt(secret.Payload, secret.AdditionalData, url, masterKey)
}

func (p *kmsPlugin) Decrypt(secret kms.BaseSecret, url string, masterKey string) (string, error) {
	return p.service.Decrypt(secret.Payload, secret.Key, secret.AdditionalData, secret.Mode, url, masterKey)
}

type kmsPluginSecretProvider struct {
	kms.BaseSecret
	URL       string
	MasterKey string
	config    *Config
}

func (s *kmsPluginSecretProvider) Name() string {
	return fmt.Sprintf("KMSPlugin_%v_%v_%v", filepath.Base(s.config.Cmd), s.config.KMSOptions.Scheme, s.config.kmsID)
}

func (s *kmsPluginSecretProvider) IsEncrypted() bool {
	return s.Status == s.config.KMSOptions.EncryptedStatus
}

func (s *kmsPluginSecretProvider) Encrypt() error {
	if s.Status != sdkkms.SecretStatusPlain {
		return kms.ErrWrongSecretStatus
	}
	if s.Payload == "" {
		return kms.ErrInvalidSecret
	}

	payload, key, mode, err := Handler.kmsEncrypt(s.BaseSecret, s.URL, s.MasterKey, s.config.kmsID)
	if err != nil {
		return err
	}
	s.Status = s.config.KMSOptions.EncryptedStatus
	s.Payload = payload
	s.Key = key
	s.Mode = int(mode)

	return nil
}

func (s *kmsPluginSecretProvider) Decrypt() error {
	if !s.IsEncrypted() {
		return kms.ErrWrongSecretStatus
	}
	payload, err := Handler.kmsDecrypt(s.BaseSecret, s.URL, s.MasterKey, s.config.kmsID)
	if err != nil {
		return err
	}
	s.Status = sdkkms.SecretStatusPlain
	s.Payload = payload
	s.Key = ""
	s.AdditionalData = ""
	s.Mode = 0

	return nil
}

func (s *kmsPluginSecretProvider) Clone() kms.SecretProvider {
	baseSecret := kms.BaseSecret{
		Status:         s.Status,
		Payload:        s.Payload,
		Key:            s.Key,
		AdditionalData: s.AdditionalData,
		Mode:           s.Mode,
	}
	return s.config.newKMSPluginSecretProvider(baseSecret, s.URL, s.MasterKey)
}
