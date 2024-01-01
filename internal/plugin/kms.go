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

package plugin

import (
	"fmt"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	sdkkms "github.com/sftpgo/sdk/kms"
	kmsplugin "github.com/sftpgo/sdk/plugin/kms"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
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
	if !util.Contains(validKMSSchemes, c.Scheme) {
		return fmt.Errorf("invalid kms scheme: %v", c.Scheme)
	}
	if !util.Contains(validKMSEncryptedStatuses, c.EncryptedStatus) {
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
	logger.Debug(logSender, "", "create new kms plugin %q", p.config.Cmd)
	if err := p.config.KMSOptions.validate(); err != nil {
		return fmt.Errorf("invalid options for kms plugin %q: %v", p.config.Cmd, err)
	}
	secureConfig, err := p.config.getSecureConfig()
	if err != nil {
		return err
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: kmsplugin.Handshake,
		Plugins:         kmsplugin.PluginMap,
		Cmd:             p.config.getCommand(),
		SkipHostEnv:     true,
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
		logger.Debug(logSender, "", "unable to get rpc client for kms plugin %q: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(kmsplugin.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %q: %v",
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
