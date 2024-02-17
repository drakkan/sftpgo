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

// Package plugin provides support for the SFTPGo plugin system
package plugin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/auth"
	"github.com/sftpgo/sdk/plugin/eventsearcher"
	"github.com/sftpgo/sdk/plugin/ipfilter"
	kmsplugin "github.com/sftpgo/sdk/plugin/kms"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	logSender = "plugins"
)

var (
	// Handler defines the plugins manager
	Handler         Manager
	pluginsLogLevel = hclog.Debug
	// ErrNoSearcher defines the error to return for events searches if no plugin is configured
	ErrNoSearcher = errors.New("no events searcher plugin defined")
)

// Renderer defines the interface for generic objects rendering
type Renderer interface {
	RenderAsJSON(reload bool) ([]byte, error)
}

// Config defines a plugin configuration
type Config struct {
	// Plugin type
	Type string `json:"type" mapstructure:"type"`
	// NotifierOptions defines options for notifiers plugins
	NotifierOptions NotifierConfig `json:"notifier_options" mapstructure:"notifier_options"`
	// KMSOptions defines options for a KMS plugin
	KMSOptions KMSConfig `json:"kms_options" mapstructure:"kms_options"`
	// AuthOptions defines options for authentication plugins
	AuthOptions AuthConfig `json:"auth_options" mapstructure:"auth_options"`
	// Path to the plugin executable
	Cmd string `json:"cmd" mapstructure:"cmd"`
	// Args to pass to the plugin executable
	Args []string `json:"args" mapstructure:"args"`
	// SHA256 checksum for the plugin executable.
	// If not empty it will be used to verify the integrity of the executable
	SHA256Sum string `json:"sha256sum" mapstructure:"sha256sum"`
	// If enabled the client and the server automatically negotiate mTLS for
	// transport authentication. This ensures that only the original client will
	// be allowed to connect to the server, and all other connections will be
	// rejected. The client will also refuse to connect to any server that isn't
	// the original instance started by the client.
	AutoMTLS bool `json:"auto_mtls" mapstructure:"auto_mtls"`
	// EnvPrefix defines the prefix for env vars to pass from the SFTPGo process
	// environment to the plugin. Set to "none" to not pass any environment
	// variable, set to "*" to pass all environment variables. If empty, the
	// prefix is returned as the plugin name in uppercase with "-" replaced with
	// "_" and a trailing "_". For example if the plugin name is
	// sftpgo-plugin-eventsearch the prefix will be SFTPGO_PLUGIN_EVENTSEARCH_
	EnvPrefix string `json:"env_prefix" mapstructure:"env_prefix"`
	// Additional environment variable names to pass from the SFTPGo process
	// environment to the plugin.
	EnvVars []string `json:"env_vars" mapstructure:"env_vars"`
	// unique identifier for kms plugins
	kmsID int
}

func (c *Config) getSecureConfig() (*plugin.SecureConfig, error) {
	if c.SHA256Sum != "" {
		checksum, err := hex.DecodeString(c.SHA256Sum)
		if err != nil {
			return nil, fmt.Errorf("invalid sha256 hash %q: %w", c.SHA256Sum, err)
		}
		return &plugin.SecureConfig{
			Checksum: checksum,
			Hash:     sha256.New(),
		}, nil
	}
	return nil, nil
}

func (c *Config) getEnvVarPrefix() string {
	if c.EnvPrefix == "none" {
		return ""
	}
	if c.EnvPrefix != "" {
		return c.EnvPrefix
	}

	prefix := strings.ToUpper(filepath.Base(c.Cmd)) + "_"
	return strings.ReplaceAll(prefix, "-", "_")
}

func (c *Config) getCommand() *exec.Cmd {
	cmd := exec.Command(c.Cmd, c.Args...)
	cmd.Env = []string{}

	if envVarPrefix := c.getEnvVarPrefix(); envVarPrefix != "" {
		if envVarPrefix == "*" {
			logger.Debug(logSender, "", "sharing all the environment variables with plugin %q", c.Cmd)
			cmd.Env = append(cmd.Env, os.Environ()...)
			return cmd
		}
		logger.Debug(logSender, "", "adding env vars with prefix %q for plugin %q", envVarPrefix, c.Cmd)
		for _, val := range os.Environ() {
			if strings.HasPrefix(val, envVarPrefix) {
				cmd.Env = append(cmd.Env, val)
			}
		}
	}
	logger.Debug(logSender, "", "additional env vars for plugin %q: %+v", c.Cmd, c.EnvVars)
	for _, key := range c.EnvVars {
		cmd.Env = append(cmd.Env, os.Getenv(key))
	}
	return cmd
}

func (c *Config) newKMSPluginSecretProvider(base kms.BaseSecret, url, masterKey string) kms.SecretProvider {
	return &kmsPluginSecretProvider{
		BaseSecret: base,
		URL:        url,
		MasterKey:  masterKey,
		config:     c,
	}
}

// Manager handles enabled plugins
type Manager struct {
	closed atomic.Bool
	done   chan bool
	// List of configured plugins
	Configs          []Config `json:"plugins" mapstructure:"plugins"`
	notifLock        sync.RWMutex
	notifiers        []*notifierPlugin
	kmsLock          sync.RWMutex
	kms              []*kmsPlugin
	authLock         sync.RWMutex
	auths            []*authPlugin
	searcherLock     sync.RWMutex
	searcher         *searcherPlugin
	ipFilterLock     sync.RWMutex
	filter           *ipFilterPlugin
	authScopes       int
	hasSearcher      bool
	hasNotifiers     bool
	hasAuths         bool
	hasIPFilter      bool
	concurrencyGuard chan struct{}
}

// Initialize initializes the configured plugins
func Initialize(configs []Config, logLevel string) error {
	logger.Debug(logSender, "", "initialize")
	Handler = Manager{
		Configs:          configs,
		done:             make(chan bool),
		authScopes:       -1,
		concurrencyGuard: make(chan struct{}, 250),
	}
	Handler.closed.Store(false)
	setLogLevel(logLevel)
	if len(configs) == 0 {
		return nil
	}

	if err := Handler.validateConfigs(); err != nil {
		return err
	}
	if err := initializePlugins(); err != nil {
		return err
	}

	startCheckTicker()
	return nil
}

func initializePlugins() error {
	kmsID := 0
	for idx, config := range Handler.Configs {
		switch config.Type {
		case notifier.PluginName:
			plugin, err := newNotifierPlugin(config)
			if err != nil {
				return err
			}
			Handler.notifiers = append(Handler.notifiers, plugin)
		case kmsplugin.PluginName:
			plugin, err := newKMSPlugin(config)
			if err != nil {
				return err
			}
			Handler.kms = append(Handler.kms, plugin)
			Handler.Configs[idx].kmsID = kmsID
			kmsID++
			kms.RegisterSecretProvider(config.KMSOptions.Scheme, config.KMSOptions.EncryptedStatus,
				Handler.Configs[idx].newKMSPluginSecretProvider)
			logger.Info(logSender, "", "registered secret provider for scheme: %v, encrypted status: %v",
				config.KMSOptions.Scheme, config.KMSOptions.EncryptedStatus)
		case auth.PluginName:
			plugin, err := newAuthPlugin(config)
			if err != nil {
				return err
			}
			Handler.auths = append(Handler.auths, plugin)
			if Handler.authScopes == -1 {
				Handler.authScopes = config.AuthOptions.Scope
			} else {
				Handler.authScopes |= config.AuthOptions.Scope
			}
		case eventsearcher.PluginName:
			plugin, err := newSearcherPlugin(config)
			if err != nil {
				return err
			}
			Handler.searcher = plugin
		case ipfilter.PluginName:
			plugin, err := newIPFilterPlugin(config)
			if err != nil {
				return err
			}
			Handler.filter = plugin
		default:
			return fmt.Errorf("unsupported plugin type: %v", config.Type)
		}
	}

	return nil
}

func (m *Manager) validateConfigs() error {
	kmsSchemes := make(map[string]bool)
	kmsEncryptions := make(map[string]bool)
	m.hasSearcher = false
	m.hasNotifiers = false
	m.hasAuths = false
	m.hasIPFilter = false

	for _, config := range m.Configs {
		switch config.Type {
		case kmsplugin.PluginName:
			if _, ok := kmsSchemes[config.KMSOptions.Scheme]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated scheme %q", config.KMSOptions.Scheme)
			}
			if _, ok := kmsEncryptions[config.KMSOptions.EncryptedStatus]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated encrypted status %q", config.KMSOptions.EncryptedStatus)
			}
			kmsSchemes[config.KMSOptions.Scheme] = true
			kmsEncryptions[config.KMSOptions.EncryptedStatus] = true
		case eventsearcher.PluginName:
			if m.hasSearcher {
				return errors.New("only one eventsearcher plugin can be defined")
			}
			m.hasSearcher = true
		case notifier.PluginName:
			m.hasNotifiers = true
		case auth.PluginName:
			m.hasAuths = true
		case ipfilter.PluginName:
			m.hasIPFilter = true
		}
	}
	return nil
}

// HasAuthenticators returns true if there is at least an auth plugin
func (m *Manager) HasAuthenticators() bool {
	return m.hasAuths
}

// HasNotifiers returns true if there is at least a notifier plugin
func (m *Manager) HasNotifiers() bool {
	return m.hasNotifiers
}

// NotifyFsEvent sends the fs event notifications using any defined notifier plugins
func (m *Manager) NotifyFsEvent(event *notifier.FsEvent) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyFsAction(event)
	}
}

// NotifyProviderEvent sends the provider event notifications using any defined notifier plugins
func (m *Manager) NotifyProviderEvent(event *notifier.ProviderEvent, object Renderer) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyProviderAction(event, object)
	}
}

// NotifyLogEvent sends the log event notifications using any defined notifier plugins
func (m *Manager) NotifyLogEvent(event notifier.LogEventType, protocol, username, ip, role string, err error) {
	if !m.hasNotifiers {
		return
	}
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	e := &notifier.LogEvent{
		Timestamp: time.Now().UnixNano(),
		Event:     event,
		Protocol:  protocol,
		Username:  username,
		IP:        ip,
		Message:   err.Error(),
		Role:      role,
	}

	for _, n := range m.notifiers {
		n.notifyLogEvent(e)
	}
}

// HasSearcher returns true if an event searcher plugin is defined
func (m *Manager) HasSearcher() bool {
	return m.hasSearcher
}

// SearchFsEvents returns the filesystem events matching the specified filters
func (m *Manager) SearchFsEvents(searchFilters *eventsearcher.FsEventSearch) ([]byte, error) {
	if !m.hasSearcher {
		return nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchFsEvents(searchFilters)
}

// SearchProviderEvents returns the provider events matching the specified filters
func (m *Manager) SearchProviderEvents(searchFilters *eventsearcher.ProviderEventSearch) ([]byte, error) {
	if !m.hasSearcher {
		return nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchProviderEvents(searchFilters)
}

// SearchLogEvents returns the log events matching the specified filters
func (m *Manager) SearchLogEvents(searchFilters *eventsearcher.LogEventSearch) ([]byte, error) {
	if !m.hasSearcher {
		return nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchLogEvents(searchFilters)
}

// IsIPBanned returns true if the IP filter plugin does not allow the specified ip.
// If no IP filter plugin is defined this method returns false
func (m *Manager) IsIPBanned(ip, protocol string) bool {
	if !m.hasIPFilter {
		return false
	}

	m.ipFilterLock.RLock()
	plugin := m.filter
	m.ipFilterLock.RUnlock()

	if plugin.exited() {
		logger.Warn(logSender, "", "ip filter plugin is not active, cannot check ip %q", ip)
		return false
	}

	return plugin.filter.CheckIP(ip, protocol) != nil
}

// ReloadFilter sends a reload request to the IP filter plugin
func (m *Manager) ReloadFilter() {
	if !m.hasIPFilter {
		return
	}
	m.ipFilterLock.RLock()
	plugin := m.filter
	m.ipFilterLock.RUnlock()

	if err := plugin.filter.Reload(); err != nil {
		logger.Error(logSender, "", "unable to reload IP filter plugin: %v", err)
	}
}

func (m *Manager) kmsEncrypt(secret kms.BaseSecret, url string, masterKey string, kmsID int) (string, string, int32, error) {
	m.kmsLock.RLock()
	plugin := m.kms[kmsID]
	m.kmsLock.RUnlock()

	return plugin.Encrypt(secret, url, masterKey)
}

func (m *Manager) kmsDecrypt(secret kms.BaseSecret, url string, masterKey string, kmsID int) (string, error) {
	m.kmsLock.RLock()
	plugin := m.kms[kmsID]
	m.kmsLock.RUnlock()

	return plugin.Decrypt(secret, url, masterKey)
}

// HasAuthScope returns true if there is an auth plugin that support the specified scope
func (m *Manager) HasAuthScope(scope int) bool {
	if m.authScopes == -1 {
		return false
	}
	return m.authScopes&scope != 0
}

// Authenticate tries to authenticate the specified user using an external plugin
func (m *Manager) Authenticate(username, password, ip, protocol string, pkey string,
	tlsCert *x509.Certificate, authScope int, userAsJSON []byte,
) ([]byte, error) {
	switch authScope {
	case AuthScopePassword:
		return m.checkUserAndPass(username, password, ip, protocol, userAsJSON)
	case AuthScopePublicKey:
		return m.checkUserAndPublicKey(username, pkey, ip, protocol, userAsJSON)
	case AuthScopeKeyboardInteractive:
		return m.checkUserAndKeyboardInteractive(username, ip, protocol, userAsJSON)
	case AuthScopeTLSCertificate:
		cert, err := util.EncodeTLSCertToPem(tlsCert)
		if err != nil {
			logger.Error(logSender, "", "unable to encode tls certificate to pem: %v", err)
			return nil, fmt.Errorf("unable to encode tls cert to pem: %w", err)
		}
		return m.checkUserAndTLSCert(username, cert, ip, protocol, userAsJSON)
	default:
		return nil, fmt.Errorf("unsupported auth scope: %v", authScope)
	}
}

// ExecuteKeyboardInteractiveStep executes a keyboard interactive step
func (m *Manager) ExecuteKeyboardInteractiveStep(req *KeyboardAuthRequest) (*KeyboardAuthResponse, error) {
	var plugin *authPlugin

	m.authLock.Lock()
	for _, p := range m.auths {
		if p.config.AuthOptions.Scope&AuthScopePassword != 0 {
			plugin = p
			break
		}
	}
	m.authLock.Unlock()

	if plugin == nil {
		return nil, errors.New("no auth plugin configured for keyaboard interactive authentication step")
	}

	return plugin.sendKeyboardIteractiveRequest(req)
}

func (m *Manager) checkUserAndPass(username, password, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var plugin *authPlugin

	m.authLock.Lock()
	for _, p := range m.auths {
		if p.config.AuthOptions.Scope&AuthScopePassword != 0 {
			plugin = p
			break
		}
	}
	m.authLock.Unlock()

	if plugin == nil {
		return nil, errors.New("no auth plugin configured for password checking")
	}

	return plugin.checkUserAndPass(username, password, ip, protocol, userAsJSON)
}

func (m *Manager) checkUserAndPublicKey(username, pubKey, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var plugin *authPlugin

	m.authLock.Lock()
	for _, p := range m.auths {
		if p.config.AuthOptions.Scope&AuthScopePublicKey != 0 {
			plugin = p
			break
		}
	}
	m.authLock.Unlock()

	if plugin == nil {
		return nil, errors.New("no auth plugin configured for public key checking")
	}

	return plugin.checkUserAndPublicKey(username, pubKey, ip, protocol, userAsJSON)
}

func (m *Manager) checkUserAndTLSCert(username, tlsCert, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var plugin *authPlugin

	m.authLock.Lock()
	for _, p := range m.auths {
		if p.config.AuthOptions.Scope&AuthScopeTLSCertificate != 0 {
			plugin = p
			break
		}
	}
	m.authLock.Unlock()

	if plugin == nil {
		return nil, errors.New("no auth plugin configured for TLS certificate checking")
	}

	return plugin.checkUserAndTLSCertificate(username, tlsCert, ip, protocol, userAsJSON)
}

func (m *Manager) checkUserAndKeyboardInteractive(username, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	var plugin *authPlugin

	m.authLock.Lock()
	for _, p := range m.auths {
		if p.config.AuthOptions.Scope&AuthScopeKeyboardInteractive != 0 {
			plugin = p
			break
		}
	}
	m.authLock.Unlock()

	if plugin == nil {
		return nil, errors.New("no auth plugin configured for keyboard interactive checking")
	}

	return plugin.checkUserAndKeyboardInteractive(username, ip, protocol, userAsJSON)
}

func (m *Manager) checkCrashedPlugins() {
	m.notifLock.RLock()
	for idx, n := range m.notifiers {
		if n.exited() {
			defer func(cfg Config, index int) {
				Handler.restartNotifierPlugin(cfg, index)
			}(n.config, idx)
		} else {
			n.sendQueuedEvents()
		}
	}
	m.notifLock.RUnlock()

	m.kmsLock.RLock()
	for idx, k := range m.kms {
		if k.exited() {
			defer func(cfg Config, index int) {
				Handler.restartKMSPlugin(cfg, index)
			}(k.config, idx)
		}
	}
	m.kmsLock.RUnlock()

	m.authLock.RLock()
	for idx, a := range m.auths {
		if a.exited() {
			defer func(cfg Config, index int) {
				Handler.restartAuthPlugin(cfg, index)
			}(a.config, idx)
		}
	}
	m.authLock.RUnlock()

	if m.hasSearcher {
		m.searcherLock.RLock()
		if m.searcher.exited() {
			defer func(cfg Config) {
				Handler.restartSearcherPlugin(cfg)
			}(m.searcher.config)
		}
		m.searcherLock.RUnlock()
	}

	if m.hasIPFilter {
		m.ipFilterLock.RLock()
		if m.filter.exited() {
			defer func(cfg Config) {
				Handler.restartIPFilterPlugin(cfg)
			}(m.filter.config)
		}
		m.ipFilterLock.RUnlock()
	}
}

func (m *Manager) restartNotifierPlugin(config Config, idx int) {
	if m.closed.Load() {
		return
	}
	logger.Info(logSender, "", "try to restart crashed notifier plugin %q, idx: %v", config.Cmd, idx)
	plugin, err := newNotifierPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart notifier plugin %q, err: %v", config.Cmd, err)
		return
	}

	m.notifLock.Lock()
	plugin.queue = m.notifiers[idx].queue
	m.notifiers[idx] = plugin
	m.notifLock.Unlock()
	plugin.sendQueuedEvents()
}

func (m *Manager) restartKMSPlugin(config Config, idx int) {
	if m.closed.Load() {
		return
	}
	logger.Info(logSender, "", "try to restart crashed kms plugin %q, idx: %v", config.Cmd, idx)
	plugin, err := newKMSPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart kms plugin %q, err: %v", config.Cmd, err)
		return
	}

	m.kmsLock.Lock()
	m.kms[idx] = plugin
	m.kmsLock.Unlock()
}

func (m *Manager) restartAuthPlugin(config Config, idx int) {
	if m.closed.Load() {
		return
	}
	logger.Info(logSender, "", "try to restart crashed auth plugin %q, idx: %v", config.Cmd, idx)
	plugin, err := newAuthPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart auth plugin %q, err: %v", config.Cmd, err)
		return
	}

	m.authLock.Lock()
	m.auths[idx] = plugin
	m.authLock.Unlock()
}

func (m *Manager) restartSearcherPlugin(config Config) {
	if m.closed.Load() {
		return
	}
	logger.Info(logSender, "", "try to restart crashed searcher plugin %q", config.Cmd)
	plugin, err := newSearcherPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart searcher plugin %q, err: %v", config.Cmd, err)
		return
	}

	m.searcherLock.Lock()
	m.searcher = plugin
	m.searcherLock.Unlock()
}

func (m *Manager) restartIPFilterPlugin(config Config) {
	if m.closed.Load() {
		return
	}
	logger.Info(logSender, "", "try to restart crashed IP filter plugin %q", config.Cmd)
	plugin, err := newIPFilterPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart IP filter plugin %q, err: %v", config.Cmd, err)
		return
	}

	m.ipFilterLock.Lock()
	m.filter = plugin
	m.ipFilterLock.Unlock()
}

func (m *Manager) addTask() {
	m.concurrencyGuard <- struct{}{}
}

func (m *Manager) removeTask() {
	<-m.concurrencyGuard
}

// Cleanup releases all the active plugins
func (m *Manager) Cleanup() {
	if m.closed.Swap(true) {
		return
	}
	logger.Debug(logSender, "", "cleanup")
	close(m.done)
	m.notifLock.Lock()
	for _, n := range m.notifiers {
		logger.Debug(logSender, "", "cleanup notifier plugin %v", n.config.Cmd)
		n.cleanup()
	}
	m.notifLock.Unlock()

	m.kmsLock.Lock()
	for _, k := range m.kms {
		logger.Debug(logSender, "", "cleanup kms plugin %v", k.config.Cmd)
		k.cleanup()
	}
	m.kmsLock.Unlock()

	m.authLock.Lock()
	for _, a := range m.auths {
		logger.Debug(logSender, "", "cleanup auth plugin %v", a.config.Cmd)
		a.cleanup()
	}
	m.authLock.Unlock()

	if m.hasSearcher {
		m.searcherLock.Lock()
		logger.Debug(logSender, "", "cleanup searcher plugin %v", m.searcher.config.Cmd)
		m.searcher.cleanup()
		m.searcherLock.Unlock()
	}

	if m.hasIPFilter {
		m.ipFilterLock.Lock()
		logger.Debug(logSender, "", "cleanup IP filter plugin %v", m.filter.config.Cmd)
		m.filter.cleanup()
		m.ipFilterLock.Unlock()
	}
}

func setLogLevel(logLevel string) {
	switch logLevel {
	case "info":
		pluginsLogLevel = hclog.Info
	case "warn":
		pluginsLogLevel = hclog.Warn
	case "error":
		pluginsLogLevel = hclog.Error
	default:
		pluginsLogLevel = hclog.Debug
	}
}

func startCheckTicker() {
	logger.Debug(logSender, "", "start plugins checker")

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-Handler.done:
				logger.Debug(logSender, "", "handler done, stop plugins checker")
				return
			case <-ticker.C:
				Handler.checkCrashedPlugins()
			}
		}
	}()
}
