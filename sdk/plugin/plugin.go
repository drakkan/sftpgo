// Package plugin provides support for the SFTPGo plugin system
package plugin

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/sdk/plugin/auth"
	"github.com/drakkan/sftpgo/v2/sdk/plugin/eventsearcher"
	kmsplugin "github.com/drakkan/sftpgo/v2/sdk/plugin/kms"
	"github.com/drakkan/sftpgo/v2/sdk/plugin/notifier"
	"github.com/drakkan/sftpgo/v2/util"
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
	// unique identifier for kms plugins
	kmsID int
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
	closed int32
	done   chan bool
	// List of configured plugins
	Configs      []Config `json:"plugins" mapstructure:"plugins"`
	notifLock    sync.RWMutex
	notifiers    []*notifierPlugin
	kmsLock      sync.RWMutex
	kms          []*kmsPlugin
	authLock     sync.RWMutex
	auths        []*authPlugin
	searcherLock sync.RWMutex
	searcher     *searcherPlugin
	authScopes   int
	hasSearcher  bool
}

// Initialize initializes the configured plugins
func Initialize(configs []Config, logVerbose bool) error {
	logger.Debug(logSender, "", "initialize")
	Handler = Manager{
		Configs:    configs,
		done:       make(chan bool),
		closed:     0,
		authScopes: -1,
	}
	if len(configs) == 0 {
		return nil
	}
	if err := Handler.validateConfigs(); err != nil {
		return err
	}

	if logVerbose {
		pluginsLogLevel = hclog.Debug
	} else {
		pluginsLogLevel = hclog.Info
	}

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
			logger.Debug(logSender, "", "registered secret provider for scheme: %v, encrypted status: %v",
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
		default:
			return fmt.Errorf("unsupported plugin type: %v", config.Type)
		}
	}
	startCheckTicker()
	return nil
}

func (m *Manager) validateConfigs() error {
	kmsSchemes := make(map[string]bool)
	kmsEncryptions := make(map[string]bool)
	m.hasSearcher = false

	for _, config := range m.Configs {
		if config.Type == kmsplugin.PluginName {
			if _, ok := kmsSchemes[config.KMSOptions.Scheme]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated scheme %#v", config.KMSOptions.Scheme)
			}
			if _, ok := kmsEncryptions[config.KMSOptions.EncryptedStatus]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated encrypted status %#v", config.KMSOptions.EncryptedStatus)
			}
			kmsSchemes[config.KMSOptions.Scheme] = true
			kmsEncryptions[config.KMSOptions.EncryptedStatus] = true
		}
		if config.Type == eventsearcher.PluginName {
			if m.hasSearcher {
				return fmt.Errorf("only one eventsearcher plugin can be defined")
			}
			m.hasSearcher = true
		}
	}
	return nil
}

// NotifyFsEvent sends the fs event notifications using any defined notifier plugins
func (m *Manager) NotifyFsEvent(timestamp int64, action, username, fsPath, fsTargetPath, sshCmd, protocol, ip,
	virtualPath, virtualTargetPath string, fileSize int64, err error,
) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyFsAction(timestamp, action, username, fsPath, fsTargetPath, sshCmd, protocol, ip, virtualPath, virtualTargetPath,
			fileSize, err)
	}
}

// NotifyProviderEvent sends the provider event notifications using any defined notifier plugins
func (m *Manager) NotifyProviderEvent(timestamp int64, action, username, objectType, objectName, ip string,
	object Renderer,
) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyProviderAction(timestamp, action, username, objectType, objectName, ip, object)
	}
}

// SearchFsEvents returns the filesystem events matching the specified filter and a continuation token
// to use for cursor based pagination
func (m *Manager) SearchFsEvents(startTimestamp, endTimestamp int64, username, ip, sshCmd string, actions,
	protocols, instanceIDs, excludeIDs []string, statuses []int32, limit, order int,
) ([]byte, []string, []string, error) {
	if !m.hasSearcher {
		return nil, nil, nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchFsEvents(startTimestamp, endTimestamp, username, ip, sshCmd, actions, protocols,
		instanceIDs, excludeIDs, statuses, limit, order)
}

// SearchProviderEvents returns the provider events matching the specified filter and a continuation token
// to use for cursor based pagination
func (m *Manager) SearchProviderEvents(startTimestamp, endTimestamp int64, username, ip, objectName string,
	limit, order int, actions, objectTypes, instanceIDs, excludeIDs []string,
) ([]byte, []string, []string, error) {
	if !m.hasSearcher {
		return nil, nil, nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchProviderEvents(startTimestamp, endTimestamp, username, ip, objectName, limit,
		order, actions, objectTypes, instanceIDs, excludeIDs)
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
			logger.Warn(logSender, "", "unable to encode tls certificate to pem: %v", err)
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
}

func (m *Manager) restartNotifierPlugin(config Config, idx int) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed notifier plugin %#v, idx: %v", config.Cmd, idx)
	plugin, err := newNotifierPlugin(config)
	if err != nil {
		logger.Warn(logSender, "", "unable to restart notifier plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.notifLock.Lock()
	plugin.queue = m.notifiers[idx].queue
	m.notifiers[idx] = plugin
	m.notifLock.Unlock()
	plugin.sendQueuedEvents()
}

func (m *Manager) restartKMSPlugin(config Config, idx int) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed kms plugin %#v, idx: %v", config.Cmd, idx)
	plugin, err := newKMSPlugin(config)
	if err != nil {
		logger.Warn(logSender, "", "unable to restart kms plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.kmsLock.Lock()
	m.kms[idx] = plugin
	m.kmsLock.Unlock()
}

func (m *Manager) restartAuthPlugin(config Config, idx int) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed auth plugin %#v, idx: %v", config.Cmd, idx)
	plugin, err := newAuthPlugin(config)
	if err != nil {
		logger.Warn(logSender, "", "unable to restart auth plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.authLock.Lock()
	m.auths[idx] = plugin
	m.authLock.Unlock()
}

func (m *Manager) restartSearcherPlugin(config Config) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed searcher plugin %#v", config.Cmd)
	plugin, err := newSearcherPlugin(config)
	if err != nil {
		logger.Warn(logSender, "", "unable to restart searcher plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.searcherLock.Lock()
	m.searcher = plugin
	m.searcherLock.Unlock()
}

// Cleanup releases all the active plugins
func (m *Manager) Cleanup() {
	logger.Debug(logSender, "", "cleanup")
	atomic.StoreInt32(&m.closed, 1)
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
}

func startCheckTicker() {
	logger.Debug(logSender, "", "start plugins checker")
	checker := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-Handler.done:
				logger.Debug(logSender, "", "handler done, stop plugins checker")
				checker.Stop()
				return
			case <-checker.C:
				Handler.checkCrashedPlugins()
			}
		}
	}()
}
