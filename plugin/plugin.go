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
	"github.com/sftpgo/sdk/plugin/auth"
	"github.com/sftpgo/sdk/plugin/eventsearcher"
	"github.com/sftpgo/sdk/plugin/ipfilter"
	kmsplugin "github.com/sftpgo/sdk/plugin/kms"
	"github.com/sftpgo/sdk/plugin/metadata"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
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
	// ErrNoMetadater returns the error to return for metadata methods if no plugin is configured
	ErrNoMetadater = errors.New("no metadata plugin defined")
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
	Configs       []Config `json:"plugins" mapstructure:"plugins"`
	notifLock     sync.RWMutex
	notifiers     []*notifierPlugin
	kmsLock       sync.RWMutex
	kms           []*kmsPlugin
	authLock      sync.RWMutex
	auths         []*authPlugin
	searcherLock  sync.RWMutex
	searcher      *searcherPlugin
	metadaterLock sync.RWMutex
	metadater     *metadataPlugin
	ipFilterLock  sync.RWMutex
	filter        *ipFilterPlugin
	authScopes    int
	hasSearcher   bool
	hasMetadater  bool
	hasNotifiers  bool
	hasAuths      bool
	hasIPFilter   bool
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
	setLogLevel(logVerbose)
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
		case metadata.PluginName:
			plugin, err := newMetadaterPlugin(config)
			if err != nil {
				return err
			}
			Handler.metadater = plugin
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
	m.hasMetadater = false
	m.hasNotifiers = false
	m.hasAuths = false
	m.hasIPFilter = false

	for _, config := range m.Configs {
		switch config.Type {
		case kmsplugin.PluginName:
			if _, ok := kmsSchemes[config.KMSOptions.Scheme]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated scheme %#v", config.KMSOptions.Scheme)
			}
			if _, ok := kmsEncryptions[config.KMSOptions.EncryptedStatus]; ok {
				return fmt.Errorf("invalid KMS configuration, duplicated encrypted status %#v", config.KMSOptions.EncryptedStatus)
			}
			kmsSchemes[config.KMSOptions.Scheme] = true
			kmsEncryptions[config.KMSOptions.EncryptedStatus] = true
		case eventsearcher.PluginName:
			if m.hasSearcher {
				return errors.New("only one eventsearcher plugin can be defined")
			}
			m.hasSearcher = true
		case metadata.PluginName:
			if m.hasMetadater {
				return errors.New("only one metadata plugin can be defined")
			}
			m.hasMetadater = true
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

// SearchFsEvents returns the filesystem events matching the specified filters
func (m *Manager) SearchFsEvents(searchFilters *eventsearcher.FsEventSearch) ([]byte, []string, []string, error) {
	if !m.hasSearcher {
		return nil, nil, nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchFsEvents(searchFilters)
}

// SearchProviderEvents returns the provider events matching the specified filters
func (m *Manager) SearchProviderEvents(searchFilters *eventsearcher.ProviderEventSearch) ([]byte, []string, []string, error) {
	if !m.hasSearcher {
		return nil, nil, nil, ErrNoSearcher
	}
	m.searcherLock.RLock()
	plugin := m.searcher
	m.searcherLock.RUnlock()

	return plugin.searchear.SearchProviderEvents(searchFilters)
}

// HasMetadater returns true if a metadata plugin is defined
func (m *Manager) HasMetadater() bool {
	return m.hasMetadater
}

// SetModificationTime sets the modification time for the specified object
func (m *Manager) SetModificationTime(storageID, objectPath string, mTime int64) error {
	if !m.hasMetadater {
		return ErrNoMetadater
	}
	m.metadaterLock.RLock()
	plugin := m.metadater
	m.metadaterLock.RUnlock()

	return plugin.metadater.SetModificationTime(storageID, objectPath, mTime)
}

// GetModificationTime returns the modification time for the specified path
func (m *Manager) GetModificationTime(storageID, objectPath string, isDir bool) (int64, error) {
	if !m.hasMetadater {
		return 0, ErrNoMetadater
	}
	m.metadaterLock.RLock()
	plugin := m.metadater
	m.metadaterLock.RUnlock()

	return plugin.metadater.GetModificationTime(storageID, objectPath)
}

// GetModificationTimes returns the modification times for all the files within the specified folder
func (m *Manager) GetModificationTimes(storageID, objectPath string) (map[string]int64, error) {
	if !m.hasMetadater {
		return nil, ErrNoMetadater
	}
	m.metadaterLock.RLock()
	plugin := m.metadater
	m.metadaterLock.RUnlock()

	return plugin.metadater.GetModificationTimes(storageID, objectPath)
}

// RemoveMetadata deletes the metadata stored for the specified object
func (m *Manager) RemoveMetadata(storageID, objectPath string) error {
	if !m.hasMetadater {
		return ErrNoMetadater
	}
	m.metadaterLock.RLock()
	plugin := m.metadater
	m.metadaterLock.RUnlock()

	return plugin.metadater.RemoveMetadata(storageID, objectPath)
}

// GetMetadataFolders returns the folders that metadata is associated with
func (m *Manager) GetMetadataFolders(storageID, from string, limit int) ([]string, error) {
	if !m.hasMetadater {
		return nil, ErrNoMetadater
	}
	m.metadaterLock.RLock()
	plugin := m.metadater
	m.metadaterLock.RUnlock()

	return plugin.metadater.GetFolders(storageID, limit, from)
}

// IsIPBanned returns true if the IP filter plugin does not allow the specified ip.
// If no IP filter plugin is defined this method returns false
func (m *Manager) IsIPBanned(ip string) bool {
	if !m.hasIPFilter {
		return false
	}

	m.ipFilterLock.RLock()
	plugin := m.filter
	m.ipFilterLock.RUnlock()

	if plugin.exited() {
		logger.Warn(logSender, "", "ip filter plugin is not active, cannot check ip %#v", ip)
		return false
	}

	return plugin.filter.CheckIP(ip) != nil
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

	if m.hasMetadater {
		m.metadaterLock.RLock()
		if m.metadater.exited() {
			defer func(cfg Config) {
				Handler.restartMetadaterPlugin(cfg)
			}(m.metadater.config)
		}
		m.metadaterLock.RUnlock()
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
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed notifier plugin %#v, idx: %v", config.Cmd, idx)
	plugin, err := newNotifierPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart notifier plugin %#v, err: %v", config.Cmd, err)
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
		logger.Error(logSender, "", "unable to restart kms plugin %#v, err: %v", config.Cmd, err)
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
		logger.Error(logSender, "", "unable to restart auth plugin %#v, err: %v", config.Cmd, err)
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
		logger.Error(logSender, "", "unable to restart searcher plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.searcherLock.Lock()
	m.searcher = plugin
	m.searcherLock.Unlock()
}

func (m *Manager) restartMetadaterPlugin(config Config) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed metadater plugin %#v", config.Cmd)
	plugin, err := newMetadaterPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart metadater plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.metadaterLock.Lock()
	m.metadater = plugin
	m.metadaterLock.Unlock()
}

func (m *Manager) restartIPFilterPlugin(config Config) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return
	}
	logger.Info(logSender, "", "try to restart crashed IP filter plugin %#v", config.Cmd)
	plugin, err := newIPFilterPlugin(config)
	if err != nil {
		logger.Error(logSender, "", "unable to restart IP filter plugin %#v, err: %v", config.Cmd, err)
		return
	}

	m.ipFilterLock.Lock()
	m.filter = plugin
	m.ipFilterLock.Unlock()
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

	if m.hasMetadater {
		m.metadaterLock.Lock()
		logger.Debug(logSender, "", "cleanup metadater plugin %v", m.metadater.config.Cmd)
		m.metadater.cleanup()
		m.metadaterLock.Unlock()
	}

	if m.hasIPFilter {
		m.ipFilterLock.Lock()
		logger.Debug(logSender, "", "cleanup IP filter plugin %v", m.filter.config.Cmd)
		m.filter.cleanup()
		m.ipFilterLock.Unlock()
	}
}

func setLogLevel(logVerbose bool) {
	if logVerbose {
		pluginsLogLevel = hclog.Debug
	} else {
		pluginsLogLevel = hclog.Info
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
