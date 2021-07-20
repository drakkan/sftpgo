// Package plugin provides support for the SFTPGo plugin system
package plugin

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	kmsplugin "github.com/drakkan/sftpgo/v2/sdk/plugin/kms"
	"github.com/drakkan/sftpgo/v2/sdk/plugin/notifier"
)

const (
	logSender = "plugins"
)

var (
	// Handler defines the plugins manager
	Handler         Manager
	pluginsLogLevel = hclog.Debug
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
	Configs   []Config `json:"plugins" mapstructure:"plugins"`
	notifLock sync.RWMutex
	notifiers []*notifierPlugin
	kmsLock   sync.RWMutex
	kms       []*kmsPlugin
}

// Initialize initializes the configured plugins
func Initialize(configs []Config, logVerbose bool) error {
	Handler = Manager{
		Configs: configs,
		done:    make(chan bool),
		closed:  0,
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
	}
	return nil
}

// NotifyFsEvent sends the fs event notifications using any defined notifier plugins
func (m *Manager) NotifyFsEvent(timestamp time.Time, action, username, fsPath, fsTargetPath, sshCmd, protocol string,
	fileSize int64, err error) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyFsAction(timestamp, action, username, fsPath, fsTargetPath, sshCmd, protocol, fileSize, err)
	}
}

// NotifyUserEvent sends the user event notifications using any defined notifier plugins
func (m *Manager) NotifyUserEvent(timestamp time.Time, action string, user Renderer) {
	m.notifLock.RLock()
	defer m.notifLock.RUnlock()

	for _, n := range m.notifiers {
		n.notifyUserAction(timestamp, action, user)
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

// Cleanup releases all the active plugins
func (m *Manager) Cleanup() {
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
