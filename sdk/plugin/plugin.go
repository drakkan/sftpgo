// Package plugin provides support for the SFTPGo plugin system
package plugin

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"

	"github.com/drakkan/sftpgo/v2/logger"
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
	// NotifierOptions defines additional options for notifiers plugins
	NotifierOptions NotifierConfig `json:"notifier_options" mapstructure:"notifier_options"`
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
}

// Manager handles enabled plugins
type Manager struct {
	// List of configured plugins
	Configs   []Config `json:"plugins" mapstructure:"plugins"`
	mu        sync.RWMutex
	notifiers []*notifierPlugin
}

// Initialize initializes the configured plugins
func Initialize(configs []Config, logVerbose bool) error {
	Handler = Manager{
		Configs: configs,
	}

	if logVerbose {
		pluginsLogLevel = hclog.Debug
	} else {
		pluginsLogLevel = hclog.Info
	}

	for _, config := range configs {
		switch config.Type {
		case notifier.PluginName:
			plugin, err := newNotifierPlugin(config)
			if err != nil {
				return err
			}
			Handler.notifiers = append(Handler.notifiers, plugin)
		default:
			return fmt.Errorf("unsupported plugin type: %v", config.Type)
		}
	}
	return nil
}

// NotifyFsEvent sends the fs event notifications using any defined notifier plugins
func (m *Manager) NotifyFsEvent(action, username, fsPath, fsTargetPath, sshCmd, protocol string, fileSize int64, err error) {
	m.mu.RLock()

	var crashedIdxs []int
	for idx, n := range m.notifiers {
		if n.exited() {
			crashedIdxs = append(crashedIdxs, idx)
		} else {
			n.notifyFsAction(action, username, fsPath, fsTargetPath, sshCmd, protocol, fileSize, err)
		}
	}

	m.mu.RUnlock()

	if len(crashedIdxs) > 0 {
		m.restartCrashedNotifiers(crashedIdxs)

		m.mu.RLock()
		defer m.mu.RUnlock()

		for idx := range crashedIdxs {
			if !m.notifiers[idx].exited() {
				m.notifiers[idx].notifyFsAction(action, username, fsPath, fsTargetPath, sshCmd, protocol, fileSize, err)
			}
		}
	}
}

// NotifyUserEvent sends the user event notifications using any defined notifier plugins
func (m *Manager) NotifyUserEvent(action string, user Renderer) {
	m.mu.RLock()

	var crashedIdxs []int
	for idx, n := range m.notifiers {
		if n.exited() {
			crashedIdxs = append(crashedIdxs, idx)
		} else {
			n.notifyUserAction(action, user)
		}
	}

	m.mu.RUnlock()

	if len(crashedIdxs) > 0 {
		m.restartCrashedNotifiers(crashedIdxs)

		m.mu.RLock()
		defer m.mu.RUnlock()

		for idx := range crashedIdxs {
			if !m.notifiers[idx].exited() {
				m.notifiers[idx].notifyUserAction(action, user)
			}
		}
	}
}

func (m *Manager) restartCrashedNotifiers(crashedIdxs []int) {
	for _, idx := range crashedIdxs {
		m.mu.Lock()
		defer m.mu.Unlock()

		if m.notifiers[idx].exited() {
			logger.Info(logSender, "", "try to restart crashed plugin %v", m.Configs[idx].Cmd)
			plugin, err := newNotifierPlugin(m.Configs[idx])
			if err == nil {
				m.notifiers[idx] = plugin
			} else {
				logger.Warn(logSender, "", "plugin %v crashed and restart failed: %v", m.Configs[idx].Cmd, err)
			}
		}
	}
}

// Cleanup releases all the active plugins
func (m *Manager) Cleanup() {
	for _, n := range m.notifiers {
		logger.Debug(logSender, "", "cleanup plugin %v", n.config.Cmd)
		n.cleanup()
	}
}
