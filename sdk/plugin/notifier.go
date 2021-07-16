package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/sdk/plugin/notifier"
	"github.com/drakkan/sftpgo/v2/util"
)

// NotifierConfig defines configuration parameters for notifiers plugins
type NotifierConfig struct {
	FsEvents   []string `json:"fs_events" mapstructure:"fs_events"`
	UserEvents []string `json:"user_events" mapstructure:"user_events"`
}

func (c *NotifierConfig) hasActions() bool {
	if len(c.FsEvents) > 0 {
		return true
	}
	if len(c.UserEvents) > 0 {
		return true
	}
	return false
}

type notifierPlugin struct {
	config   Config
	notifier notifier.Notifier
	client   *plugin.Client
}

func newNotifierPlugin(config Config) (*notifierPlugin, error) {
	p := &notifierPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create notifier plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *notifierPlugin) exited() bool {
	return p.client.Exited()
}

func (p *notifierPlugin) cleanup() {
	p.client.Kill()
}

func (p *notifierPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new notifier plugin %#v", p.config.Cmd)
	if !p.config.NotifierOptions.hasActions() {
		return fmt.Errorf("no actions defined for the notifier plugin %#v", p.config.Cmd)
	}
	var secureConfig *plugin.SecureConfig
	if p.config.SHA256Sum != "" {
		secureConfig.Checksum = []byte(p.config.SHA256Sum)
		secureConfig.Hash = sha256.New()
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: notifier.Handshake,
		Plugins:         notifier.PluginMap,
		Cmd:             exec.Command(p.config.Cmd, p.config.Args...),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, notifier.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for plugin %#v: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(notifier.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %#v: %v",
			notifier.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.notifier = raw.(notifier.Notifier)

	return nil
}

func (p *notifierPlugin) notifyFsAction(action, username, fsPath, fsTargetPath, sshCmd, protocol string, fileSize int64, errAction error) {
	if !util.IsStringInSlice(action, p.config.NotifierOptions.FsEvents) {
		return
	}

	go func() {
		status := 1
		if errAction != nil {
			status = 0
		}
		if err := p.notifier.NotifyFsEvent(action, username, fsPath, fsTargetPath, sshCmd, protocol, fileSize, status); err != nil {
			logger.Warn(logSender, "", "unable to send fs action notification to plugin %v: %v", p.config.Cmd, err)
		}
	}()
}

func (p *notifierPlugin) notifyUserAction(action string, user Renderer) {
	if !util.IsStringInSlice(action, p.config.NotifierOptions.UserEvents) {
		return
	}

	go func() {
		userAsJSON, err := user.RenderAsJSON(action != "delete")
		if err != nil {
			logger.Warn(logSender, "", "unable to render user as json for action %v: %v", action, err)
			return
		}
		if err := p.notifier.NotifyUserEvent(action, userAsJSON); err != nil {
			logger.Warn(logSender, "", "unable to send user action notification to plugin %v: %v", p.config.Cmd, err)
		}
	}()
}
