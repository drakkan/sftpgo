package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/eventsearcher"

	"github.com/drakkan/sftpgo/v2/logger"
)

type searcherPlugin struct {
	config    Config
	searchear eventsearcher.Searcher
	client    *plugin.Client
}

func newSearcherPlugin(config Config) (*searcherPlugin, error) {
	p := &searcherPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create events searcher plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *searcherPlugin) exited() bool {
	return p.client.Exited()
}

func (p *searcherPlugin) cleanup() {
	p.client.Kill()
}

func (p *searcherPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new searcher plugin %#v", p.config.Cmd)
	var secureConfig *plugin.SecureConfig
	if p.config.SHA256Sum != "" {
		secureConfig.Checksum = []byte(p.config.SHA256Sum)
		secureConfig.Hash = sha256.New()
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: eventsearcher.Handshake,
		Plugins:         eventsearcher.PluginMap,
		Cmd:             exec.Command(p.config.Cmd, p.config.Args...),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, eventsearcher.PluginName),
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
	raw, err := rpcClient.Dispense(eventsearcher.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %#v: %v",
			eventsearcher.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.searchear = raw.(eventsearcher.Searcher)

	return nil
}
