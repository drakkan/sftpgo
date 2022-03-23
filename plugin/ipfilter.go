package plugin

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/ipfilter"

	"github.com/drakkan/sftpgo/v2/logger"
)

type ipFilterPlugin struct {
	config Config
	filter ipfilter.Filter
	client *plugin.Client
}

func newIPFilterPlugin(config Config) (*ipFilterPlugin, error) {
	p := &ipFilterPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create IP filter plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *ipFilterPlugin) exited() bool {
	return p.client.Exited()
}

func (p *ipFilterPlugin) cleanup() {
	p.client.Kill()
}

func (p *ipFilterPlugin) initialize() error {
	logger.Debug(logSender, "", "create new IP filter plugin %#v", p.config.Cmd)
	killProcess(p.config.Cmd)
	var secureConfig *plugin.SecureConfig
	if p.config.SHA256Sum != "" {
		secureConfig.Checksum = []byte(p.config.SHA256Sum)
		secureConfig.Hash = sha256.New()
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: ipfilter.Handshake,
		Plugins:         ipfilter.PluginMap,
		Cmd:             exec.Command(p.config.Cmd, p.config.Args...),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, ipfilter.PluginName),
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
	raw, err := rpcClient.Dispense(ipfilter.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %#v: %v",
			ipfilter.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.filter = raw.(ipfilter.Filter)

	return nil
}
