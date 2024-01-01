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

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/ipfilter"

	"github.com/drakkan/sftpgo/v2/internal/logger"
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
	logger.Debug(logSender, "", "create new IP filter plugin %q", p.config.Cmd)
	killProcess(p.config.Cmd)
	secureConfig, err := p.config.getSecureConfig()
	if err != nil {
		return err
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: ipfilter.Handshake,
		Plugins:         ipfilter.PluginMap,
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
				Name:        fmt.Sprintf("%v.%v", logSender, ipfilter.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for plugin %q: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(ipfilter.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %q: %v",
			ipfilter.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.filter = raw.(ipfilter.Filter)

	return nil
}
