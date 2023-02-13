package main

import (
	"fmt"

	"github.com/hashicorp/go-plugin"
	"github.com/sftpgo/sdk/plugin/ipfilter"
)

type Filter struct{}

func (f *Filter) CheckIP(ip, protocol string) error {
	if ip == "192.168.1.12" {
		return fmt.Errorf("ip %q is not allowed", ip)
	}
	return nil
}

func (f *Filter) Reload() error {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: ipfilter.Handshake,
		Plugins: map[string]plugin.Plugin{
			ipfilter.PluginName: &ipfilter.Plugin{Impl: &Filter{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})

}
