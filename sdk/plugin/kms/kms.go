// Package kms defines the implementation for kms plugins.
// KMS plugins allow to encrypt/decrypt sensitive data.
package kms

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/kms/proto"
)

const (
	// PluginName defines the name for a kms plugin
	PluginName = "kms"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SFTPGO_PLUGIN_KMS",
	MagicCookieValue: "223e3571-7ed2-4b96-b4b3-c7eb87d7ca1d",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	PluginName: &Plugin{},
}

// Service defines the interface for kms plugins
type Service interface {
	Encrypt(payload, additionalData, URL, masterKey string) (string, string, int32, error)
	Decrypt(payload, key, additionalData string, mode int, URL, masterKey string) (string, error)
}

// Plugin defines the implementation to serve/connect to a notifier plugin
type Plugin struct {
	plugin.Plugin
	Impl Service
}

// GRPCServer defines the GRPC server implementation for this plugin
func (p *Plugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterKMSServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient defines the GRPC client implementation for this plugin
func (p *Plugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewKMSClient(c),
	}, nil
}
