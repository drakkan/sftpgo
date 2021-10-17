// Package auth defines the implementation for authentication plugins.
// Authentication plugins allow to authenticate external users
package auth

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/auth/proto"
)

const (
	// PluginName defines the name for a notifier plugin
	PluginName = "auth"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SFTPGO_PLUGIN_AUTH",
	MagicCookieValue: "d1ed507d-d2be-4a38-a460-6fe0b2cc7efc",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	PluginName: &Plugin{},
}

// Authenticator defines the interface for authentication plugins
type Authenticator interface {
	CheckUserAndPass(username, password, ip, protocol string, userAsJSON []byte) ([]byte, error)
	CheckUserAndTLSCert(username, tlsCert, ip, protocol string, userAsJSON []byte) ([]byte, error)
	CheckUserAndPublicKey(username, pubKey, ip, protocol string, userAsJSON []byte) ([]byte, error)
	CheckUserAndKeyboardInteractive(username, ip, protocol string, userAsJSON []byte) ([]byte, error)
	SendKeyboardAuthRequest(requestID, username, password, ip string, answers, questions []string, step int32) (string, []string, []bool, int, int, error)
}

// Plugin defines the implementation to serve/connect to an authe plugin
type Plugin struct {
	plugin.Plugin
	Impl Authenticator
}

// GRPCServer defines the GRPC server implementation for this plugin
func (p *Plugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterAuthServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient defines the GRPC client implementation for this plugin
func (p *Plugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewAuthClient(c),
	}, nil
}
