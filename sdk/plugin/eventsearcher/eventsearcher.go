// Package eventsearcher defines the implementation for events search plugins.
// Events search plugins allow to search for filesystem and provider events.
package eventsearcher

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/eventsearcher/proto"
)

const (
	// PluginName defines the name for an events search plugin
	PluginName = "eventsearcher"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SFTPGO_PLUGIN_EVENTSEARCHER",
	MagicCookieValue: "2b523805-0279-471c-895e-6c0d39002ca4",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	PluginName: &Plugin{},
}

// Searcher defines the interface for events search plugins
type Searcher interface {
	SearchFsEvents(startTimestamp, endTimestamp int64, username, ip, sshCmd string, actions, protocols,
		instanceIDs, excludeIDs []string, statuses []int32, limit, order int) ([]byte, []string, []string, error)
	SearchProviderEvents(startTimestamp, endTimestamp int64, username, ip, objectName string,
		limit, order int, actions, objectTypes, instanceIDs, excludeIDs []string) ([]byte, []string, []string, error)
}

// Plugin defines the implementation to serve/connect to a notifier plugin
type Plugin struct {
	plugin.Plugin
	Impl Searcher
}

// GRPCServer defines the GRPC server implementation for this plugin
func (p *Plugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterSearcherServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient defines the GRPC client implementation for this plugin
func (p *Plugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewSearcherClient(c),
	}, nil
}
