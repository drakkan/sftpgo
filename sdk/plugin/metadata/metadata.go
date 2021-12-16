package metadata

import (
	"context"
	"errors"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/metadata/proto"
)

const (
	// PluginName defines the name for a metadata plugin
	PluginName = "metadata"
)

var (
	// Handshake is a common handshake that is shared by plugin and host.
	Handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "SFTPGO_PLUGIN_METADATA",
		MagicCookieValue: "85dddeea-56d8-4d5b-b488-8b125edb3a0f",
	}
	// ErrNoSuchObject is the error that plugins must return if the request object does not exist
	ErrNoSuchObject = errors.New("no such object")
	// PluginMap is the map of plugins we can dispense.
	PluginMap = map[string]plugin.Plugin{
		PluginName: &Plugin{},
	}
)

// Metadater defines the interface for metadata plugins
type Metadater interface {
	SetModificationTime(storageID, objectPath string, mTime int64) error
	GetModificationTime(storageID, objectPath string) (int64, error)
	GetModificationTimes(storageID, objectPath string) (map[string]int64, error)
	RemoveMetadata(storageID, objectPath string) error
	GetFolders(storageID string, limit int, from string) ([]string, error)
}

// Plugin defines the implementation to serve/connect to a metadata plugin
type Plugin struct {
	plugin.Plugin
	Impl Metadater
}

// GRPCServer defines the GRPC server implementation for this plugin
func (p *Plugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterMetadataServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient defines the GRPC client implementation for this plugin
func (p *Plugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewMetadataClient(c),
	}, nil
}
