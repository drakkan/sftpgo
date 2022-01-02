// Package notifier defines the implementation for event notifier plugins.
// Notifier plugins allow to receive notifications for supported filesystem
// events such as file uploads, downloads etc. and provider events such as
// objects add, update, delete.
package notifier

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/notifier/proto"
)

const (
	// PluginName defines the name for a notifier plugin
	PluginName = "notifier"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SFTPGO_PLUGIN_NOTIFIER",
	MagicCookieValue: "c499b98b-cd59-4df2-92b3-6268817f4d80",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	PluginName: &Plugin{},
}

// FsEvent defines a file system event
type FsEvent struct {
	Action            string `json:"action"`
	Username          string `json:"username"`
	Path              string `json:"path"`
	TargetPath        string `json:"target_path,omitempty"`
	VirtualPath       string `json:"virtual_path"`
	VirtualTargetPath string `json:"virtual_target_path,omitempty"`
	SSHCmd            string `json:"ssh_cmd,omitempty"`
	FileSize          int64  `json:"file_size,omitempty"`
	FsProvider        int    `json:"fs_provider"`
	Bucket            string `json:"bucket,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	Status            int    `json:"status"`
	Protocol          string `json:"protocol"`
	IP                string `json:"ip"`
	SessionID         string `json:"session_id"`
	Timestamp         int64  `json:"timestamp"`
	OpenFlags         int    `json:"open_flags,omitempty"`
}

// ProviderEvent defines a provider event
type ProviderEvent struct {
	Action     string
	Username   string
	ObjectType string
	ObjectName string
	IP         string
	ObjectData []byte
	Timestamp  int64
}

// Notifier defines the interface for notifiers plugins
type Notifier interface {
	NotifyFsEvent(event *FsEvent) error
	NotifyProviderEvent(event *ProviderEvent) error
}

// Plugin defines the implementation to serve/connect to a notifier plugin
type Plugin struct {
	plugin.Plugin
	Impl Notifier
}

// GRPCServer defines the GRPC server implementation for this plugin
func (p *Plugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterNotifierServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient defines the GRPC client implementation for this plugin
func (p *Plugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewNotifierClient(c),
	}, nil
}
