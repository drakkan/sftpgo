package notifier

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/notifier/proto"
)

const (
	rpcTimeout = 20 * time.Second
)

// GRPCClient is an implementation of Notifier interface that talks over RPC.
type GRPCClient struct {
	client proto.NotifierClient
}

// NotifyFsEvent implements the Notifier interface
func (c *GRPCClient) NotifyFsEvent(event *FsEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendFsEvent(ctx, &proto.FsEvent{
		Timestamp:         event.Timestamp,
		Action:            event.Action,
		Username:          event.Username,
		FsPath:            event.Path,
		FsTargetPath:      event.TargetPath,
		SshCmd:            event.SSHCmd,
		FileSize:          event.FileSize,
		Protocol:          event.Protocol,
		Ip:                event.IP,
		Status:            int32(event.Status),
		VirtualPath:       event.VirtualPath,
		VirtualTargetPath: event.VirtualTargetPath,
		SessionId:         event.SessionID,
		FsProvider:        int32(event.FsProvider),
		Bucket:            event.Bucket,
		Endpoint:          event.Endpoint,
	})

	return err
}

// NotifyProviderEvent implements the Notifier interface
func (c *GRPCClient) NotifyProviderEvent(event *ProviderEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendProviderEvent(ctx, &proto.ProviderEvent{
		Timestamp:  event.Timestamp,
		Action:     event.Action,
		ObjectType: event.ObjectType,
		Username:   event.Username,
		Ip:         event.IP,
		ObjectName: event.ObjectName,
		ObjectData: event.ObjectData,
	})

	return err
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Notifier
}

// SendFsEvent implements the serve side fs notify method
func (s *GRPCServer) SendFsEvent(ctx context.Context, req *proto.FsEvent) (*emptypb.Empty, error) {
	event := &FsEvent{
		Action:      req.Action,
		Username:    req.Username,
		Path:        req.FsPath,
		TargetPath:  req.FsTargetPath,
		VirtualPath: req.VirtualPath,
		SSHCmd:      req.SshCmd,
		FileSize:    req.FileSize,
		Status:      int(req.Status),
		Protocol:    req.Protocol,
		IP:          req.Ip,
		SessionID:   req.SessionId,
		Timestamp:   req.Timestamp,
		FsProvider:  int(req.FsProvider),
		Bucket:      req.Bucket,
		Endpoint:    req.Endpoint,
	}
	err := s.Impl.NotifyFsEvent(event)
	return &emptypb.Empty{}, err
}

// SendProviderEvent implements the serve side provider event notify method
func (s *GRPCServer) SendProviderEvent(ctx context.Context, req *proto.ProviderEvent) (*emptypb.Empty, error) {
	event := &ProviderEvent{
		Action:     req.Action,
		Username:   req.Username,
		ObjectType: req.ObjectType,
		ObjectName: req.ObjectName,
		IP:         req.Ip,
		ObjectData: req.ObjectData,
		Timestamp:  req.Timestamp,
	}
	err := s.Impl.NotifyProviderEvent(event)
	return &emptypb.Empty{}, err
}
