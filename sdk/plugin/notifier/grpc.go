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
func (c *GRPCClient) NotifyFsEvent(timestamp int64, action, username, fsPath, fsTargetPath, sshCmd, protocol, ip,
	virtualPath, virtualTargetPath string, fileSize int64, status int,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendFsEvent(ctx, &proto.FsEvent{
		Timestamp:         timestamp,
		Action:            action,
		Username:          username,
		FsPath:            fsPath,
		FsTargetPath:      fsTargetPath,
		SshCmd:            sshCmd,
		FileSize:          fileSize,
		Protocol:          protocol,
		Ip:                ip,
		Status:            int32(status),
		VirtualPath:       virtualPath,
		VirtualTargetPath: virtualTargetPath,
	})

	return err
}

// NotifyProviderEvent implements the Notifier interface
func (c *GRPCClient) NotifyProviderEvent(timestamp int64, action, username, objectType, objectName, ip string, object []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendProviderEvent(ctx, &proto.ProviderEvent{
		Timestamp:  timestamp,
		Action:     action,
		ObjectType: objectType,
		Username:   username,
		Ip:         ip,
		ObjectName: objectName,
		ObjectData: object,
	})

	return err
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Notifier
}

// SendFsEvent implements the serve side fs notify method
func (s *GRPCServer) SendFsEvent(ctx context.Context, req *proto.FsEvent) (*emptypb.Empty, error) {
	err := s.Impl.NotifyFsEvent(req.Timestamp, req.Action, req.Username, req.FsPath, req.FsTargetPath, req.SshCmd,
		req.Protocol, req.Ip, req.VirtualPath, req.VirtualTargetPath, req.FileSize, int(req.Status))
	return &emptypb.Empty{}, err
}

// SendProviderEvent implements the serve side provider event notify method
func (s *GRPCServer) SendProviderEvent(ctx context.Context, req *proto.ProviderEvent) (*emptypb.Empty, error) {
	err := s.Impl.NotifyProviderEvent(req.Timestamp, req.Action, req.Username, req.ObjectType, req.ObjectName,
		req.Ip, req.ObjectData)
	return &emptypb.Empty{}, err
}
