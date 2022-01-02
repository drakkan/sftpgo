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
	virtualPath, virtualTargetPath, sessionID string, fileSize int64, status int,
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
		SessionId:         sessionID,
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
