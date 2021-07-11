package notifier

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

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
func (c *GRPCClient) NotifyFsEvent(action, username, fsPath, fsTargetPath, sshCmd, protocol string, fileSize int64, status int) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendFsEvent(ctx, &proto.FsEvent{
		Timestamp:    timestamppb.New(time.Now()),
		Action:       action,
		Username:     username,
		FsPath:       fsPath,
		FsTargetPath: fsTargetPath,
		SshCmd:       sshCmd,
		FileSize:     fileSize,
		Protocol:     protocol,
		Status:       int32(status),
	})

	return err
}

// NotifyUserEvent implements the Notifier interface
func (c *GRPCClient) NotifyUserEvent(action string, user []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SendUserEvent(ctx, &proto.UserEvent{
		Timestamp: timestamppb.New(time.Now()),
		Action:    action,
		User:      user,
	})

	return err
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Notifier
}

// SendFsEvent implements the serve side fs notify method
func (s *GRPCServer) SendFsEvent(ctx context.Context, req *proto.FsEvent) (*emptypb.Empty, error) {
	err := s.Impl.NotifyFsEvent(req.Action, req.Username, req.FsPath, req.FsTargetPath, req.SshCmd,
		req.Protocol, req.FileSize, int(req.Status))
	return &emptypb.Empty{}, err
}

// SendUserEvent implements the serve side user notify method
func (s *GRPCServer) SendUserEvent(ctx context.Context, req *proto.UserEvent) (*emptypb.Empty, error) {
	err := s.Impl.NotifyUserEvent(req.Action, req.User)
	return &emptypb.Empty{}, err
}
