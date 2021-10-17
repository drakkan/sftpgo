package eventsearcher

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/eventsearcher/proto"
)

const (
	rpcTimeout = 30 * time.Second
)

// GRPCClient is an implementation of Notifier interface that talks over RPC.
type GRPCClient struct {
	client proto.SearcherClient
}

// SearchFsEvents implements the Searcher interface
func (c *GRPCClient) SearchFsEvents(startTimestamp, endTimestamp time.Time, action, username, ip, sshCmd, protocol,
	instanceID, continuationToken string, status, limit int) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchFsEvents(ctx, &proto.FsEventsFilter{
		StartTimestamp:    timestamppb.New(startTimestamp),
		EndTimestamp:      timestamppb.New(endTimestamp),
		Action:            action,
		Username:          username,
		Ip:                ip,
		SshCmd:            sshCmd,
		Protocol:          protocol,
		InstanceId:        instanceID,
		ContinuationToken: continuationToken,
		Status:            int32(status),
		Limit:             int32(limit),
	})

	if err != nil {
		return "", nil, err
	}
	return resp.ContinuationToken, resp.ResponseData, nil
}

// SearchProviderEvents implements the Searcher interface
func (c *GRPCClient) SearchProviderEvents(startTimestamp, endTimestamp time.Time, action, username, ip, objectType,
	objectName, instanceID, continuationToken string, limit int) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchProviderEvents(ctx, &proto.ProviderEventsFilter{
		StartTimestamp:    timestamppb.New(startTimestamp),
		EndTimestamp:      timestamppb.New(endTimestamp),
		Action:            action,
		Username:          username,
		Ip:                ip,
		ObjectType:        objectType,
		ObjectName:        objectName,
		InstanceId:        instanceID,
		ContinuationToken: continuationToken,
		Limit:             int32(limit),
	})

	if err != nil {
		return "", nil, err
	}
	return resp.ContinuationToken, resp.ResponseData, nil
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Searcher
}

// SearchFsEvents implement the server side fs events search method
func (s *GRPCServer) SearchFsEvents(ctx context.Context, req *proto.FsEventsFilter) (*proto.SearchResponse, error) {
	continuationToken, responseData, err := s.Impl.SearchFsEvents(req.StartTimestamp.AsTime(),
		req.EndTimestamp.AsTime(), req.Action, req.Username, req.Ip, req.SshCmd, req.Protocol, req.InstanceId,
		req.ContinuationToken, int(req.Status), int(req.Limit))

	return &proto.SearchResponse{
		ContinuationToken: continuationToken,
		ResponseData:      responseData,
	}, err
}

// SearchProviderEvents implement the server side provider events search method
func (s *GRPCServer) SearchProviderEvents(ctx context.Context, req *proto.ProviderEventsFilter) (*proto.SearchResponse, error) {
	continuationToken, responseData, err := s.Impl.SearchProviderEvents(req.StartTimestamp.AsTime(),
		req.EndTimestamp.AsTime(), req.Action, req.Username, req.Ip, req.ObjectType, req.ObjectName,
		req.InstanceId, req.ContinuationToken, int(req.Limit))

	return &proto.SearchResponse{
		ContinuationToken: continuationToken,
		ResponseData:      responseData,
	}, err
}
