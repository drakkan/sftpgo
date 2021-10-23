package eventsearcher

import (
	"context"
	"time"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/eventsearcher/proto"
)

const (
	rpcTimeout = 20 * time.Second
)

// GRPCClient is an implementation of Notifier interface that talks over RPC.
type GRPCClient struct {
	client proto.SearcherClient
}

// SearchFsEvents implements the Searcher interface
func (c *GRPCClient) SearchFsEvents(startTimestamp, endTimestamp int64, username, ip, sshCmd string, actions,
	protocols, instanceIDs, excludeIDs []string, statuses []int32, limit, order int,
) ([]byte, []string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchFsEvents(ctx, &proto.FsEventsFilter{
		StartTimestamp: startTimestamp,
		EndTimestamp:   endTimestamp,
		Actions:        actions,
		Username:       username,
		Ip:             ip,
		SshCmd:         sshCmd,
		Protocols:      protocols,
		InstanceIds:    instanceIDs,
		Statuses:       statuses,
		Limit:          int32(limit),
		Order:          proto.FsEventsFilter_Order(order),
		ExcludeIds:     excludeIDs,
	})

	if err != nil {
		return nil, nil, nil, err
	}
	return resp.Data, resp.SameTsAtStart, resp.SameTsAtEnd, nil
}

// SearchProviderEvents implements the Searcher interface
func (c *GRPCClient) SearchProviderEvents(startTimestamp, endTimestamp int64, username, ip, objectName string,
	limit, order int, actions, objectTypes, instanceIDs, excludeIDs []string,
) ([]byte, []string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchProviderEvents(ctx, &proto.ProviderEventsFilter{
		StartTimestamp: startTimestamp,
		EndTimestamp:   endTimestamp,
		Actions:        actions,
		Username:       username,
		Ip:             ip,
		ObjectTypes:    objectTypes,
		ObjectName:     objectName,
		InstanceIds:    instanceIDs,
		Limit:          int32(limit),
		Order:          proto.ProviderEventsFilter_Order(order),
		ExcludeIds:     excludeIDs,
	})

	if err != nil {
		return nil, nil, nil, err
	}
	return resp.Data, resp.SameTsAtStart, resp.SameTsAtEnd, nil
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Searcher
}

// SearchFsEvents implement the server side fs events search method
func (s *GRPCServer) SearchFsEvents(ctx context.Context, req *proto.FsEventsFilter) (*proto.SearchResponse, error) {
	responseData, sameTsAtStart, sameTsAtEnd, err := s.Impl.SearchFsEvents(req.StartTimestamp,
		req.EndTimestamp, req.Username, req.Ip, req.SshCmd, req.Actions, req.Protocols, req.InstanceIds,
		req.ExcludeIds, req.Statuses, int(req.Limit), int(req.Order))

	return &proto.SearchResponse{
		Data:          responseData,
		SameTsAtStart: sameTsAtStart,
		SameTsAtEnd:   sameTsAtEnd,
	}, err
}

// SearchProviderEvents implement the server side provider events search method
func (s *GRPCServer) SearchProviderEvents(ctx context.Context, req *proto.ProviderEventsFilter) (*proto.SearchResponse, error) {
	responseData, sameTsAtStart, sameTsAtEnd, err := s.Impl.SearchProviderEvents(req.StartTimestamp,
		req.EndTimestamp, req.Username, req.Ip, req.ObjectName, int(req.Limit),
		int(req.Order), req.Actions, req.ObjectTypes, req.InstanceIds, req.ExcludeIds)

	return &proto.SearchResponse{
		Data:          responseData,
		SameTsAtStart: sameTsAtStart,
		SameTsAtEnd:   sameTsAtEnd,
	}, err
}
