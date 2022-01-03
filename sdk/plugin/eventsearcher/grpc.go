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
func (c *GRPCClient) SearchFsEvents(searchFilters *FsEventSearch) ([]byte, []string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchFsEvents(ctx, &proto.FsEventsFilter{
		StartTimestamp: searchFilters.StartTimestamp,
		EndTimestamp:   searchFilters.EndTimestamp,
		Actions:        searchFilters.Actions,
		Username:       searchFilters.Username,
		Ip:             searchFilters.IP,
		SshCmd:         searchFilters.SSHCmd,
		Protocols:      searchFilters.Protocols,
		InstanceIds:    searchFilters.InstanceIDs,
		Statuses:       searchFilters.Statuses,
		Limit:          int32(searchFilters.Limit),
		ExcludeIds:     searchFilters.ExcludeIDs,
		FsProvider:     int32(searchFilters.FsProvider),
		Bucket:         searchFilters.Bucket,
		Endpoint:       searchFilters.Endpoint,
		Order:          proto.FsEventsFilter_Order(searchFilters.Order),
	})

	if err != nil {
		return nil, nil, nil, err
	}
	return resp.Data, resp.SameTsAtStart, resp.SameTsAtEnd, nil
}

// SearchProviderEvents implements the Searcher interface
func (c *GRPCClient) SearchProviderEvents(searchFilters *ProviderEventSearch) ([]byte, []string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SearchProviderEvents(ctx, &proto.ProviderEventsFilter{
		StartTimestamp: searchFilters.StartTimestamp,
		EndTimestamp:   searchFilters.EndTimestamp,
		Actions:        searchFilters.Actions,
		Username:       searchFilters.Username,
		Ip:             searchFilters.IP,
		ObjectTypes:    searchFilters.ObjectTypes,
		ObjectName:     searchFilters.ObjectName,
		InstanceIds:    searchFilters.InstanceIDs,
		Limit:          int32(searchFilters.Limit),
		ExcludeIds:     searchFilters.ExcludeIDs,
		Order:          proto.ProviderEventsFilter_Order(searchFilters.Order),
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

// SearchFsEvents implements the server side fs events search method
func (s *GRPCServer) SearchFsEvents(ctx context.Context, req *proto.FsEventsFilter) (*proto.SearchResponse, error) {
	responseData, sameTsAtStart, sameTsAtEnd, err := s.Impl.SearchFsEvents(&FsEventSearch{
		CommonSearchParams: CommonSearchParams{
			StartTimestamp: req.StartTimestamp,
			EndTimestamp:   req.EndTimestamp,
			Actions:        req.Actions,
			Username:       req.Username,
			IP:             req.Ip,
			InstanceIDs:    req.InstanceIds,
			Limit:          int(req.Limit),
			ExcludeIDs:     req.ExcludeIds,
			Order:          int(req.Order),
		},

		SSHCmd:     req.SshCmd,
		Protocols:  req.Protocols,
		Statuses:   req.Statuses,
		FsProvider: int(req.FsProvider),
		Bucket:     req.Bucket,
		Endpoint:   req.Endpoint,
	})

	return &proto.SearchResponse{
		Data:          responseData,
		SameTsAtStart: sameTsAtStart,
		SameTsAtEnd:   sameTsAtEnd,
	}, err
}

// SearchProviderEvents implement the server side provider events search method
func (s *GRPCServer) SearchProviderEvents(ctx context.Context, req *proto.ProviderEventsFilter) (*proto.SearchResponse, error) {
	responseData, sameTsAtStart, sameTsAtEnd, err := s.Impl.SearchProviderEvents(&ProviderEventSearch{
		CommonSearchParams: CommonSearchParams{
			StartTimestamp: req.StartTimestamp,
			EndTimestamp:   req.EndTimestamp,
			Actions:        req.Actions,
			Username:       req.Username,
			IP:             req.Ip,
			InstanceIDs:    req.InstanceIds,
			Limit:          int(req.Limit),
			ExcludeIDs:     req.ExcludeIds,
			Order:          int(req.Order),
		},
		ObjectTypes: req.ObjectTypes,
		ObjectName:  req.ObjectName,
	})

	return &proto.SearchResponse{
		Data:          responseData,
		SameTsAtStart: sameTsAtStart,
		SameTsAtEnd:   sameTsAtEnd,
	}, err
}
