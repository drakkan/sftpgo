package metadata

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/metadata/proto"
)

const (
	rpcTimeout = 20 * time.Second
)

// GRPCClient is an implementation of Metadater interface that talks over RPC.
type GRPCClient struct {
	client proto.MetadataClient
}

// SetModificationTime implements the Metadater interface
func (c *GRPCClient) SetModificationTime(storageID, objectPath string, mTime int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.SetModificationTime(ctx, &proto.SetModificationTimeRequest{
		StorageId:        storageID,
		ObjectPath:       objectPath,
		ModificationTime: mTime,
	})

	return c.checkError(err)
}

// GetModificationTime implements the Metadater interface
func (c *GRPCClient) GetModificationTime(storageID, objectPath string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.GetModificationTime(ctx, &proto.GetModificationTimeRequest{
		StorageId:  storageID,
		ObjectPath: objectPath,
	})

	if err != nil {
		return 0, c.checkError(err)
	}

	return resp.ModificationTime, nil
}

// GetModificationTimes implements the Metadater interface
func (c *GRPCClient) GetModificationTimes(storageID, objectPath string) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout*4)
	defer cancel()

	resp, err := c.client.GetModificationTimes(ctx, &proto.GetModificationTimesRequest{
		StorageId:  storageID,
		FolderPath: objectPath,
	})

	if err != nil {
		return nil, c.checkError(err)
	}

	return resp.Pairs, nil
}

// RemoveMetadata implements the Metadater interface
func (c *GRPCClient) RemoveMetadata(storageID, objectPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	_, err := c.client.RemoveMetadata(ctx, &proto.RemoveMetadataRequest{
		StorageId:  storageID,
		ObjectPath: objectPath,
	})

	return c.checkError(err)
}

// GetFolders implements the Metadater interface
func (c *GRPCClient) GetFolders(storageID string, limit int, from string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.GetFolders(ctx, &proto.GetFoldersRequest{
		StorageId: storageID,
		Limit:     int32(limit),
		From:      from,
	})
	if err != nil {
		return nil, c.checkError(err)
	}
	return resp.Folders, nil
}

func (c *GRPCClient) checkError(err error) error {
	if err == nil {
		return nil
	}
	if s, ok := status.FromError(err); ok {
		if s.Code() == codes.NotFound {
			return ErrNoSuchObject
		}
	}
	return err
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Metadater
}

// SetModificationTime implements the server side set modification time method
func (s *GRPCServer) SetModificationTime(ctx context.Context, req *proto.SetModificationTimeRequest) (*emptypb.Empty, error) {
	err := s.Impl.SetModificationTime(req.StorageId, req.ObjectPath, req.ModificationTime)

	return &emptypb.Empty{}, err
}

// GetModificationTime implements the server side get modification time method
func (s *GRPCServer) GetModificationTime(ctx context.Context, req *proto.GetModificationTimeRequest) (
	*proto.GetModificationTimeResponse, error,
) {
	mTime, err := s.Impl.GetModificationTime(req.StorageId, req.ObjectPath)

	return &proto.GetModificationTimeResponse{
		ModificationTime: mTime,
	}, err
}

// GetModificationTimes implements the server side get modification times method
func (s *GRPCServer) GetModificationTimes(ctx context.Context, req *proto.GetModificationTimesRequest) (
	*proto.GetModificationTimesResponse, error,
) {
	res, err := s.Impl.GetModificationTimes(req.StorageId, req.FolderPath)

	return &proto.GetModificationTimesResponse{
		Pairs: res,
	}, err
}

// RemoveMetadata implements the server side remove metadata method
func (s *GRPCServer) RemoveMetadata(ctx context.Context, req *proto.RemoveMetadataRequest) (*emptypb.Empty, error) {
	err := s.Impl.RemoveMetadata(req.StorageId, req.ObjectPath)

	return &emptypb.Empty{}, err
}

// GetFolders implements the server side get folders method
func (s *GRPCServer) GetFolders(ctx context.Context, req *proto.GetFoldersRequest) (*proto.GetFoldersResponse, error) {
	res, err := s.Impl.GetFolders(req.StorageId, int(req.Limit), req.From)

	return &proto.GetFoldersResponse{
		Folders: res,
	}, err
}
