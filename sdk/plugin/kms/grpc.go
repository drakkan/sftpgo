package kms

import (
	"context"
	"time"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/kms/proto"
)

const (
	rpcTimeout = 20 * time.Second
)

// GRPCClient is an implementation of KMS interface that talks over RPC.
type GRPCClient struct {
	client proto.KMSClient
}

// Encrypt implements the KMSService interface
func (c *GRPCClient) Encrypt(payload, additionalData, URL, masterKey string) (string, string, int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.Encrypt(ctx, &proto.EncryptRequest{
		Payload:        payload,
		AdditionalData: additionalData,
		Url:            URL,
		MasterKey:      masterKey,
	})
	if err != nil {
		return "", "", 0, err
	}
	return resp.Payload, resp.Key, resp.Mode, nil
}

// Decrypt implements the KMSService interface
func (c *GRPCClient) Decrypt(payload, key, additionalData string, mode int, URL, masterKey string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.Decrypt(ctx, &proto.DecryptRequest{
		Payload:        payload,
		Key:            key,
		AdditionalData: additionalData,
		Mode:           int32(mode),
		Url:            URL,
		MasterKey:      masterKey,
	})
	if err != nil {
		return "", err
	}
	return resp.Payload, nil
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Service
}

// Encrypt implements the serve side encrypt method
func (s *GRPCServer) Encrypt(ctx context.Context, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	payload, key, mode, err := s.Impl.Encrypt(req.Payload, req.AdditionalData, req.Url, req.MasterKey)
	if err != nil {
		return nil, err
	}

	return &proto.EncryptResponse{
		Payload: payload,
		Key:     key,
		Mode:    mode,
	}, nil
}

// Decrypt implements the serve side decrypt method
func (s *GRPCServer) Decrypt(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	payload, err := s.Impl.Decrypt(req.Payload, req.Key, req.AdditionalData, int(req.Mode), req.Url, req.MasterKey)
	if err != nil {
		return nil, err
	}

	return &proto.DecryptResponse{
		Payload: payload,
	}, nil
}
