package auth

import (
	"context"
	"time"

	"github.com/drakkan/sftpgo/v2/sdk/plugin/auth/proto"
)

const (
	rpcTimeout = 20 * time.Second
)

// GRPCClient is an implementation of Authenticator interface that talks over RPC.
type GRPCClient struct {
	client proto.AuthClient
}

// CheckUserAndPass implements the Authenticator interface
func (c *GRPCClient) CheckUserAndPass(username, password, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.CheckUserAndPass(ctx, &proto.CheckUserAndPassRequest{
		Username: username,
		Password: password,
		Ip:       ip,
		Protocol: protocol,
		User:     userAsJSON,
	})
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// CheckUserAndTLSCert implements the Authenticator interface
func (c *GRPCClient) CheckUserAndTLSCert(username, tlsCert, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.CheckUserAndTLSCert(ctx, &proto.CheckUserAndTLSCertRequest{
		Username: username,
		TlsCert:  tlsCert,
		Ip:       ip,
		Protocol: protocol,
		User:     userAsJSON,
	})
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// CheckUserAndPublicKey implements the Authenticator interface
func (c *GRPCClient) CheckUserAndPublicKey(username, pubKey, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.CheckUserAndPublicKey(ctx, &proto.CheckUserAndPublicKeyRequest{
		Username: username,
		PubKey:   pubKey,
		Ip:       ip,
		Protocol: protocol,
		User:     userAsJSON,
	})
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// CheckUserAndKeyboardInteractive implements the Authenticator interface
func (c *GRPCClient) CheckUserAndKeyboardInteractive(username, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.CheckUserAndKeyboardInteractive(ctx, &proto.CheckUserAndKeyboardInteractiveRequest{
		Username: username,
		Ip:       ip,
		Protocol: protocol,
		User:     userAsJSON,
	})
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// SendKeyboardAuthRequest implements the Authenticator interface
func (c *GRPCClient) SendKeyboardAuthRequest(requestID, username, password, ip string, answers, questions []string, step int32) (string, []string, []bool, int, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.SendKeyboardAuthRequest(ctx, &proto.KeyboardAuthRequest{
		RequestID: requestID,
		Username:  username,
		Password:  password,
		Ip:        ip,
		Answers:   answers,
		Questions: questions,
		Step:      step,
	})
	if err != nil {
		return "", nil, nil, 0, 0, err
	}
	return resp.Instructions, resp.Questions, resp.Echos, int(resp.AuthResult), int(resp.CheckPassword), err
}

// GRPCServer defines the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	Impl Authenticator
}

// CheckUserAndPass implements the server side check user and password method
func (s *GRPCServer) CheckUserAndPass(ctx context.Context, req *proto.CheckUserAndPassRequest) (*proto.AuthResponse, error) {
	user, err := s.Impl.CheckUserAndPass(req.Username, req.Password, req.Ip, req.Protocol, req.User)
	if err != nil {
		return nil, err
	}
	return &proto.AuthResponse{User: user}, nil
}

// CheckUserAndTLSCert implements the server side check user and tls certificate method
func (s *GRPCServer) CheckUserAndTLSCert(ctx context.Context, req *proto.CheckUserAndTLSCertRequest) (*proto.AuthResponse, error) {
	user, err := s.Impl.CheckUserAndTLSCert(req.Username, req.TlsCert, req.Ip, req.Protocol, req.User)
	if err != nil {
		return nil, err
	}
	return &proto.AuthResponse{User: user}, nil
}

// CheckUserAndPublicKey implements the server side check user and public key method
func (s *GRPCServer) CheckUserAndPublicKey(ctx context.Context, req *proto.CheckUserAndPublicKeyRequest) (*proto.AuthResponse, error) {
	user, err := s.Impl.CheckUserAndPublicKey(req.Username, req.PubKey, req.Ip, req.Protocol, req.User)
	if err != nil {
		return nil, err
	}
	return &proto.AuthResponse{User: user}, nil
}

// CheckUserAndKeyboardInteractive implements the server side check user and keyboard interactive method
func (s *GRPCServer) CheckUserAndKeyboardInteractive(ctx context.Context, req *proto.CheckUserAndKeyboardInteractiveRequest) (*proto.AuthResponse, error) {
	user, err := s.Impl.CheckUserAndKeyboardInteractive(req.Username, req.Ip, req.Protocol, req.User)
	if err != nil {
		return nil, err
	}
	return &proto.AuthResponse{User: user}, nil
}

// SendKeyboardAuthRequest implements the server side method to send a keyboard interactive authentication request
func (s *GRPCServer) SendKeyboardAuthRequest(ctx context.Context, req *proto.KeyboardAuthRequest) (*proto.KeyboardAuthResponse, error) {
	instructions, questions, echos, authResult, checkPwd, err := s.Impl.SendKeyboardAuthRequest(req.RequestID, req.Username,
		req.Password, req.Ip, req.Answers, req.Questions, req.Step)
	if err != nil {
		return nil, err
	}
	return &proto.KeyboardAuthResponse{
		Instructions:  instructions,
		Questions:     questions,
		Echos:         echos,
		AuthResult:    int32(authResult),
		CheckPassword: int32(checkPwd),
	}, nil
}
