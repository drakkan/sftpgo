package dataprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// Supported protocols for connecting to other nodes
const (
	NodeProtoHTTP  = "http"
	NodeProtoHTTPS = "https"
)

const (
	// NodeTokenHeader defines the header to use for the node auth token
	NodeTokenHeader = "X-SFTPGO-Node"
)

var (
	// current node
	currentNode        *Node
	errNoClusterNodes  = errors.New("no cluster node defined")
	activeNodeTimeDiff = -2 * time.Minute
	nodeReqTimeout     = 8 * time.Second
)

// NodeConfig defines the node configuration
type NodeConfig struct {
	Host  string `json:"host" mapstructure:"host"`
	Port  int    `json:"port" mapstructure:"port"`
	Proto string `json:"proto" mapstructure:"proto"`
}

func (n *NodeConfig) validate() error {
	currentNode = nil
	if config.IsShared != 1 {
		return nil
	}
	if n.Host == "" {
		return nil
	}
	currentNode = &Node{
		Data: NodeData{
			Host:  n.Host,
			Port:  n.Port,
			Proto: n.Proto,
		},
	}
	return provider.addNode()
}

// NodeData defines the details to connect to a cluster node
type NodeData struct {
	Host  string      `json:"host"`
	Port  int         `json:"port"`
	Proto string      `json:"proto"`
	Key   *kms.Secret `json:"api_key"`
}

func (n *NodeData) validate() error {
	if n.Host == "" {
		return util.NewValidationError("node host is mandatory")
	}
	if n.Port < 0 || n.Port > 65535 {
		return util.NewValidationError(fmt.Sprintf("invalid node port: %d", n.Port))
	}
	if n.Proto != NodeProtoHTTP && n.Proto != NodeProtoHTTPS {
		return util.NewValidationError(fmt.Sprintf("invalid node proto: %s", n.Proto))
	}
	n.Key = kms.NewPlainSecret(string(util.GenerateRandomBytes(32)))
	n.Key.SetAdditionalData(n.Host)
	if err := n.Key.Encrypt(); err != nil {
		return fmt.Errorf("unable to encrypt node key: %w", err)
	}
	return nil
}

// Node defines a cluster node
type Node struct {
	Name      string   `json:"name"`
	Data      NodeData `json:"data"`
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}

func (n *Node) validate() error {
	if n.Name == "" {
		n.Name = n.Data.Host
	}
	return n.Data.validate()
}

func (n *Node) authenticate(token string) error {
	if err := n.Data.Key.TryDecrypt(); err != nil {
		providerLog(logger.LevelError, "unable to decrypt node key: %v", err)
		return err
	}
	if token == "" {
		return ErrInvalidCredentials
	}
	t, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.HS256, []byte(n.Data.Key.GetPayload())))
	if err != nil {
		return fmt.Errorf("unable to parse token: %v", err)
	}
	if err := jwt.Validate(t); err != nil {
		return fmt.Errorf("unable to validate token: %v", err)
	}
	return nil
}

// getBaseURL returns the base URL for this node
func (n *Node) getBaseURL() string {
	var sb strings.Builder
	sb.WriteString(n.Data.Proto)
	sb.WriteString("://")
	sb.WriteString(n.Data.Host)
	if n.Data.Port > 0 {
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(n.Data.Port))
	}
	return sb.String()
}

// generateAuthToken generates a new auth token
func (n *Node) generateAuthToken() (string, error) {
	if err := n.Data.Key.TryDecrypt(); err != nil {
		return "", fmt.Errorf("unable to decrypt node key: %w", err)
	}
	now := time.Now().UTC()

	t := jwt.New()
	t.Set(jwt.JwtIDKey, xid.New().String())           //nolint:errcheck
	t.Set(jwt.NotBeforeKey, now.Add(-30*time.Second)) //nolint:errcheck
	t.Set(jwt.ExpirationKey, now.Add(1*time.Minute))  //nolint:errcheck

	payload, err := jwt.Sign(t, jwa.HS256, []byte(n.Data.Key.GetPayload()))
	if err != nil {
		return "", fmt.Errorf("unable to sign authentication token: %w", err)
	}
	return string(payload), nil
}

func (n *Node) prepareRequest(ctx context.Context, relativeURL, method string, body io.Reader) (*http.Request, error) {
	url := fmt.Sprintf("%s%s", n.getBaseURL(), relativeURL)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	token, err := n.generateAuthToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set(NodeTokenHeader, fmt.Sprintf("Bearer %s", token))
	return req, nil
}

// SendGetRequest sends an HTTP GET request to this node.
// The responseHolder must be a pointer
func (n *Node) SendGetRequest(relativeURL string, responseHolder any) error {
	ctx, cancel := context.WithTimeout(context.Background(), nodeReqTimeout)
	defer cancel()

	req, err := n.prepareRequest(ctx, relativeURL, http.MethodGet, nil)
	if err != nil {
		return err
	}
	client := httpclient.GetHTTPClient()
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to send HTTP GET to node %s: %w", n.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(responseHolder)
	if err != nil {
		return fmt.Errorf("unable to decode response as json")
	}
	return nil
}

// SendDeleteRequest sends an HTTP DELETE request to this node
func (n *Node) SendDeleteRequest(relativeURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nodeReqTimeout)
	defer cancel()

	req, err := n.prepareRequest(ctx, relativeURL, http.MethodDelete, nil)
	if err != nil {
		return err
	}
	client := httpclient.GetHTTPClient()
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to send HTTP DELETE to node %s: %w", n.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// AuthenticateNodeToken check the validity of the provided token
func AuthenticateNodeToken(token string) error {
	if currentNode == nil {
		return errNoClusterNodes
	}
	return currentNode.authenticate(token)
}

// GetNodeName returns the node name or an empty string
func GetNodeName() string {
	if currentNode == nil {
		return ""
	}
	return currentNode.Name
}
