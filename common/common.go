// Package common defines code shared among file transfer packages and protocols
package common

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
)

// constants
const (
	logSender                = "common"
	uploadLogSender          = "Upload"
	downloadLogSender        = "Download"
	renameLogSender          = "Rename"
	rmdirLogSender           = "Rmdir"
	mkdirLogSender           = "Mkdir"
	symlinkLogSender         = "Symlink"
	removeLogSender          = "Remove"
	chownLogSender           = "Chown"
	chmodLogSender           = "Chmod"
	chtimesLogSender         = "Chtimes"
	operationDownload        = "download"
	operationUpload          = "upload"
	operationDelete          = "delete"
	operationPreDelete       = "pre-delete"
	operationRename          = "rename"
	operationSSHCmd          = "ssh_cmd"
	chtimesFormat            = "2006-01-02T15:04:05" // YYYY-MM-DDTHH:MM:SS
	idleTimeoutCheckInterval = 3 * time.Minute
)

// Stat flags
const (
	StatAttrUIDGID = 1
	StatAttrPerms  = 2
	StatAttrTimes  = 4
)

// Transfer types
const (
	TransferUpload = iota
	TransferDownload
)

// Supported protocols
const (
	ProtocolSFTP   = "SFTP"
	ProtocolSCP    = "SCP"
	ProtocolSSH    = "SSH"
	ProtocolFTP    = "FTP"
	ProtocolWebDAV = "DAV"
)

// Upload modes
const (
	UploadModeStandard = iota
	UploadModeAtomic
	UploadModeAtomicWithResume
)

// errors definitions
var (
	ErrPermissionDenied     = errors.New("permission denied")
	ErrNotExist             = errors.New("no such file or directory")
	ErrOpUnsupported        = errors.New("operation unsupported")
	ErrGenericFailure       = errors.New("failure")
	ErrQuotaExceeded        = errors.New("denying write due to space limit")
	ErrSkipPermissionsCheck = errors.New("permission check skipped")
	ErrConnectionDenied     = errors.New("You are not allowed to connect")
)

var (
	// Config is the configuration for the supported protocols
	Config Configuration
	// Connections is the list of active connections
	Connections ActiveConnections
	// QuotaScans is the list of active quota scans
	QuotaScans            ActiveScans
	idleTimeoutTicker     *time.Ticker
	idleTimeoutTickerDone chan bool
	supportedProtocols    = []string{ProtocolSFTP, ProtocolSCP, ProtocolSSH, ProtocolFTP, ProtocolWebDAV}
)

// Initialize sets the common configuration
func Initialize(c Configuration) {
	Config = c
	Config.idleLoginTimeout = 2 * time.Minute
	Config.idleTimeoutAsDuration = time.Duration(Config.IdleTimeout) * time.Minute
	if Config.IdleTimeout > 0 {
		startIdleTimeoutTicker(idleTimeoutCheckInterval)
	}
}

func startIdleTimeoutTicker(duration time.Duration) {
	stopIdleTimeoutTicker()
	idleTimeoutTicker = time.NewTicker(duration)
	idleTimeoutTickerDone = make(chan bool)
	go func() {
		for {
			select {
			case <-idleTimeoutTickerDone:
				return
			case <-idleTimeoutTicker.C:
				Connections.checkIdleConnections()
			}
		}
	}()
}

func stopIdleTimeoutTicker() {
	if idleTimeoutTicker != nil {
		idleTimeoutTicker.Stop()
		idleTimeoutTickerDone <- true
		idleTimeoutTicker = nil
	}
}

// ActiveTransfer defines the interface for the current active transfers
type ActiveTransfer interface {
	GetID() uint64
	GetType() int
	GetSize() int64
	GetVirtualPath() string
	GetStartTime() time.Time
	SignalClose()
}

// ActiveConnection defines the interface for the current active connections
type ActiveConnection interface {
	GetID() string
	GetUsername() string
	GetRemoteAddress() string
	GetClientVersion() string
	GetProtocol() string
	GetConnectionTime() time.Time
	GetLastActivity() time.Time
	GetCommand() string
	Disconnect() error
	SetConnDeadline()
	AddTransfer(t ActiveTransfer)
	RemoveTransfer(t ActiveTransfer)
	GetTransfers() []ConnectionTransfer
}

// StatAttributes defines the attributes for set stat commands
type StatAttributes struct {
	Mode  os.FileMode
	Atime time.Time
	Mtime time.Time
	UID   int
	GID   int
	Flags int
}

// ConnectionTransfer defines the trasfer details to expose
type ConnectionTransfer struct {
	ID            uint64 `json:"-"`
	OperationType string `json:"operation_type"`
	StartTime     int64  `json:"start_time"`
	Size          int64  `json:"size"`
	VirtualPath   string `json:"path"`
}

func (t *ConnectionTransfer) getConnectionTransferAsString() string {
	result := ""
	switch t.OperationType {
	case operationUpload:
		result += "UL "
	case operationDownload:
		result += "DL "
	}
	result += fmt.Sprintf("%#v ", t.VirtualPath)
	if t.Size > 0 {
		elapsed := time.Since(utils.GetTimeFromMsecSinceEpoch(t.StartTime))
		speed := float64(t.Size) / float64(utils.GetTimeAsMsSinceEpoch(time.Now())-t.StartTime)
		result += fmt.Sprintf("Size: %#v Elapsed: %#v Speed: \"%.1f KB/s\"", utils.ByteCountSI(t.Size),
			utils.GetDurationAsString(elapsed), speed)
	}
	return result
}

// Configuration defines configuration parameters common to all supported protocols
type Configuration struct {
	// Maximum idle timeout as minutes. If a client is idle for a time that exceeds this setting it will be disconnected.
	// 0 means disabled
	IdleTimeout int `json:"idle_timeout" mapstructure:"idle_timeout"`
	// UploadMode 0 means standard, the files are uploaded directly to the requested path.
	// 1 means atomic: the files are uploaded to a temporary path and renamed to the requested path
	// when the client ends the upload. Atomic mode avoid problems such as a web server that
	// serves partial files when the files are being uploaded.
	// In atomic mode if there is an upload error the temporary file is deleted and so the requested
	// upload path will not contain a partial file.
	// 2 means atomic with resume support: as atomic but if there is an upload error the temporary
	// file is renamed to the requested path and not deleted, this way a client can reconnect and resume
	// the upload.
	UploadMode int `json:"upload_mode" mapstructure:"upload_mode"`
	// Actions to execute for SFTP file operations and SSH commands
	Actions ProtocolActions `json:"actions" mapstructure:"actions"`
	// SetstatMode 0 means "normal mode": requests for changing permissions and owner/group are executed.
	// 1 means "ignore mode": requests for changing permissions and owner/group are silently ignored.
	SetstatMode int `json:"setstat_mode" mapstructure:"setstat_mode"`
	// Support for HAProxy PROXY protocol.
	// If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable
	// the proxy protocol. It provides a convenient way to safely transport connection information
	// such as a client's address across multiple layers of NAT or TCP proxies to get the real
	// client IP address instead of the proxy IP. Both protocol versions 1 and 2 are supported.
	// - 0 means disabled
	// - 1 means proxy protocol enabled. Proxy header will be used and requests without proxy header will be accepted.
	// - 2 means proxy protocol required. Proxy header will be used and requests without proxy header will be rejected.
	// If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too,
	// for example for HAProxy add "send-proxy" or "send-proxy-v2" to each server configuration line.
	ProxyProtocol int `json:"proxy_protocol" mapstructure:"proxy_protocol"`
	// List of IP addresses and IP ranges allowed to send the proxy header.
	// If proxy protocol is set to 1 and we receive a proxy header from an IP that is not in the list then the
	// connection will be accepted and the header will be ignored.
	// If proxy protocol is set to 2 and we receive a proxy header from an IP that is not in the list then the
	// connection will be rejected.
	ProxyAllowed []string `json:"proxy_allowed" mapstructure:"proxy_allowed"`
	// Absolute path to an external program or an HTTP URL to invoke after a user connects
	// and before he tries to login. It allows you to reject the connection based on the source
	// ip address. Leave empty do disable.
	PostConnectHook       string `json:"post_connect_hook" mapstructure:"post_connect_hook"`
	idleTimeoutAsDuration time.Duration
	idleLoginTimeout      time.Duration
}

// IsAtomicUploadEnabled returns true if atomic upload is enabled
func (c *Configuration) IsAtomicUploadEnabled() bool {
	return c.UploadMode == UploadModeAtomic || c.UploadMode == UploadModeAtomicWithResume
}

// GetProxyListener returns a wrapper for the given listener that supports the
// HAProxy Proxy Protocol or nil if the proxy protocol is not configured
func (c *Configuration) GetProxyListener(listener net.Listener) (*proxyproto.Listener, error) {
	var proxyListener *proxyproto.Listener
	var err error
	if c.ProxyProtocol > 0 {
		var policyFunc func(upstream net.Addr) (proxyproto.Policy, error)
		if c.ProxyProtocol == 1 && len(c.ProxyAllowed) > 0 {
			policyFunc, err = proxyproto.LaxWhiteListPolicy(c.ProxyAllowed)
			if err != nil {
				return nil, err
			}
		}
		if c.ProxyProtocol == 2 {
			if len(c.ProxyAllowed) == 0 {
				policyFunc = func(upstream net.Addr) (proxyproto.Policy, error) {
					return proxyproto.REQUIRE, nil
				}
			} else {
				policyFunc, err = proxyproto.StrictWhiteListPolicy(c.ProxyAllowed)
				if err != nil {
					return nil, err
				}
			}
		}
		proxyListener = &proxyproto.Listener{
			Listener: listener,
			Policy:   policyFunc,
		}
	}
	return proxyListener, nil
}

// ExecutePostConnectHook executes the post connect hook if defined
func (c *Configuration) ExecutePostConnectHook(remoteAddr, protocol string) error {
	if len(c.PostConnectHook) == 0 {
		return nil
	}
	ip := utils.GetIPFromRemoteAddress(remoteAddr)
	if strings.HasPrefix(c.PostConnectHook, "http") {
		var url *url.URL
		url, err := url.Parse(c.PostConnectHook)
		if err != nil {
			logger.Warn(protocol, "", "Login from ip %#v denied, invalid post connect hook %#v: %v",
				ip, c.PostConnectHook, err)
			return err
		}
		httpClient := httpclient.GetHTTPClient()
		q := url.Query()
		q.Add("ip", ip)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()

		resp, err := httpClient.Get(url.String())
		if err != nil {
			logger.Warn(protocol, "", "Login from ip %#v denied, error executing post connect hook: %v", ip, err)
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logger.Warn(protocol, "", "Login from ip %#v denied, post connect hook response code: %v", ip, resp.StatusCode)
			return errUnexpectedHTTResponse
		}
		return nil
	}
	if !filepath.IsAbs(c.PostConnectHook) {
		err := fmt.Errorf("invalid post connect hook %#v", c.PostConnectHook)
		logger.Warn(protocol, "", "Login from ip %#v denied: %v", ip, err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.PostConnectHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_CONNECTION_IP=%v", ip),
		fmt.Sprintf("SFTPGO_CONNECTION_PROTOCOL=%v", protocol))
	err := cmd.Run()
	if err != nil {
		logger.Warn(protocol, "", "Login from ip %#v denied, connect hook error: %v", ip, err)
	}
	return err
}

// ActiveConnections holds the currect active connections with the associated transfers
type ActiveConnections struct {
	sync.RWMutex
	connections []ActiveConnection
}

// GetActiveSessions returns the number of active sessions for the given username.
// We return the open sessions for any protocol
func (conns *ActiveConnections) GetActiveSessions(username string) int {
	conns.RLock()
	defer conns.RUnlock()

	numSessions := 0
	for _, c := range conns.connections {
		if c.GetUsername() == username {
			numSessions++
		}
	}
	return numSessions
}

// Add adds a new connection to the active ones
func (conns *ActiveConnections) Add(c ActiveConnection) {
	conns.Lock()
	defer conns.Unlock()

	conns.connections = append(conns.connections, c)
	metrics.UpdateActiveConnectionsSize(len(conns.connections))
	logger.Debug(c.GetProtocol(), c.GetID(), "connection added, num open connections: %v", len(conns.connections))
}

// Swap replaces an existing connection with the given one.
// This method is useful if you have to change some connection details
// for example for FTP is used to update the connection once the user
// authenticates
func (conns *ActiveConnections) Swap(c ActiveConnection) error {
	conns.Lock()
	defer conns.Unlock()

	for idx, conn := range conns.connections {
		if conn.GetID() == c.GetID() {
			conn = nil
			conns.connections[idx] = c
			return nil
		}
	}
	return errors.New("connection to swap not found")
}

// Remove removes a connection from the active ones
func (conns *ActiveConnections) Remove(connectionID string) {
	conns.Lock()
	defer conns.Unlock()

	var c ActiveConnection
	indexToRemove := -1
	for i, conn := range conns.connections {
		if conn.GetID() == connectionID {
			indexToRemove = i
			c = conn
			break
		}
	}
	if indexToRemove >= 0 {
		conns.connections[indexToRemove] = conns.connections[len(conns.connections)-1]
		conns.connections[len(conns.connections)-1] = nil
		conns.connections = conns.connections[:len(conns.connections)-1]
		metrics.UpdateActiveConnectionsSize(len(conns.connections))
		logger.Debug(c.GetProtocol(), c.GetID(), "connection removed, num open connections: %v",
			len(conns.connections))
		// we have finished to send data here and most of the time the underlying network connection
		// is already closed. Sometime a client can still be reading the last sended data, so we set
		// a deadline instead of directly closing the network connection.
		// Setting a deadline on an already closed connection has no effect.
		// We only need to ensure that a connection will not remain indefinitely open and so the
		// underlying file descriptor is not released.
		// This should protect us against buggy clients and edge cases.
		c.SetConnDeadline()
	} else {
		logger.Warn(logSender, "", "connection to remove with id %#v not found!", connectionID)
	}
}

// Close closes an active connection.
// It returns true on success
func (conns *ActiveConnections) Close(connectionID string) bool {
	conns.RLock()
	result := false

	for _, c := range conns.connections {
		if c.GetID() == connectionID {
			defer func(conn ActiveConnection) {
				err := conn.Disconnect()
				logger.Debug(conn.GetProtocol(), conn.GetID(), "close connection requested, close err: %v", err)
			}(c)
			result = true
			break
		}
	}

	conns.RUnlock()
	return result
}

func (conns *ActiveConnections) checkIdleConnections() {
	conns.RLock()

	for _, c := range conns.connections {
		idleTime := time.Since(c.GetLastActivity())
		isUnauthenticatedFTPUser := (c.GetProtocol() == ProtocolFTP && len(c.GetUsername()) == 0)

		if idleTime > Config.idleTimeoutAsDuration || (isUnauthenticatedFTPUser && idleTime > Config.idleLoginTimeout) {
			defer func(conn ActiveConnection, isFTPNoAuth bool) {
				err := conn.Disconnect()
				logger.Debug(conn.GetProtocol(), conn.GetID(), "close idle connection, idle time: %v, username: %#v close err: %v",
					idleTime, conn.GetUsername(), err)
				if isFTPNoAuth {
					logger.ConnectionFailedLog("", utils.GetIPFromRemoteAddress(c.GetRemoteAddress()),
						"no_auth_tryed", "client idle")
					metrics.AddNoAuthTryed()
				}
			}(c, isUnauthenticatedFTPUser)
		}
	}

	conns.RUnlock()
}

// GetStats returns stats for active connections
func (conns *ActiveConnections) GetStats() []ConnectionStatus {
	conns.RLock()
	defer conns.RUnlock()

	stats := make([]ConnectionStatus, 0, len(conns.connections))
	for _, c := range conns.connections {
		stat := ConnectionStatus{
			Username:       c.GetUsername(),
			ConnectionID:   c.GetID(),
			ClientVersion:  c.GetClientVersion(),
			RemoteAddress:  c.GetRemoteAddress(),
			ConnectionTime: utils.GetTimeAsMsSinceEpoch(c.GetConnectionTime()),
			LastActivity:   utils.GetTimeAsMsSinceEpoch(c.GetLastActivity()),
			Protocol:       c.GetProtocol(),
			Command:        c.GetCommand(),
			Transfers:      c.GetTransfers(),
		}
		stats = append(stats, stat)
	}
	return stats
}

// ConnectionStatus returns the status for an active connection
type ConnectionStatus struct {
	// Logged in username
	Username string `json:"username"`
	// Unique identifier for the connection
	ConnectionID string `json:"connection_id"`
	// client's version string
	ClientVersion string `json:"client_version,omitempty"`
	// Remote address for this connection
	RemoteAddress string `json:"remote_address"`
	// Connection time as unix timestamp in milliseconds
	ConnectionTime int64 `json:"connection_time"`
	// Last activity as unix timestamp in milliseconds
	LastActivity int64 `json:"last_activity"`
	// Protocol for this connection
	Protocol string `json:"protocol"`
	// active uploads/downloads
	Transfers []ConnectionTransfer `json:"active_transfers,omitempty"`
	// SSH command or WevDAV method
	Command string `json:"command,omitempty"`
}

// GetConnectionDuration returns the connection duration as string
func (c ConnectionStatus) GetConnectionDuration() string {
	elapsed := time.Since(utils.GetTimeFromMsecSinceEpoch(c.ConnectionTime))
	return utils.GetDurationAsString(elapsed)
}

// GetConnectionInfo returns connection info.
// Protocol,Client Version and RemoteAddress are returned.
// For SSH commands the issued command is returned too.
func (c ConnectionStatus) GetConnectionInfo() string {
	result := fmt.Sprintf("%v. Client: %#v From: %#v", c.Protocol, c.ClientVersion, c.RemoteAddress)
	if c.Protocol == ProtocolSSH && len(c.Command) > 0 {
		result += fmt.Sprintf(". Command: %#v", c.Command)
	}
	if c.Protocol == ProtocolWebDAV && len(c.Command) > 0 {
		result += fmt.Sprintf(". Method: %#v", c.Command)
	}
	return result
}

// GetTransfersAsString returns the active transfers as string
func (c ConnectionStatus) GetTransfersAsString() string {
	result := ""
	for _, t := range c.Transfers {
		if len(result) > 0 {
			result += ". "
		}
		result += t.getConnectionTransferAsString()
	}
	return result
}

// ActiveQuotaScan defines an active quota scan for a user home dir
type ActiveQuotaScan struct {
	// Username to which the quota scan refers
	Username string `json:"username"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// ActiveVirtualFolderQuotaScan defines an active quota scan for a virtual folder
type ActiveVirtualFolderQuotaScan struct {
	// folder path to which the quota scan refers
	MappedPath string `json:"mapped_path"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// ActiveScans holds the active quota scans
type ActiveScans struct {
	sync.RWMutex
	UserHomeScans []ActiveQuotaScan
	FolderScans   []ActiveVirtualFolderQuotaScan
}

// GetUsersQuotaScans returns the active quota scans for users home directories
func (s *ActiveScans) GetUsersQuotaScans() []ActiveQuotaScan {
	s.RLock()
	defer s.RUnlock()

	scans := make([]ActiveQuotaScan, len(s.UserHomeScans))
	copy(scans, s.UserHomeScans)
	return scans
}

// AddUserQuotaScan adds a user to the ones with active quota scans.
// Returns false if the user has a quota scan already running
func (s *ActiveScans) AddUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.UserHomeScans {
		if scan.Username == username {
			return false
		}
	}
	s.UserHomeScans = append(s.UserHomeScans, ActiveQuotaScan{
		Username:  username,
		StartTime: utils.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveUserQuotaScan removes a user from the ones with active quota scans.
// Returns false if the user has no active quota scans
func (s *ActiveScans) RemoveUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	indexToRemove := -1
	for i, scan := range s.UserHomeScans {
		if scan.Username == username {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		s.UserHomeScans[indexToRemove] = s.UserHomeScans[len(s.UserHomeScans)-1]
		s.UserHomeScans = s.UserHomeScans[:len(s.UserHomeScans)-1]
		return true
	}
	return false
}

// GetVFoldersQuotaScans returns the active quota scans for virtual folders
func (s *ActiveScans) GetVFoldersQuotaScans() []ActiveVirtualFolderQuotaScan {
	s.RLock()
	defer s.RUnlock()
	scans := make([]ActiveVirtualFolderQuotaScan, len(s.FolderScans))
	copy(scans, s.FolderScans)
	return scans
}

// AddVFolderQuotaScan adds a virtual folder to the ones with active quota scans.
// Returns false if the folder has a quota scan already running
func (s *ActiveScans) AddVFolderQuotaScan(folderPath string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.FolderScans {
		if scan.MappedPath == folderPath {
			return false
		}
	}
	s.FolderScans = append(s.FolderScans, ActiveVirtualFolderQuotaScan{
		MappedPath: folderPath,
		StartTime:  utils.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveVFolderQuotaScan removes a folder from the ones with active quota scans.
// Returns false if the folder has no active quota scans
func (s *ActiveScans) RemoveVFolderQuotaScan(folderPath string) bool {
	s.Lock()
	defer s.Unlock()

	indexToRemove := -1
	for i, scan := range s.FolderScans {
		if scan.MappedPath == folderPath {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		s.FolderScans[indexToRemove] = s.FolderScans[len(s.FolderScans)-1]
		s.FolderScans = s.FolderScans[:len(s.FolderScans)-1]
		return true
	}
	return false
}
