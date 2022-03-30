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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

// constants
const (
	logSender         = "common"
	uploadLogSender   = "Upload"
	downloadLogSender = "Download"
	renameLogSender   = "Rename"
	rmdirLogSender    = "Rmdir"
	mkdirLogSender    = "Mkdir"
	symlinkLogSender  = "Symlink"
	removeLogSender   = "Remove"
	chownLogSender    = "Chown"
	chmodLogSender    = "Chmod"
	chtimesLogSender  = "Chtimes"
	truncateLogSender = "Truncate"
	operationDownload = "download"
	operationUpload   = "upload"
	operationDelete   = "delete"
	// Pre-download action name
	OperationPreDownload = "pre-download"
	// Pre-upload action name
	OperationPreUpload = "pre-upload"
	operationPreDelete = "pre-delete"
	operationRename    = "rename"
	operationMkdir     = "mkdir"
	operationRmdir     = "rmdir"
	// SSH command action name
	OperationSSHCmd              = "ssh_cmd"
	chtimesFormat                = "2006-01-02T15:04:05" // YYYY-MM-DDTHH:MM:SS
	idleTimeoutCheckInterval     = 3 * time.Minute
	periodicTimeoutCheckInterval = 1 * time.Minute
)

// Stat flags
const (
	StatAttrUIDGID = 1
	StatAttrPerms  = 2
	StatAttrTimes  = 4
	StatAttrSize   = 8
)

// Transfer types
const (
	TransferUpload = iota
	TransferDownload
)

// Supported protocols
const (
	ProtocolSFTP          = "SFTP"
	ProtocolSCP           = "SCP"
	ProtocolSSH           = "SSH"
	ProtocolFTP           = "FTP"
	ProtocolWebDAV        = "DAV"
	ProtocolHTTP          = "HTTP"
	ProtocolHTTPShare     = "HTTPShare"
	ProtocolDataRetention = "DataRetention"
	ProtocolOIDC          = "OIDC"
)

// Upload modes
const (
	UploadModeStandard = iota
	UploadModeAtomic
	UploadModeAtomicWithResume
)

func init() {
	Connections.clients = clientsMap{
		clients: make(map[string]int),
	}
}

// errors definitions
var (
	ErrPermissionDenied     = errors.New("permission denied")
	ErrNotExist             = errors.New("no such file or directory")
	ErrOpUnsupported        = errors.New("operation unsupported")
	ErrGenericFailure       = errors.New("failure")
	ErrQuotaExceeded        = errors.New("denying write due to space limit")
	ErrReadQuotaExceeded    = errors.New("denying read due to quota limit")
	ErrSkipPermissionsCheck = errors.New("permission check skipped")
	ErrConnectionDenied     = errors.New("you are not allowed to connect")
	ErrNoBinding            = errors.New("no binding configured")
	ErrCrtRevoked           = errors.New("your certificate has been revoked")
	ErrNoCredentials        = errors.New("no credential provided")
	ErrInternalFailure      = errors.New("internal failure")
	ErrTransferAborted      = errors.New("transfer aborted")
	errNoTransfer           = errors.New("requested transfer not found")
	errTransferMismatch     = errors.New("transfer mismatch")
)

var (
	// Config is the configuration for the supported protocols
	Config Configuration
	// Connections is the list of active connections
	Connections ActiveConnections
	// QuotaScans is the list of active quota scans
	QuotaScans                ActiveScans
	transfersChecker          TransfersChecker
	periodicTimeoutTicker     *time.Ticker
	periodicTimeoutTickerDone chan bool
	supportedProtocols        = []string{ProtocolSFTP, ProtocolSCP, ProtocolSSH, ProtocolFTP, ProtocolWebDAV,
		ProtocolHTTP, ProtocolHTTPShare, ProtocolOIDC}
	disconnHookProtocols = []string{ProtocolSFTP, ProtocolSCP, ProtocolSSH, ProtocolFTP}
	// the map key is the protocol, for each protocol we can have multiple rate limiters
	rateLimiters map[string][]*rateLimiter
)

// Initialize sets the common configuration
func Initialize(c Configuration, isShared int) error {
	Config = c
	Config.idleLoginTimeout = 2 * time.Minute
	Config.idleTimeoutAsDuration = time.Duration(Config.IdleTimeout) * time.Minute
	startPeriodicTimeoutTicker(periodicTimeoutCheckInterval)
	Config.defender = nil
	Config.whitelist = nil
	rateLimiters = make(map[string][]*rateLimiter)
	for _, rlCfg := range c.RateLimitersConfig {
		if rlCfg.isEnabled() {
			if err := rlCfg.validate(); err != nil {
				return fmt.Errorf("rate limiters initialization error: %w", err)
			}
			allowList, err := util.ParseAllowedIPAndRanges(rlCfg.AllowList)
			if err != nil {
				return fmt.Errorf("unable to parse rate limiter allow list %v: %v", rlCfg.AllowList, err)
			}
			rateLimiter := rlCfg.getLimiter()
			rateLimiter.allowList = allowList
			for _, protocol := range rlCfg.Protocols {
				rateLimiters[protocol] = append(rateLimiters[protocol], rateLimiter)
			}
		}
	}
	if c.DefenderConfig.Enabled {
		if !util.IsStringInSlice(c.DefenderConfig.Driver, supportedDefenderDrivers) {
			return fmt.Errorf("unsupported defender driver %#v", c.DefenderConfig.Driver)
		}
		var defender Defender
		var err error
		switch c.DefenderConfig.Driver {
		case DefenderDriverProvider:
			defender, err = newDBDefender(&c.DefenderConfig)
		default:
			defender, err = newInMemoryDefender(&c.DefenderConfig)
		}
		if err != nil {
			return fmt.Errorf("defender initialization error: %v", err)
		}
		logger.Info(logSender, "", "defender initialized with config %+v", c.DefenderConfig)
		Config.defender = defender
	}
	if c.WhiteListFile != "" {
		whitelist := &whitelist{
			fileName: c.WhiteListFile,
		}
		if err := whitelist.reload(); err != nil {
			return fmt.Errorf("whitelist initialization error: %w", err)
		}
		logger.Info(logSender, "", "whitelist initialized from file: %#v", c.WhiteListFile)
		Config.whitelist = whitelist
	}
	vfs.SetTempPath(c.TempPath)
	dataprovider.SetTempPath(c.TempPath)
	transfersChecker = getTransfersChecker(isShared)
	return nil
}

// LimitRate blocks until all the configured rate limiters
// allow one event to happen.
// It returns an error if the time to wait exceeds the max
// allowed delay
func LimitRate(protocol, ip string) (time.Duration, error) {
	for _, limiter := range rateLimiters[protocol] {
		if delay, err := limiter.Wait(ip); err != nil {
			logger.Debug(logSender, "", "protocol %v ip %v: %v", protocol, ip, err)
			return delay, err
		}
	}
	return 0, nil
}

// Reload reloads the whitelist, the IP filter plugin and the defender's block and safe lists
func Reload() error {
	plugin.Handler.ReloadFilter()
	var errWithelist error
	if Config.whitelist != nil {
		errWithelist = Config.whitelist.reload()
	}
	if Config.defender == nil {
		return errWithelist
	}
	if err := Config.defender.Reload(); err != nil {
		return err
	}
	return errWithelist
}

// IsBanned returns true if the specified IP address is banned
func IsBanned(ip string) bool {
	if plugin.Handler.IsIPBanned(ip) {
		return true
	}
	if Config.defender == nil {
		return false
	}

	return Config.defender.IsBanned(ip)
}

// GetDefenderBanTime returns the ban time for the given IP
// or nil if the IP is not banned or the defender is disabled
func GetDefenderBanTime(ip string) (*time.Time, error) {
	if Config.defender == nil {
		return nil, nil
	}

	return Config.defender.GetBanTime(ip)
}

// GetDefenderHosts returns hosts that are banned or for which some violations have been detected
func GetDefenderHosts() ([]dataprovider.DefenderEntry, error) {
	if Config.defender == nil {
		return nil, nil
	}

	return Config.defender.GetHosts()
}

// GetDefenderHost returns a defender host by ip, if any
func GetDefenderHost(ip string) (dataprovider.DefenderEntry, error) {
	if Config.defender == nil {
		return dataprovider.DefenderEntry{}, errors.New("defender is disabled")
	}

	return Config.defender.GetHost(ip)
}

// DeleteDefenderHost removes the specified IP address from the defender lists
func DeleteDefenderHost(ip string) bool {
	if Config.defender == nil {
		return false
	}

	return Config.defender.DeleteHost(ip)
}

// GetDefenderScore returns the score for the given IP
func GetDefenderScore(ip string) (int, error) {
	if Config.defender == nil {
		return 0, nil
	}

	return Config.defender.GetScore(ip)
}

// AddDefenderEvent adds the specified defender event for the given IP
func AddDefenderEvent(ip string, event HostEvent) {
	if Config.defender == nil {
		return
	}

	Config.defender.AddEvent(ip, event)
}

// the ticker cannot be started/stopped from multiple goroutines
func startPeriodicTimeoutTicker(duration time.Duration) {
	stopPeriodicTimeoutTicker()
	periodicTimeoutTicker = time.NewTicker(duration)
	periodicTimeoutTickerDone = make(chan bool)
	go func() {
		counter := int64(0)
		ratio := idleTimeoutCheckInterval / periodicTimeoutCheckInterval
		for {
			select {
			case <-periodicTimeoutTickerDone:
				return
			case <-periodicTimeoutTicker.C:
				counter++
				if Config.IdleTimeout > 0 && counter >= int64(ratio) {
					counter = 0
					Connections.checkIdles()
				}
				go Connections.checkTransfers()
			}
		}
	}()
}

func stopPeriodicTimeoutTicker() {
	if periodicTimeoutTicker != nil {
		periodicTimeoutTicker.Stop()
		periodicTimeoutTickerDone <- true
		periodicTimeoutTicker = nil
	}
}

// ActiveTransfer defines the interface for the current active transfers
type ActiveTransfer interface {
	GetID() int64
	GetType() int
	GetSize() int64
	GetDownloadedSize() int64
	GetUploadedSize() int64
	GetVirtualPath() string
	GetStartTime() time.Time
	SignalClose(err error)
	Truncate(fsPath string, size int64) (int64, error)
	GetRealFsPath(fsPath string) string
	SetTimes(fsPath string, atime time.Time, mtime time.Time) bool
	GetTruncatedSize() int64
	HasSizeLimit() bool
}

// ActiveConnection defines the interface for the current active connections
type ActiveConnection interface {
	GetID() string
	GetUsername() string
	GetLocalAddress() string
	GetRemoteAddress() string
	GetClientVersion() string
	GetProtocol() string
	GetConnectionTime() time.Time
	GetLastActivity() time.Time
	GetCommand() string
	Disconnect() error
	AddTransfer(t ActiveTransfer)
	RemoveTransfer(t ActiveTransfer)
	GetTransfers() []ConnectionTransfer
	SignalTransferClose(transferID int64, err error)
	CloseFS() error
}

// StatAttributes defines the attributes for set stat commands
type StatAttributes struct {
	Mode  os.FileMode
	Atime time.Time
	Mtime time.Time
	UID   int
	GID   int
	Flags int
	Size  int64
}

// ConnectionTransfer defines the trasfer details to expose
type ConnectionTransfer struct {
	ID            int64  `json:"-"`
	OperationType string `json:"operation_type"`
	StartTime     int64  `json:"start_time"`
	Size          int64  `json:"size"`
	VirtualPath   string `json:"path"`
	HasSizeLimit  bool   `json:"-"`
	ULSize        int64  `json:"-"`
	DLSize        int64  `json:"-"`
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
		elapsed := time.Since(util.GetTimeFromMsecSinceEpoch(t.StartTime))
		speed := float64(t.Size) / float64(util.GetTimeAsMsSinceEpoch(time.Now())-t.StartTime)
		result += fmt.Sprintf("Size: %#v Elapsed: %#v Speed: \"%.1f KB/s\"", util.ByteCountIEC(t.Size),
			util.GetDurationAsString(elapsed), speed)
	}
	return result
}

type whitelist struct {
	fileName string
	sync.RWMutex
	list HostList
}

func (l *whitelist) reload() error {
	list, err := loadHostListFromFile(l.fileName)
	if err != nil {
		return err
	}
	if list == nil {
		return errors.New("cannot accept a nil whitelist")
	}

	l.Lock()
	defer l.Unlock()

	l.list = *list
	return nil
}

func (l *whitelist) isAllowed(ip string) bool {
	l.RLock()
	defer l.RUnlock()

	return l.list.isListed(ip)
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
	// 2 means "ignore mode for cloud fs": requests for changing permissions and owner/group are
	// silently ignored for cloud based filesystem such as S3, GCS, Azure Blob. Requests  for changing
	// modification times are ignored for cloud based filesystem if they are not supported.
	SetstatMode int `json:"setstat_mode" mapstructure:"setstat_mode"`
	// TempPath defines the path for temporary files such as those used for atomic uploads or file pipes.
	// If you set this option you must make sure that the defined path exists, is accessible for writing
	// by the user running SFTPGo, and is on the same filesystem as the users home directories otherwise
	// the renaming for atomic uploads will become a copy and therefore may take a long time.
	// The temporary files are not namespaced. The default is generally fine. Leave empty for the default.
	TempPath string `json:"temp_path" mapstructure:"temp_path"`
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
	// Absolute path to an external program or an HTTP URL to invoke as soon as SFTPGo starts.
	// If you define an HTTP URL it will be invoked using a `GET` request.
	// Please note that SFTPGo services may not yet be available when this hook is run.
	// Leave empty do disable.
	StartupHook string `json:"startup_hook" mapstructure:"startup_hook"`
	// Absolute path to an external program or an HTTP URL to invoke after a user connects
	// and before he tries to login. It allows you to reject the connection based on the source
	// ip address. Leave empty do disable.
	PostConnectHook string `json:"post_connect_hook" mapstructure:"post_connect_hook"`
	// Absolute path to an external program or an HTTP URL to invoke after an SSH/FTP connection ends.
	// Leave empty do disable.
	PostDisconnectHook string `json:"post_disconnect_hook" mapstructure:"post_disconnect_hook"`
	// Absolute path to an external program or an HTTP URL to invoke after a data retention check completes.
	// Leave empty do disable.
	DataRetentionHook string `json:"data_retention_hook" mapstructure:"data_retention_hook"`
	// Maximum number of concurrent client connections. 0 means unlimited
	MaxTotalConnections int `json:"max_total_connections" mapstructure:"max_total_connections"`
	// Maximum number of concurrent client connections from the same host (IP). 0 means unlimited
	MaxPerHostConnections int `json:"max_per_host_connections" mapstructure:"max_per_host_connections"`
	// Path to a file containing a list of IP addresses and/or networks to allow.
	// Only the listed IPs/networks can access the configured services, all other client connections
	// will be dropped before they even try to authenticate.
	WhiteListFile string `json:"whitelist_file" mapstructure:"whitelist_file"`
	// Defender configuration
	DefenderConfig DefenderConfig `json:"defender" mapstructure:"defender"`
	// Rate limiter configurations
	RateLimitersConfig    []RateLimiterConfig `json:"rate_limiters" mapstructure:"rate_limiters"`
	idleTimeoutAsDuration time.Duration
	idleLoginTimeout      time.Duration
	defender              Defender
	whitelist             *whitelist
}

// IsAtomicUploadEnabled returns true if atomic upload is enabled
func (c *Configuration) IsAtomicUploadEnabled() bool {
	return c.UploadMode == UploadModeAtomic || c.UploadMode == UploadModeAtomicWithResume
}

// GetProxyListener returns a wrapper for the given listener that supports the
// HAProxy Proxy Protocol
func (c *Configuration) GetProxyListener(listener net.Listener) (*proxyproto.Listener, error) {
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
		return &proxyproto.Listener{
			Listener:          listener,
			Policy:            policyFunc,
			ReadHeaderTimeout: 5 * time.Second,
		}, nil
	}
	return nil, errors.New("proxy protocol not configured")
}

// ExecuteStartupHook runs the startup hook if defined
func (c *Configuration) ExecuteStartupHook() error {
	if c.StartupHook == "" {
		return nil
	}
	if strings.HasPrefix(c.StartupHook, "http") {
		var url *url.URL
		url, err := url.Parse(c.StartupHook)
		if err != nil {
			logger.Warn(logSender, "", "Invalid startup hook %#v: %v", c.StartupHook, err)
			return err
		}
		startTime := time.Now()
		resp, err := httpclient.RetryableGet(url.String())
		if err != nil {
			logger.Warn(logSender, "", "Error executing startup hook: %v", err)
			return err
		}
		defer resp.Body.Close()
		logger.Debug(logSender, "", "Startup hook executed, elapsed: %v, response code: %v", time.Since(startTime), resp.StatusCode)
		return nil
	}
	if !filepath.IsAbs(c.StartupHook) {
		err := fmt.Errorf("invalid startup hook %#v", c.StartupHook)
		logger.Warn(logSender, "", "Invalid startup hook %#v", c.StartupHook)
		return err
	}
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.StartupHook)
	err := cmd.Run()
	logger.Debug(logSender, "", "Startup hook executed, elapsed: %v, error: %v", time.Since(startTime), err)
	return nil
}

func (c *Configuration) executePostDisconnectHook(remoteAddr, protocol, username, connID string, connectionTime time.Time) {
	ipAddr := util.GetIPFromRemoteAddress(remoteAddr)
	connDuration := int64(time.Since(connectionTime) / time.Millisecond)

	if strings.HasPrefix(c.PostDisconnectHook, "http") {
		var url *url.URL
		url, err := url.Parse(c.PostDisconnectHook)
		if err != nil {
			logger.Warn(protocol, connID, "Invalid post disconnect hook %#v: %v", c.PostDisconnectHook, err)
			return
		}
		q := url.Query()
		q.Add("ip", ipAddr)
		q.Add("protocol", protocol)
		q.Add("username", username)
		q.Add("connection_duration", strconv.FormatInt(connDuration, 10))
		url.RawQuery = q.Encode()
		startTime := time.Now()
		resp, err := httpclient.RetryableGet(url.String())
		respCode := 0
		if err == nil {
			respCode = resp.StatusCode
			resp.Body.Close()
		}
		logger.Debug(protocol, connID, "Post disconnect hook response code: %v, elapsed: %v, err: %v",
			respCode, time.Since(startTime), err)
		return
	}
	if !filepath.IsAbs(c.PostDisconnectHook) {
		logger.Debug(protocol, connID, "invalid post disconnect hook %#v", c.PostDisconnectHook)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, c.PostDisconnectHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_CONNECTION_IP=%v", ipAddr),
		fmt.Sprintf("SFTPGO_CONNECTION_USERNAME=%v", username),
		fmt.Sprintf("SFTPGO_CONNECTION_DURATION=%v", connDuration),
		fmt.Sprintf("SFTPGO_CONNECTION_PROTOCOL=%v", protocol))
	err := cmd.Run()
	logger.Debug(protocol, connID, "Post disconnect hook executed, elapsed: %v error: %v", time.Since(startTime), err)
}

func (c *Configuration) checkPostDisconnectHook(remoteAddr, protocol, username, connID string, connectionTime time.Time) {
	if c.PostDisconnectHook == "" {
		return
	}
	if !util.IsStringInSlice(protocol, disconnHookProtocols) {
		return
	}
	go c.executePostDisconnectHook(remoteAddr, protocol, username, connID, connectionTime)
}

// ExecutePostConnectHook executes the post connect hook if defined
func (c *Configuration) ExecutePostConnectHook(ipAddr, protocol string) error {
	if c.PostConnectHook == "" {
		return nil
	}
	if strings.HasPrefix(c.PostConnectHook, "http") {
		var url *url.URL
		url, err := url.Parse(c.PostConnectHook)
		if err != nil {
			logger.Warn(protocol, "", "Login from ip %#v denied, invalid post connect hook %#v: %v",
				ipAddr, c.PostConnectHook, err)
			return err
		}
		q := url.Query()
		q.Add("ip", ipAddr)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()

		resp, err := httpclient.RetryableGet(url.String())
		if err != nil {
			logger.Warn(protocol, "", "Login from ip %#v denied, error executing post connect hook: %v", ipAddr, err)
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logger.Warn(protocol, "", "Login from ip %#v denied, post connect hook response code: %v", ipAddr, resp.StatusCode)
			return errUnexpectedHTTResponse
		}
		return nil
	}
	if !filepath.IsAbs(c.PostConnectHook) {
		err := fmt.Errorf("invalid post connect hook %#v", c.PostConnectHook)
		logger.Warn(protocol, "", "Login from ip %#v denied: %v", ipAddr, err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.PostConnectHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_CONNECTION_IP=%v", ipAddr),
		fmt.Sprintf("SFTPGO_CONNECTION_PROTOCOL=%v", protocol))
	err := cmd.Run()
	if err != nil {
		logger.Warn(protocol, "", "Login from ip %#v denied, connect hook error: %v", ipAddr, err)
	}
	return err
}

// SSHConnection defines an ssh connection.
// Each SSH connection can open several channels for SFTP or SSH commands
type SSHConnection struct {
	id           string
	conn         net.Conn
	lastActivity int64
}

// NewSSHConnection returns a new SSHConnection
func NewSSHConnection(id string, conn net.Conn) *SSHConnection {
	return &SSHConnection{
		id:           id,
		conn:         conn,
		lastActivity: time.Now().UnixNano(),
	}
}

// GetID returns the ID for this SSHConnection
func (c *SSHConnection) GetID() string {
	return c.id
}

// UpdateLastActivity updates last activity for this connection
func (c *SSHConnection) UpdateLastActivity() {
	atomic.StoreInt64(&c.lastActivity, time.Now().UnixNano())
}

// GetLastActivity returns the last connection activity
func (c *SSHConnection) GetLastActivity() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.lastActivity))
}

// Close closes the underlying network connection
func (c *SSHConnection) Close() error {
	return c.conn.Close()
}

// ActiveConnections holds the currect active connections with the associated transfers
type ActiveConnections struct {
	// clients contains both authenticated and estabilished connections and the ones waiting
	// for authentication
	clients              clientsMap
	transfersCheckStatus int32
	sync.RWMutex
	connections    []ActiveConnection
	sshConnections []*SSHConnection
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
	metric.UpdateActiveConnectionsSize(len(conns.connections))
	logger.Debug(c.GetProtocol(), c.GetID(), "connection added, local address %#v, remote address %#v, num open connections: %v",
		c.GetLocalAddress(), c.GetRemoteAddress(), len(conns.connections))
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
			err := conn.CloseFS()
			conns.connections[idx] = c
			logger.Debug(logSender, c.GetID(), "connection swapped, close fs error: %v", err)
			conn = nil
			return nil
		}
	}
	return errors.New("connection to swap not found")
}

// Remove removes a connection from the active ones
func (conns *ActiveConnections) Remove(connectionID string) {
	conns.Lock()
	defer conns.Unlock()

	for idx, conn := range conns.connections {
		if conn.GetID() == connectionID {
			err := conn.CloseFS()
			lastIdx := len(conns.connections) - 1
			conns.connections[idx] = conns.connections[lastIdx]
			conns.connections[lastIdx] = nil
			conns.connections = conns.connections[:lastIdx]
			metric.UpdateActiveConnectionsSize(lastIdx)
			logger.Debug(conn.GetProtocol(), conn.GetID(), "connection removed, local address %#v, remote address %#v close fs error: %v, num open connections: %v",
				conn.GetLocalAddress(), conn.GetRemoteAddress(), err, lastIdx)
			Config.checkPostDisconnectHook(conn.GetRemoteAddress(), conn.GetProtocol(), conn.GetUsername(),
				conn.GetID(), conn.GetConnectionTime())
			return
		}
	}
	logger.Warn(logSender, "", "connection id %#v to remove not found!", connectionID)
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

// AddSSHConnection adds a new ssh connection to the active ones
func (conns *ActiveConnections) AddSSHConnection(c *SSHConnection) {
	conns.Lock()
	defer conns.Unlock()

	conns.sshConnections = append(conns.sshConnections, c)
	logger.Debug(logSender, c.GetID(), "ssh connection added, num open connections: %v", len(conns.sshConnections))
}

// RemoveSSHConnection removes a connection from the active ones
func (conns *ActiveConnections) RemoveSSHConnection(connectionID string) {
	conns.Lock()
	defer conns.Unlock()

	for idx, conn := range conns.sshConnections {
		if conn.GetID() == connectionID {
			lastIdx := len(conns.sshConnections) - 1
			conns.sshConnections[idx] = conns.sshConnections[lastIdx]
			conns.sshConnections[lastIdx] = nil
			conns.sshConnections = conns.sshConnections[:lastIdx]
			logger.Debug(logSender, conn.GetID(), "ssh connection removed, num open ssh connections: %v", lastIdx)
			return
		}
	}
	logger.Warn(logSender, "", "ssh connection to remove with id %#v not found!", connectionID)
}

func (conns *ActiveConnections) checkIdles() {
	conns.RLock()

	for _, sshConn := range conns.sshConnections {
		idleTime := time.Since(sshConn.GetLastActivity())
		if idleTime > Config.idleTimeoutAsDuration {
			// we close an SSH connection if it has no active connections associated
			idToMatch := fmt.Sprintf("_%s_", sshConn.GetID())
			toClose := true
			for _, conn := range conns.connections {
				if strings.Contains(conn.GetID(), idToMatch) {
					if time.Since(conn.GetLastActivity()) <= Config.idleTimeoutAsDuration {
						toClose = false
						break
					}
				}
			}
			if toClose {
				defer func(c *SSHConnection) {
					err := c.Close()
					logger.Debug(logSender, c.GetID(), "close idle SSH connection, idle time: %v, close err: %v",
						time.Since(c.GetLastActivity()), err)
				}(sshConn)
			}
		}
	}

	for _, c := range conns.connections {
		idleTime := time.Since(c.GetLastActivity())
		isUnauthenticatedFTPUser := (c.GetProtocol() == ProtocolFTP && c.GetUsername() == "")

		if idleTime > Config.idleTimeoutAsDuration || (isUnauthenticatedFTPUser && idleTime > Config.idleLoginTimeout) {
			defer func(conn ActiveConnection, isFTPNoAuth bool) {
				err := conn.Disconnect()
				logger.Debug(conn.GetProtocol(), conn.GetID(), "close idle connection, idle time: %v, username: %#v close err: %v",
					time.Since(conn.GetLastActivity()), conn.GetUsername(), err)
				if isFTPNoAuth {
					ip := util.GetIPFromRemoteAddress(c.GetRemoteAddress())
					logger.ConnectionFailedLog("", ip, dataprovider.LoginMethodNoAuthTryed, c.GetProtocol(), "client idle")
					metric.AddNoAuthTryed()
					AddDefenderEvent(ip, HostEventNoLoginTried)
					dataprovider.ExecutePostLoginHook(&dataprovider.User{}, dataprovider.LoginMethodNoAuthTryed, ip, c.GetProtocol(),
						dataprovider.ErrNoAuthTryed)
				}
			}(c, isUnauthenticatedFTPUser)
		}
	}

	conns.RUnlock()
}

func (conns *ActiveConnections) checkTransfers() {
	if atomic.LoadInt32(&conns.transfersCheckStatus) == 1 {
		logger.Warn(logSender, "", "the previous transfer check is still running, skipping execution")
		return
	}
	atomic.StoreInt32(&conns.transfersCheckStatus, 1)
	defer atomic.StoreInt32(&conns.transfersCheckStatus, 0)

	conns.RLock()

	if len(conns.connections) < 2 {
		conns.RUnlock()
		return
	}
	var wg sync.WaitGroup
	logger.Debug(logSender, "", "start concurrent transfers check")

	// update the current size for transfers to monitors
	for _, c := range conns.connections {
		for _, t := range c.GetTransfers() {
			if t.HasSizeLimit {
				wg.Add(1)

				go func(transfer ConnectionTransfer, connID string) {
					defer wg.Done()
					transfersChecker.UpdateTransferCurrentSizes(transfer.ULSize, transfer.DLSize, transfer.ID, connID)
				}(t, c.GetID())
			}
		}
	}

	conns.RUnlock()
	logger.Debug(logSender, "", "waiting for the update of the transfers current size")
	wg.Wait()

	logger.Debug(logSender, "", "getting overquota transfers")
	overquotaTransfers := transfersChecker.GetOverquotaTransfers()
	logger.Debug(logSender, "", "number of overquota transfers: %v", len(overquotaTransfers))
	if len(overquotaTransfers) == 0 {
		return
	}

	conns.RLock()
	defer conns.RUnlock()

	for _, c := range conns.connections {
		for _, overquotaTransfer := range overquotaTransfers {
			if c.GetID() == overquotaTransfer.ConnID {
				logger.Info(logSender, c.GetID(), "user %#v is overquota, try to close transfer id %v",
					c.GetUsername(), overquotaTransfer.TransferID)
				var err error
				if overquotaTransfer.TransferType == TransferDownload {
					err = getReadQuotaExceededError(c.GetProtocol())
				} else {
					err = getQuotaExceededError(c.GetProtocol())
				}
				c.SignalTransferClose(overquotaTransfer.TransferID, err)
			}
		}
	}
	logger.Debug(logSender, "", "transfers check completed")
}

// AddClientConnection stores a new client connection
func (conns *ActiveConnections) AddClientConnection(ipAddr string) {
	conns.clients.add(ipAddr)
}

// RemoveClientConnection removes a disconnected client from the tracked ones
func (conns *ActiveConnections) RemoveClientConnection(ipAddr string) {
	conns.clients.remove(ipAddr)
}

// GetClientConnections returns the total number of client connections
func (conns *ActiveConnections) GetClientConnections() int32 {
	return conns.clients.getTotal()
}

// IsNewConnectionAllowed returns false if the maximum number of concurrent allowed connections is exceeded
// or a whitelist is defined and the specified ipAddr is not listed
func (conns *ActiveConnections) IsNewConnectionAllowed(ipAddr string) bool {
	if Config.whitelist != nil {
		if !Config.whitelist.isAllowed(ipAddr) {
			return false
		}
	}
	if Config.MaxTotalConnections == 0 && Config.MaxPerHostConnections == 0 {
		return true
	}

	if Config.MaxPerHostConnections > 0 {
		if total := conns.clients.getTotalFrom(ipAddr); total > Config.MaxPerHostConnections {
			logger.Debug(logSender, "", "active connections from %v %v/%v", ipAddr, total, Config.MaxPerHostConnections)
			AddDefenderEvent(ipAddr, HostEventLimitExceeded)
			return false
		}
	}

	if Config.MaxTotalConnections > 0 {
		if total := conns.clients.getTotal(); total > int32(Config.MaxTotalConnections) {
			logger.Debug(logSender, "", "active client connections %v/%v", total, Config.MaxTotalConnections)
			return false
		}

		// on a single SFTP connection we could have multiple SFTP channels or commands
		// so we check the estabilished connections too

		conns.RLock()
		defer conns.RUnlock()

		return len(conns.connections) < Config.MaxTotalConnections
	}

	return true
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
			ConnectionTime: util.GetTimeAsMsSinceEpoch(c.GetConnectionTime()),
			LastActivity:   util.GetTimeAsMsSinceEpoch(c.GetLastActivity()),
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
	// SSH command or WebDAV method
	Command string `json:"command,omitempty"`
}

// GetConnectionDuration returns the connection duration as string
func (c *ConnectionStatus) GetConnectionDuration() string {
	elapsed := time.Since(util.GetTimeFromMsecSinceEpoch(c.ConnectionTime))
	return util.GetDurationAsString(elapsed)
}

// GetConnectionInfo returns connection info.
// Protocol,Client Version and RemoteAddress are returned.
func (c *ConnectionStatus) GetConnectionInfo() string {
	var result strings.Builder

	result.WriteString(fmt.Sprintf("%v. Client: %#v From: %#v", c.Protocol, c.ClientVersion, c.RemoteAddress))

	if c.Command == "" {
		return result.String()
	}

	switch c.Protocol {
	case ProtocolSSH, ProtocolFTP:
		result.WriteString(fmt.Sprintf(". Command: %#v", c.Command))
	case ProtocolWebDAV:
		result.WriteString(fmt.Sprintf(". Method: %#v", c.Command))
	}

	return result.String()
}

// GetTransfersAsString returns the active transfers as string
func (c *ConnectionStatus) GetTransfersAsString() string {
	result := ""
	for _, t := range c.Transfers {
		if result != "" {
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
	// folder name to which the quota scan refers
	Name string `json:"name"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// ActiveScans holds the active quota scans
type ActiveScans struct {
	sync.RWMutex
	UserScans   []ActiveQuotaScan
	FolderScans []ActiveVirtualFolderQuotaScan
}

// GetUsersQuotaScans returns the active quota scans for users home directories
func (s *ActiveScans) GetUsersQuotaScans() []ActiveQuotaScan {
	s.RLock()
	defer s.RUnlock()

	scans := make([]ActiveQuotaScan, len(s.UserScans))
	copy(scans, s.UserScans)
	return scans
}

// AddUserQuotaScan adds a user to the ones with active quota scans.
// Returns false if the user has a quota scan already running
func (s *ActiveScans) AddUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.UserScans {
		if scan.Username == username {
			return false
		}
	}
	s.UserScans = append(s.UserScans, ActiveQuotaScan{
		Username:  username,
		StartTime: util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveUserQuotaScan removes a user from the ones with active quota scans.
// Returns false if the user has no active quota scans
func (s *ActiveScans) RemoveUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	for idx, scan := range s.UserScans {
		if scan.Username == username {
			lastIdx := len(s.UserScans) - 1
			s.UserScans[idx] = s.UserScans[lastIdx]
			s.UserScans = s.UserScans[:lastIdx]
			return true
		}
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
func (s *ActiveScans) AddVFolderQuotaScan(folderName string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.FolderScans {
		if scan.Name == folderName {
			return false
		}
	}
	s.FolderScans = append(s.FolderScans, ActiveVirtualFolderQuotaScan{
		Name:      folderName,
		StartTime: util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveVFolderQuotaScan removes a folder from the ones with active quota scans.
// Returns false if the folder has no active quota scans
func (s *ActiveScans) RemoveVFolderQuotaScan(folderName string) bool {
	s.Lock()
	defer s.Unlock()

	for idx, scan := range s.FolderScans {
		if scan.Name == folderName {
			lastIdx := len(s.FolderScans) - 1
			s.FolderScans[idx] = s.FolderScans[lastIdx]
			s.FolderScans = s.FolderScans[:lastIdx]
			return true
		}
	}

	return false
}
