// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// constants
const (
	logSender              = "common"
	uploadLogSender        = "Upload"
	downloadLogSender      = "Download"
	renameLogSender        = "Rename"
	rmdirLogSender         = "Rmdir"
	mkdirLogSender         = "Mkdir"
	symlinkLogSender       = "Symlink"
	removeLogSender        = "Remove"
	chownLogSender         = "Chown"
	chmodLogSender         = "Chmod"
	chtimesLogSender       = "Chtimes"
	copyLogSender          = "Copy"
	truncateLogSender      = "Truncate"
	operationDownload      = "download"
	operationUpload        = "upload"
	operationFirstDownload = "first-download"
	operationFirstUpload   = "first-upload"
	operationDelete        = "delete"
	operationCopy          = "copy"
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
	protocolEventAction   = "EventAction"
)

// Upload modes
const (
	UploadModeStandard              = 0
	UploadModeAtomic                = 1
	UploadModeAtomicWithResume      = 2
	UploadModeS3StoreOnError        = 4
	UploadModeGCSStoreOnError       = 8
	UploadModeAzureBlobStoreOnError = 16
)

func init() {
	Connections.clients = clientsMap{
		clients: make(map[string]int),
	}
	Connections.perUserConns = make(map[string]int)
	Connections.mapping = make(map[string]int)
	Connections.sshMapping = make(map[string]int)
}

// errors definitions
var (
	ErrPermissionDenied  = errors.New("permission denied")
	ErrNotExist          = errors.New("no such file or directory")
	ErrOpUnsupported     = errors.New("operation unsupported")
	ErrGenericFailure    = errors.New("failure")
	ErrQuotaExceeded     = errors.New("denying write due to space limit")
	ErrReadQuotaExceeded = errors.New("denying read due to quota limit")
	ErrConnectionDenied  = errors.New("you are not allowed to connect")
	ErrNoBinding         = errors.New("no binding configured")
	ErrCrtRevoked        = errors.New("your certificate has been revoked")
	ErrNoCredentials     = errors.New("no credential provided")
	ErrInternalFailure   = errors.New("internal failure")
	ErrTransferAborted   = errors.New("transfer aborted")
	ErrShuttingDown      = errors.New("the service is shutting down")
	errNoTransfer        = errors.New("requested transfer not found")
	errTransferMismatch  = errors.New("transfer mismatch")
)

var (
	// Config is the configuration for the supported protocols
	Config Configuration
	// Connections is the list of active connections
	Connections ActiveConnections
	// QuotaScans is the list of active quota scans
	QuotaScans         ActiveScans
	transfersChecker   TransfersChecker
	supportedProtocols = []string{ProtocolSFTP, ProtocolSCP, ProtocolSSH, ProtocolFTP, ProtocolWebDAV,
		ProtocolHTTP, ProtocolHTTPShare, ProtocolOIDC}
	disconnHookProtocols = []string{ProtocolSFTP, ProtocolSCP, ProtocolSSH, ProtocolFTP}
	// the map key is the protocol, for each protocol we can have multiple rate limiters
	rateLimiters     map[string][]*rateLimiter
	isShuttingDown   atomic.Bool
	ftpLoginCommands = []string{"PASS", "USER"}
)

// Initialize sets the common configuration
func Initialize(c Configuration, isShared int) error {
	isShuttingDown.Store(false)
	util.SetUmask(c.Umask)
	Config = c
	Config.Actions.ExecuteOn = util.RemoveDuplicates(Config.Actions.ExecuteOn, true)
	Config.Actions.ExecuteSync = util.RemoveDuplicates(Config.Actions.ExecuteSync, true)
	Config.ProxyAllowed = util.RemoveDuplicates(Config.ProxyAllowed, true)
	Config.idleLoginTimeout = 2 * time.Minute
	Config.idleTimeoutAsDuration = time.Duration(Config.IdleTimeout) * time.Minute
	startPeriodicChecks(periodicTimeoutCheckInterval, isShared)
	Config.defender = nil
	Config.allowList = nil
	Config.rateLimitersList = nil
	rateLimiters = make(map[string][]*rateLimiter)
	for _, rlCfg := range c.RateLimitersConfig {
		if rlCfg.isEnabled() {
			if err := rlCfg.validate(); err != nil {
				return fmt.Errorf("rate limiters initialization error: %w", err)
			}
			rateLimiter := rlCfg.getLimiter()
			for _, protocol := range rlCfg.Protocols {
				rateLimiters[protocol] = append(rateLimiters[protocol], rateLimiter)
			}
		}
	}
	if len(rateLimiters) > 0 {
		rateLimitersList, err := dataprovider.NewIPList(dataprovider.IPListTypeRateLimiterSafeList)
		if err != nil {
			return fmt.Errorf("unable to initialize ratelimiters list: %w", err)
		}
		Config.rateLimitersList = rateLimitersList
	}
	if c.DefenderConfig.Enabled {
		if !util.Contains(supportedDefenderDrivers, c.DefenderConfig.Driver) {
			return fmt.Errorf("unsupported defender driver %q", c.DefenderConfig.Driver)
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
	if c.AllowListStatus > 0 {
		allowList, err := dataprovider.NewIPList(dataprovider.IPListTypeAllowList)
		if err != nil {
			return fmt.Errorf("unable to initialize the allow list: %w", err)
		}
		logger.Info(logSender, "", "allow list initialized")
		Config.allowList = allowList
	}
	if err := c.initializeProxyProtocol(); err != nil {
		return err
	}
	vfs.SetTempPath(c.TempPath)
	dataprovider.SetTempPath(c.TempPath)
	vfs.SetAllowSelfConnections(c.AllowSelfConnections)
	vfs.SetRenameMode(c.RenameMode)
	vfs.SetReadMetadataMode(c.Metadata.Read)
	vfs.SetResumeMaxSize(c.ResumeMaxSize)
	vfs.SetUploadMode(c.UploadMode)
	dataprovider.SetAllowSelfConnections(c.AllowSelfConnections)
	transfersChecker = getTransfersChecker(isShared)
	return nil
}

// CheckClosing returns an error if the service is closing
func CheckClosing() error {
	if isShuttingDown.Load() {
		return ErrShuttingDown
	}
	return nil
}

// WaitForTransfers waits, for the specified grace time, for currently ongoing
// client-initiated transfer sessions to completes.
// A zero graceTime means no wait
func WaitForTransfers(graceTime int) {
	if graceTime == 0 {
		return
	}
	if isShuttingDown.Swap(true) {
		return
	}

	if activeHooks.Load() == 0 && getActiveConnections() == 0 {
		return
	}

	graceTimer := time.NewTimer(time.Duration(graceTime) * time.Second)
	ticker := time.NewTicker(3 * time.Second)

	for {
		select {
		case <-ticker.C:
			hooks := activeHooks.Load()
			logger.Info(logSender, "", "active hooks: %d", hooks)
			if hooks == 0 && getActiveConnections() == 0 {
				logger.Info(logSender, "", "no more active connections, graceful shutdown")
				ticker.Stop()
				graceTimer.Stop()
				return
			}
		case <-graceTimer.C:
			logger.Info(logSender, "", "grace time expired, hard shutdown")
			ticker.Stop()
			return
		}
	}
}

// getActiveConnections returns the number of connections with active transfers
func getActiveConnections() int {
	var activeConns int

	Connections.RLock()
	for _, c := range Connections.connections {
		if len(c.GetTransfers()) > 0 {
			activeConns++
		}
	}
	Connections.RUnlock()

	logger.Info(logSender, "", "number of connections with active transfers: %d", activeConns)
	return activeConns
}

// LimitRate blocks until all the configured rate limiters
// allow one event to happen.
// It returns an error if the time to wait exceeds the max
// allowed delay
func LimitRate(protocol, ip string) (time.Duration, error) {
	if Config.rateLimitersList != nil {
		isListed, _, err := Config.rateLimitersList.IsListed(ip, protocol)
		if err == nil && isListed {
			return 0, nil
		}
	}
	for _, limiter := range rateLimiters[protocol] {
		if delay, err := limiter.Wait(ip, protocol); err != nil {
			logger.Debug(logSender, "", "protocol %s ip %s: %v", protocol, ip, err)
			return delay, err
		}
	}
	return 0, nil
}

// Reload reloads the whitelist, the IP filter plugin and the defender's block and safe lists
func Reload() error {
	plugin.Handler.ReloadFilter()
	return nil
}

// IsBanned returns true if the specified IP address is banned
func IsBanned(ip, protocol string) bool {
	if plugin.Handler.IsIPBanned(ip, protocol) {
		return true
	}
	if Config.defender == nil {
		return false
	}

	return Config.defender.IsBanned(ip, protocol)
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

// AddDefenderEvent adds the specified defender event for the given IP.
// Returns true if the IP is in the defender's safe list.
func AddDefenderEvent(ip, protocol string, event HostEvent) bool {
	if Config.defender == nil {
		return false
	}

	return Config.defender.AddEvent(ip, protocol, event)
}

func startPeriodicChecks(duration time.Duration, isShared int) {
	startEventScheduler()
	spec := fmt.Sprintf("@every %s", duration)
	_, err := eventScheduler.AddFunc(spec, Connections.checkTransfers)
	util.PanicOnError(err)
	logger.Info(logSender, "", "scheduled overquota transfers check, schedule %q", spec)
	if isShared == 1 {
		logger.Info(logSender, "", "add reload configs task")
		_, err := eventScheduler.AddFunc("@every 10m", smtp.ReloadProviderConf)
		util.PanicOnError(err)
	}
	if Config.IdleTimeout > 0 {
		ratio := idleTimeoutCheckInterval / periodicTimeoutCheckInterval
		spec = fmt.Sprintf("@every %s", duration*ratio)
		_, err = eventScheduler.AddFunc(spec, Connections.checkIdles)
		util.PanicOnError(err)
		logger.Info(logSender, "", "scheduled idle connections check, schedule %q", spec)
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
	GetRole() string
	GetMaxSessions() int
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
	isAccessAllowed() bool
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

// ConnectionTransfer defines the trasfer details
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

// MetadataConfig defines how to handle metadata for cloud storage backends
type MetadataConfig struct {
	// If not zero the metadata will be read before downloads and will be
	// available in notifications
	Read int `json:"read" mapstructure:"read"`
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
	// 4 means files for S3 backend are stored even if a client-side upload error is detected.
	// 8 means files for Google Cloud Storage backend are stored even if a client-side upload error is detected.
	// 16 means files for Azure Blob backend are stored even if a client-side upload error is detected.
	UploadMode int `json:"upload_mode" mapstructure:"upload_mode"`
	// Actions to execute for SFTP file operations and SSH commands
	Actions ProtocolActions `json:"actions" mapstructure:"actions"`
	// SetstatMode 0 means "normal mode": requests for changing permissions and owner/group are executed.
	// 1 means "ignore mode": requests for changing permissions and owner/group are silently ignored.
	// 2 means "ignore mode for cloud fs": requests for changing permissions and owner/group are
	// silently ignored for cloud based filesystem such as S3, GCS, Azure Blob. Requests  for changing
	// modification times are ignored for cloud based filesystem if they are not supported.
	SetstatMode int `json:"setstat_mode" mapstructure:"setstat_mode"`
	// RenameMode defines how to handle directory renames. By default, renaming of non-empty directories
	// is not allowed for cloud storage providers (S3, GCS, Azure Blob). Set to 1 to enable recursive
	// renames for these providers, they may be slow, there is no atomic rename API like for local
	// filesystem, so SFTPGo will recursively list the directory contents and do a rename for each entry
	RenameMode int `json:"rename_mode" mapstructure:"rename_mode"`
	// ResumeMaxSize defines the maximum size allowed, in bytes, to resume uploads on storage backends
	// with immutable objects. By default, resuming uploads is not allowed for cloud storage providers
	// (S3, GCS, Azure Blob) because SFTPGo must rewrite the entire file.
	// Set to a value greater than 0 to allow resuming uploads of files smaller than or equal to the
	// defined size.
	ResumeMaxSize int64 `json:"resume_max_size" mapstructure:"resume_max_size"`
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
	// List of IP addresses and IP ranges for which not to read the proxy header
	ProxySkipped []string `json:"proxy_skipped" mapstructure:"proxy_skipped"`
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
	// Defines the status of the global allow list. 0 means disabled, 1 enabled.
	// If enabled, only the listed IPs/networks can access the configured services, all other
	// client connections will be dropped before they even try to authenticate.
	// Ensure to enable this setting only after adding some allowed ip/networks from the WebAdmin/REST API
	AllowListStatus int `json:"allowlist_status" mapstructure:"allowlist_status"`
	// Allow users on this instance to use other users/virtual folders on this instance as storage backend.
	// Enable this setting if you know what you are doing.
	AllowSelfConnections int `json:"allow_self_connections" mapstructure:"allow_self_connections"`
	// Defender configuration
	DefenderConfig DefenderConfig `json:"defender" mapstructure:"defender"`
	// Rate limiter configurations
	RateLimitersConfig []RateLimiterConfig `json:"rate_limiters" mapstructure:"rate_limiters"`
	// Umask for new uploads. Leave blank to use the system default.
	Umask string `json:"umask" mapstructure:"umask"`
	// Metadata configuration
	Metadata              MetadataConfig `json:"metadata" mapstructure:"metadata"`
	idleTimeoutAsDuration time.Duration
	idleLoginTimeout      time.Duration
	defender              Defender
	allowList             *dataprovider.IPList
	rateLimitersList      *dataprovider.IPList
	proxyAllowed          []func(net.IP) bool
	proxySkipped          []func(net.IP) bool
}

// IsAtomicUploadEnabled returns true if atomic upload is enabled
func (c *Configuration) IsAtomicUploadEnabled() bool {
	return c.UploadMode&UploadModeAtomic != 0 || c.UploadMode&UploadModeAtomicWithResume != 0
}

func (c *Configuration) initializeProxyProtocol() error {
	if c.ProxyProtocol > 0 {
		allowed, err := util.ParseAllowedIPAndRanges(c.ProxyAllowed)
		if err != nil {
			return fmt.Errorf("invalid proxy allowed: %w", err)
		}
		skipped, err := util.ParseAllowedIPAndRanges(c.ProxySkipped)
		if err != nil {
			return fmt.Errorf("invalid proxy skipped: %w", err)
		}
		Config.proxyAllowed = allowed
		Config.proxySkipped = skipped
	}
	return nil
}

// GetProxyListener returns a wrapper for the given listener that supports the
// HAProxy Proxy Protocol
func (c *Configuration) GetProxyListener(listener net.Listener) (*proxyproto.Listener, error) {
	if c.ProxyProtocol > 0 {
		defaultPolicy := proxyproto.REQUIRE
		if c.ProxyProtocol == 1 {
			defaultPolicy = proxyproto.IGNORE
		}

		return &proxyproto.Listener{
			Listener:          listener,
			Policy:            getProxyPolicy(c.proxyAllowed, c.proxySkipped, defaultPolicy),
			ReadHeaderTimeout: 10 * time.Second,
		}, nil
	}
	return nil, errors.New("proxy protocol not configured")
}

// GetRateLimitersStatus returns the rate limiters status
func (c *Configuration) GetRateLimitersStatus() (bool, []string) {
	enabled := false
	var protocols []string
	for _, rlCfg := range c.RateLimitersConfig {
		if rlCfg.isEnabled() {
			enabled = true
			protocols = append(protocols, rlCfg.Protocols...)
		}
	}
	return enabled, util.RemoveDuplicates(protocols, false)
}

// IsAllowListEnabled returns true if the global allow list is enabled
func (c *Configuration) IsAllowListEnabled() bool {
	return c.AllowListStatus > 0
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
			logger.Warn(logSender, "", "Invalid startup hook %q: %v", c.StartupHook, err)
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
		err := fmt.Errorf("invalid startup hook %q", c.StartupHook)
		logger.Warn(logSender, "", "Invalid startup hook %q", c.StartupHook)
		return err
	}
	startTime := time.Now()
	timeout, env, args := command.GetConfig(c.StartupHook, command.HookStartup)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.StartupHook, args...)
	cmd.Env = env
	err := cmd.Run()
	logger.Debug(logSender, "", "Startup hook executed, elapsed: %s, error: %v", time.Since(startTime), err)
	return nil
}

func (c *Configuration) executePostDisconnectHook(remoteAddr, protocol, username, connID string, connectionTime time.Time) {
	startNewHook()
	defer hookEnded()

	ipAddr := util.GetIPFromRemoteAddress(remoteAddr)
	connDuration := int64(time.Since(connectionTime) / time.Millisecond)

	if strings.HasPrefix(c.PostDisconnectHook, "http") {
		var url *url.URL
		url, err := url.Parse(c.PostDisconnectHook)
		if err != nil {
			logger.Warn(protocol, connID, "Invalid post disconnect hook %q: %v", c.PostDisconnectHook, err)
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
		logger.Debug(protocol, connID, "invalid post disconnect hook %q", c.PostDisconnectHook)
		return
	}
	timeout, env, args := command.GetConfig(c.PostDisconnectHook, command.HookPostDisconnect)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, c.PostDisconnectHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_CONNECTION_IP=%s", ipAddr),
		fmt.Sprintf("SFTPGO_CONNECTION_USERNAME=%s", username),
		fmt.Sprintf("SFTPGO_CONNECTION_DURATION=%d", connDuration),
		fmt.Sprintf("SFTPGO_CONNECTION_PROTOCOL=%s", protocol))
	err := cmd.Run()
	logger.Debug(protocol, connID, "Post disconnect hook executed, elapsed: %s error: %v", time.Since(startTime), err)
}

func (c *Configuration) checkPostDisconnectHook(remoteAddr, protocol, username, connID string, connectionTime time.Time) {
	if c.PostDisconnectHook == "" {
		return
	}
	if !util.Contains(disconnHookProtocols, protocol) {
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
			logger.Warn(protocol, "", "Login from ip %q denied, invalid post connect hook %q: %v",
				ipAddr, c.PostConnectHook, err)
			return getPermissionDeniedError(protocol)
		}
		q := url.Query()
		q.Add("ip", ipAddr)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()

		resp, err := httpclient.RetryableGet(url.String())
		if err != nil {
			logger.Warn(protocol, "", "Login from ip %q denied, error executing post connect hook: %v", ipAddr, err)
			return getPermissionDeniedError(protocol)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logger.Warn(protocol, "", "Login from ip %q denied, post connect hook response code: %v", ipAddr, resp.StatusCode)
			return getPermissionDeniedError(protocol)
		}
		return nil
	}
	if !filepath.IsAbs(c.PostConnectHook) {
		err := fmt.Errorf("invalid post connect hook %q", c.PostConnectHook)
		logger.Warn(protocol, "", "Login from ip %q denied: %v", ipAddr, err)
		return getPermissionDeniedError(protocol)
	}
	timeout, env, args := command.GetConfig(c.PostConnectHook, command.HookPostConnect)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.PostConnectHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_CONNECTION_IP=%s", ipAddr),
		fmt.Sprintf("SFTPGO_CONNECTION_PROTOCOL=%s", protocol))
	err := cmd.Run()
	if err != nil {
		logger.Warn(protocol, "", "Login from ip %q denied, connect hook error: %v", ipAddr, err)
		return getPermissionDeniedError(protocol)
	}
	return nil
}

func getProxyPolicy(allowed, skipped []func(net.IP) bool, def proxyproto.Policy) proxyproto.PolicyFunc {
	return func(upstream net.Addr) (proxyproto.Policy, error) {
		upstreamIP, err := util.GetIPFromNetAddr(upstream)
		if err != nil {
			// something is wrong with the source IP, better reject the connection
			return proxyproto.REJECT, err
		}

		for _, skippedFrom := range skipped {
			if skippedFrom(upstreamIP) {
				return proxyproto.SKIP, nil
			}
		}

		for _, allowFrom := range allowed {
			if allowFrom(upstreamIP) {
				if def == proxyproto.REQUIRE {
					return proxyproto.REQUIRE, nil
				}
				return proxyproto.USE, nil
			}
		}

		return def, nil
	}
}

// SSHConnection defines an ssh connection.
// Each SSH connection can open several channels for SFTP or SSH commands
type SSHConnection struct {
	id           string
	conn         net.Conn
	lastActivity atomic.Int64
}

// NewSSHConnection returns a new SSHConnection
func NewSSHConnection(id string, conn net.Conn) *SSHConnection {
	c := &SSHConnection{
		id:   id,
		conn: conn,
	}
	c.lastActivity.Store(time.Now().UnixNano())
	return c
}

// GetID returns the ID for this SSHConnection
func (c *SSHConnection) GetID() string {
	return c.id
}

// UpdateLastActivity updates last activity for this connection
func (c *SSHConnection) UpdateLastActivity() {
	c.lastActivity.Store(time.Now().UnixNano())
}

// GetLastActivity returns the last connection activity
func (c *SSHConnection) GetLastActivity() time.Time {
	return time.Unix(0, c.lastActivity.Load())
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
	transfersCheckStatus atomic.Bool
	sync.RWMutex
	connections    []ActiveConnection
	mapping        map[string]int
	sshConnections []*SSHConnection
	sshMapping     map[string]int
	perUserConns   map[string]int
}

// internal method, must be called within a locked block
func (conns *ActiveConnections) addUserConnection(username string) {
	if username == "" {
		return
	}
	conns.perUserConns[username]++
}

// internal method, must be called within a locked block
func (conns *ActiveConnections) removeUserConnection(username string) {
	if username == "" {
		return
	}
	if val, ok := conns.perUserConns[username]; ok {
		conns.perUserConns[username]--
		if val > 1 {
			return
		}
		delete(conns.perUserConns, username)
	}
}

// GetActiveSessions returns the number of active sessions for the given username.
// We return the open sessions for any protocol
func (conns *ActiveConnections) GetActiveSessions(username string) int {
	conns.RLock()
	defer conns.RUnlock()

	return conns.perUserConns[username]
}

// Add adds a new connection to the active ones
func (conns *ActiveConnections) Add(c ActiveConnection) error {
	conns.Lock()
	defer conns.Unlock()

	if username := c.GetUsername(); username != "" {
		if maxSessions := c.GetMaxSessions(); maxSessions > 0 {
			if val := conns.perUserConns[username]; val >= maxSessions {
				return fmt.Errorf("too many open sessions: %d/%d", val, maxSessions)
			}
		}
		conns.addUserConnection(username)
	}
	conns.mapping[c.GetID()] = len(conns.connections)
	conns.connections = append(conns.connections, c)
	metric.UpdateActiveConnectionsSize(len(conns.connections))
	logger.Debug(c.GetProtocol(), c.GetID(), "connection added, local address %q, remote address %q, num open connections: %d",
		c.GetLocalAddress(), c.GetRemoteAddress(), len(conns.connections))
	return nil
}

// Swap replaces an existing connection with the given one.
// This method is useful if you have to change some connection details
// for example for FTP is used to update the connection once the user
// authenticates
func (conns *ActiveConnections) Swap(c ActiveConnection) error {
	conns.Lock()
	defer conns.Unlock()

	if idx, ok := conns.mapping[c.GetID()]; ok {
		conn := conns.connections[idx]
		conns.removeUserConnection(conn.GetUsername())
		if username := c.GetUsername(); username != "" {
			if maxSessions := c.GetMaxSessions(); maxSessions > 0 {
				if val, ok := conns.perUserConns[username]; ok && val >= maxSessions {
					conns.addUserConnection(conn.GetUsername())
					return fmt.Errorf("too many open sessions: %d/%d", val, maxSessions)
				}
			}
			conns.addUserConnection(username)
		}
		err := conn.CloseFS()
		conns.connections[idx] = c
		logger.Debug(logSender, c.GetID(), "connection swapped, close fs error: %v", err)
		conn = nil
		return nil
	}

	return errors.New("connection to swap not found")
}

// Remove removes a connection from the active ones
func (conns *ActiveConnections) Remove(connectionID string) {
	conns.Lock()
	defer conns.Unlock()

	if idx, ok := conns.mapping[connectionID]; ok {
		conn := conns.connections[idx]
		err := conn.CloseFS()
		lastIdx := len(conns.connections) - 1
		conns.connections[idx] = conns.connections[lastIdx]
		conns.connections[lastIdx] = nil
		conns.connections = conns.connections[:lastIdx]
		delete(conns.mapping, connectionID)
		if idx != lastIdx {
			conns.mapping[conns.connections[idx].GetID()] = idx
		}
		conns.removeUserConnection(conn.GetUsername())
		metric.UpdateActiveConnectionsSize(lastIdx)
		logger.Debug(conn.GetProtocol(), conn.GetID(), "connection removed, local address %q, remote address %q close fs error: %v, num open connections: %d",
			conn.GetLocalAddress(), conn.GetRemoteAddress(), err, lastIdx)
		if conn.GetProtocol() == ProtocolFTP && conn.GetUsername() == "" && !util.Contains(ftpLoginCommands, conn.GetCommand()) {
			ip := util.GetIPFromRemoteAddress(conn.GetRemoteAddress())
			logger.ConnectionFailedLog("", ip, dataprovider.LoginMethodNoAuthTried, ProtocolFTP,
				dataprovider.ErrNoAuthTried.Error())
			metric.AddNoAuthTried()
			AddDefenderEvent(ip, ProtocolFTP, HostEventNoLoginTried)
			dataprovider.ExecutePostLoginHook(&dataprovider.User{}, dataprovider.LoginMethodNoAuthTried, ip,
				ProtocolFTP, dataprovider.ErrNoAuthTried)
			plugin.Handler.NotifyLogEvent(notifier.LogEventTypeNoLoginTried, ProtocolFTP, "", ip, "",
				dataprovider.ErrNoAuthTried)
		}
		Config.checkPostDisconnectHook(conn.GetRemoteAddress(), conn.GetProtocol(), conn.GetUsername(),
			conn.GetID(), conn.GetConnectionTime())
		return
	}

	logger.Debug(logSender, "", "connection id %q to remove not found!", connectionID)
}

// Close closes an active connection.
// It returns true on success
func (conns *ActiveConnections) Close(connectionID, role string) bool {
	conns.RLock()

	var result bool

	if idx, ok := conns.mapping[connectionID]; ok {
		c := conns.connections[idx]

		if role == "" || c.GetRole() == role {
			defer func(conn ActiveConnection) {
				err := conn.Disconnect()
				logger.Debug(conn.GetProtocol(), conn.GetID(), "close connection requested, close err: %v", err)
			}(c)
			result = true
		}
	}

	conns.RUnlock()
	return result
}

// AddSSHConnection adds a new ssh connection to the active ones
func (conns *ActiveConnections) AddSSHConnection(c *SSHConnection) {
	conns.Lock()
	defer conns.Unlock()

	conns.sshMapping[c.GetID()] = len(conns.sshConnections)
	conns.sshConnections = append(conns.sshConnections, c)
	logger.Debug(logSender, c.GetID(), "ssh connection added, num open connections: %d", len(conns.sshConnections))
}

// RemoveSSHConnection removes a connection from the active ones
func (conns *ActiveConnections) RemoveSSHConnection(connectionID string) {
	conns.Lock()
	defer conns.Unlock()

	if idx, ok := conns.sshMapping[connectionID]; ok {
		lastIdx := len(conns.sshConnections) - 1
		conns.sshConnections[idx] = conns.sshConnections[lastIdx]
		conns.sshConnections[lastIdx] = nil
		conns.sshConnections = conns.sshConnections[:lastIdx]
		delete(conns.sshMapping, connectionID)
		if idx != lastIdx {
			conns.sshMapping[conns.sshConnections[idx].GetID()] = idx
		}
		logger.Debug(logSender, connectionID, "ssh connection removed, num open ssh connections: %d", lastIdx)
		return
	}
	logger.Warn(logSender, "", "ssh connection to remove with id %q not found!", connectionID)
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
			defer func(conn ActiveConnection) {
				err := conn.Disconnect()
				logger.Debug(conn.GetProtocol(), conn.GetID(), "close idle connection, idle time: %s, username: %q close err: %v",
					time.Since(conn.GetLastActivity()), conn.GetUsername(), err)
			}(c)
		} else if !c.isAccessAllowed() {
			defer func(conn ActiveConnection) {
				err := conn.Disconnect()
				logger.Info(conn.GetProtocol(), conn.GetID(), "access conditions not met for user: %q close connection err: %v",
					conn.GetUsername(), err)
			}(c)
		}
	}

	conns.RUnlock()
}

func (conns *ActiveConnections) checkTransfers() {
	if conns.transfersCheckStatus.Load() {
		logger.Warn(logSender, "", "the previous transfer check is still running, skipping execution")
		return
	}
	conns.transfersCheckStatus.Store(true)
	defer conns.transfersCheckStatus.Store(false)

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
				logger.Info(logSender, c.GetID(), "user %q is overquota, try to close transfer id %v",
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

// IsNewConnectionAllowed returns an error if the maximum number of concurrent allowed
// connections is exceeded or a whitelist is defined and the specified ipAddr is not listed
// or the service is shutting down
func (conns *ActiveConnections) IsNewConnectionAllowed(ipAddr, protocol string) error {
	if isShuttingDown.Load() {
		return ErrShuttingDown
	}
	if Config.allowList != nil {
		isListed, _, err := Config.allowList.IsListed(ipAddr, protocol)
		if err != nil {
			logger.Error(logSender, "", "unable to query allow list, connection denied, ip %q, protocol %s, err: %v",
				ipAddr, protocol, err)
			return ErrConnectionDenied
		}
		if !isListed {
			return ErrConnectionDenied
		}
	}
	if Config.MaxTotalConnections == 0 && Config.MaxPerHostConnections == 0 {
		return nil
	}

	if Config.MaxPerHostConnections > 0 {
		if total := conns.clients.getTotalFrom(ipAddr); total > Config.MaxPerHostConnections {
			if !AddDefenderEvent(ipAddr, protocol, HostEventLimitExceeded) {
				logger.Warn(logSender, "", "connection denied, active connections from IP %q: %d/%d",
					ipAddr, total, Config.MaxPerHostConnections)
				return ErrConnectionDenied
			}
			logger.Info(logSender, "", "active connections from safe IP %q: %d", ipAddr, total)
		}
	}

	if Config.MaxTotalConnections > 0 {
		if total := conns.clients.getTotal(); total > int32(Config.MaxTotalConnections) {
			logger.Info(logSender, "", "active client connections %d/%d", total, Config.MaxTotalConnections)
			return ErrConnectionDenied
		}

		// on a single SFTP connection we could have multiple SFTP channels or commands
		// so we check the estabilished connections too

		conns.RLock()
		defer conns.RUnlock()

		if sess := len(conns.connections); sess >= Config.MaxTotalConnections {
			logger.Info(logSender, "", "active client sessions %d/%d", sess, Config.MaxTotalConnections)
			return ErrConnectionDenied
		}
	}

	return nil
}

// GetStats returns stats for active connections
func (conns *ActiveConnections) GetStats(role string) []ConnectionStatus {
	conns.RLock()
	defer conns.RUnlock()

	stats := make([]ConnectionStatus, 0, len(conns.connections))
	node := dataprovider.GetNodeName()
	for _, c := range conns.connections {
		if role == "" || c.GetRole() == role {
			stat := ConnectionStatus{
				Username:       c.GetUsername(),
				ConnectionID:   c.GetID(),
				ClientVersion:  c.GetClientVersion(),
				RemoteAddress:  c.GetRemoteAddress(),
				ConnectionTime: util.GetTimeAsMsSinceEpoch(c.GetConnectionTime()),
				LastActivity:   util.GetTimeAsMsSinceEpoch(c.GetLastActivity()),
				CurrentTime:    util.GetTimeAsMsSinceEpoch(time.Now()),
				Protocol:       c.GetProtocol(),
				Command:        c.GetCommand(),
				Transfers:      c.GetTransfers(),
				Node:           node,
			}
			stats = append(stats, stat)
		}
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
	// Current time as unix timestamp in milliseconds
	CurrentTime int64 `json:"current_time"`
	// Protocol for this connection
	Protocol string `json:"protocol"`
	// active uploads/downloads
	Transfers []ConnectionTransfer `json:"active_transfers,omitempty"`
	// SSH command or WebDAV method
	Command string `json:"command,omitempty"`
	// Node identifier, omitted for single node installations
	Node string `json:"node,omitempty"`
}

// ActiveQuotaScan defines an active quota scan for a user
type ActiveQuotaScan struct {
	// Username to which the quota scan refers
	Username string `json:"username"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64  `json:"start_time"`
	Role      string `json:"-"`
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

// GetUsersQuotaScans returns the active users quota scans
func (s *ActiveScans) GetUsersQuotaScans(role string) []ActiveQuotaScan {
	s.RLock()
	defer s.RUnlock()

	scans := make([]ActiveQuotaScan, 0, len(s.UserScans))
	for _, scan := range s.UserScans {
		if role == "" || role == scan.Role {
			scans = append(scans, ActiveQuotaScan{
				Username:  scan.Username,
				StartTime: scan.StartTime,
			})
		}
	}

	return scans
}

// AddUserQuotaScan adds a user to the ones with active quota scans.
// Returns false if the user has a quota scan already running
func (s *ActiveScans) AddUserQuotaScan(username, role string) bool {
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
		Role:      role,
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
