// Package sftpd implements the SSH File Transfer Protocol as described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02.
// It uses pkg/sftp library:
// https://github.com/pkg/sftp
package sftpd

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	logSender         = "sftpd"
	logSenderSCP      = "scp"
	uploadLogSender   = "Upload"
	downloadLogSender = "Download"
	renameLogSender   = "Rename"
	rmdirLogSender    = "Rmdir"
	mkdirLogSender    = "Mkdir"
	symlinkLogSender  = "Symlink"
	removeLogSender   = "Remove"
	operationDownload = "download"
	operationUpload   = "upload"
	operationDelete   = "delete"
	operationRename   = "rename"
	protocolSFTP      = "SFTP"
	protocolSCP       = "SCP"
)

var (
	mutex                sync.RWMutex
	openConnections      map[string]Connection
	activeTransfers      []*Transfer
	idleConnectionTicker *time.Ticker
	idleTimeout          time.Duration
	activeQuotaScans     []ActiveQuotaScan
	dataProvider         dataprovider.Provider
	actions              Actions
	uploadMode           int
)

type connectionTransfer struct {
	OperationType string `json:"operation_type"`
	StartTime     int64  `json:"start_time"`
	Size          int64  `json:"size"`
	LastActivity  int64  `json:"last_activity"`
	Path          string `json:"path"`
}

// ActiveQuotaScan defines an active quota scan
type ActiveQuotaScan struct {
	// Username to which the quota scan refers
	Username string `json:"username"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// Actions to execute on SFTP create, download, delete and rename.
// An external command can be executed and/or an HTTP notification can be fired
type Actions struct {
	// Valid values are download, upload, delete, rename. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Absolute path to the command to execute, empty to disable
	Command string `json:"command" mapstructure:"command"`
	// The URL to notify using an HTTP GET, empty to disable
	HTTPNotificationURL string `json:"http_notification_url" mapstructure:"http_notification_url"`
}

// ConnectionStatus status for an active connection
type ConnectionStatus struct {
	// Logged in username
	Username string `json:"username"`
	// Unique identifier for the connection
	ConnectionID string `json:"connection_id"`
	// client's version string
	ClientVersion string `json:"client_version"`
	// Remote address for this connection
	RemoteAddress string `json:"remote_address"`
	// Connection time as unix timestamp in milliseconds
	ConnectionTime int64 `json:"connection_time"`
	// Last activity as unix timestamp in milliseconds
	LastActivity int64 `json:"last_activity"`
	// Protocol for this connection: SFTP or SCP
	Protocol string `json:"protocol"`
	// active uploads/downloads
	Transfers []connectionTransfer `json:"active_transfers"`
}

func init() {
	openConnections = make(map[string]Connection)
	idleConnectionTicker = time.NewTicker(5 * time.Minute)
}

// SetDataProvider sets the data provider to use to authenticate users and to get/update their disk quota
func SetDataProvider(provider dataprovider.Provider) {
	dataProvider = provider
}

func getActiveSessions(username string) int {
	mutex.RLock()
	defer mutex.RUnlock()
	numSessions := 0
	for _, c := range openConnections {
		if c.User.Username == username {
			numSessions++
		}
	}
	return numSessions
}

// GetQuotaScans returns the active quota scans
func GetQuotaScans() []ActiveQuotaScan {
	mutex.RLock()
	defer mutex.RUnlock()
	scans := make([]ActiveQuotaScan, len(activeQuotaScans))
	copy(scans, activeQuotaScans)
	return scans
}

// AddQuotaScan add an user to the ones with active quota scans.
// Returns false if the user has a quota scan already running
func AddQuotaScan(username string) bool {
	mutex.Lock()
	defer mutex.Unlock()
	for _, s := range activeQuotaScans {
		if s.Username == username {
			return false
		}
	}
	activeQuotaScans = append(activeQuotaScans, ActiveQuotaScan{
		Username:  username,
		StartTime: utils.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveQuotaScan removes an user from the ones with active quota scans
func RemoveQuotaScan(username string) error {
	mutex.Lock()
	defer mutex.Unlock()
	var err error
	indexToRemove := -1
	for i, s := range activeQuotaScans {
		if s.Username == username {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		activeQuotaScans[indexToRemove] = activeQuotaScans[len(activeQuotaScans)-1]
		activeQuotaScans = activeQuotaScans[:len(activeQuotaScans)-1]
	} else {
		logger.Warn(logSender, "", "quota scan to remove not found for user: %v", username)
		err = fmt.Errorf("quota scan to remove not found for user: %v", username)
	}
	return err
}

// CloseActiveConnection closes an active SFTP connection.
// It returns true on success
func CloseActiveConnection(connectionID string) bool {
	result := false
	mutex.RLock()
	defer mutex.RUnlock()
	for _, c := range openConnections {
		if c.ID == connectionID {
			err := c.netConn.Close()
			c.Log(logger.LevelDebug, logSender, "close connection requested, err: %v", err)
			result = true
			break
		}
	}
	return result
}

// GetConnectionsStats returns stats for active connections
func GetConnectionsStats() []ConnectionStatus {
	mutex.RLock()
	defer mutex.RUnlock()
	stats := []ConnectionStatus{}
	for _, c := range openConnections {
		conn := ConnectionStatus{
			Username:       c.User.Username,
			ConnectionID:   c.ID,
			ClientVersion:  c.ClientVersion,
			RemoteAddress:  c.RemoteAddr.String(),
			ConnectionTime: utils.GetTimeAsMsSinceEpoch(c.StartTime),
			LastActivity:   utils.GetTimeAsMsSinceEpoch(c.lastActivity),
			Protocol:       c.protocol,
			Transfers:      []connectionTransfer{},
		}
		for _, t := range activeTransfers {
			if t.connectionID == c.ID {
				if t.lastActivity.UnixNano() > c.lastActivity.UnixNano() {
					conn.LastActivity = utils.GetTimeAsMsSinceEpoch(t.lastActivity)
				}
				var operationType string
				var size int64
				if t.transferType == transferUpload {
					operationType = operationUpload
					size = t.bytesReceived
				} else {
					operationType = operationDownload
					size = t.bytesSent
				}
				connTransfer := connectionTransfer{
					OperationType: operationType,
					StartTime:     utils.GetTimeAsMsSinceEpoch(t.start),
					Size:          size,
					LastActivity:  utils.GetTimeAsMsSinceEpoch(t.lastActivity),
					Path:          c.User.GetRelativePath(t.path),
				}
				conn.Transfers = append(conn.Transfers, connTransfer)
			}
		}
		stats = append(stats, conn)
	}
	return stats
}

func startIdleTimer(maxIdleTime time.Duration) {
	idleTimeout = maxIdleTime
	go func() {
		for t := range idleConnectionTicker.C {
			logger.Debug(logSender, "", "idle connections check ticker %v", t)
			CheckIdleConnections()
		}
	}()
}

// CheckIdleConnections disconnects clients idle for too long, based on IdleTimeout setting
func CheckIdleConnections() {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, c := range openConnections {
		idleTime := time.Since(c.lastActivity)
		for _, t := range activeTransfers {
			if t.connectionID == c.ID {
				transferIdleTime := time.Since(t.lastActivity)
				if transferIdleTime < idleTime {
					c.Log(logger.LevelDebug, logSender, "idle time: %v setted to transfer idle time: %v",
						idleTime, transferIdleTime)
					idleTime = transferIdleTime
				}
			}
		}
		if idleTime > idleTimeout {
			c.Log(logger.LevelInfo, logSender, "close idle connection, idle time: %v", idleTime)
			err := c.netConn.Close()
			if err != nil {
				c.Log(logger.LevelWarn, logSender, "idle connection close failed: %v", err)
			}
		}
	}
	logger.Debug(logSender, "", "check idle connections ended")
}

func addConnection(id string, c Connection) {
	mutex.Lock()
	defer mutex.Unlock()
	openConnections[id] = c
	c.Log(logger.LevelDebug, logSender, "connection added, num open connections: %v", len(openConnections))
}

func removeConnection(id string) {
	mutex.Lock()
	defer mutex.Unlock()
	c := openConnections[id]
	delete(openConnections, id)
	c.Log(logger.LevelDebug, logSender, "connection removed, num open connections: %v", len(openConnections))
}

func addTransfer(transfer *Transfer) {
	mutex.Lock()
	defer mutex.Unlock()
	activeTransfers = append(activeTransfers, transfer)
}

func removeTransfer(transfer *Transfer) error {
	mutex.Lock()
	defer mutex.Unlock()
	var err error
	indexToRemove := -1
	for i, v := range activeTransfers {
		if v == transfer {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		activeTransfers[indexToRemove] = activeTransfers[len(activeTransfers)-1]
		activeTransfers = activeTransfers[:len(activeTransfers)-1]
	} else {
		logger.Warn(logSender, transfer.connectionID, "transfer to remove not found!")
		err = fmt.Errorf("transfer to remove not found")
	}
	return err
}

func updateConnectionActivity(id string) {
	mutex.Lock()
	defer mutex.Unlock()
	if c, ok := openConnections[id]; ok {
		c.lastActivity = time.Now()
		openConnections[id] = c
	}
}

func executeAction(operation string, username string, path string, target string) error {
	if !utils.IsStringInSlice(operation, actions.ExecuteOn) {
		return nil
	}
	var err error
	if len(actions.Command) > 0 && filepath.IsAbs(actions.Command) {
		if _, err = os.Stat(actions.Command); err == nil {
			command := exec.Command(actions.Command, operation, username, path, target)
			err = command.Start()
			logger.Debug(logSender, "", "start command %#v with arguments: %v, %v, %v, %v, error: %v",
				actions.Command, operation, username, path, target, err)
			if err == nil {
				go command.Wait()
			}
		} else {
			logger.Warn(logSender, "", "Invalid action command %#v : %v", actions.Command, err)
		}
	}
	if len(actions.HTTPNotificationURL) > 0 {
		var url *url.URL
		url, err = url.Parse(actions.HTTPNotificationURL)
		if err == nil {
			q := url.Query()
			q.Add("action", operation)
			q.Add("username", username)
			q.Add("path", path)
			if len(target) > 0 {
				q.Add("target_path", target)
			}
			url.RawQuery = q.Encode()
			go func() {
				startTime := time.Now()
				httpClient := &http.Client{
					Timeout: 15 * time.Second,
				}
				resp, err := httpClient.Get(url.String())
				respCode := 0
				if err == nil {
					respCode = resp.StatusCode
					resp.Body.Close()
				}
				logger.Debug(logSender, "", "notified action to URL: %v status code: %v, elapsed: %v err: %v",
					url.String(), respCode, time.Since(startTime), err)
			}()
		} else {
			logger.Warn(logSender, "", "Invalid http_notification_url %#v : %v", actions.HTTPNotificationURL, err)
		}
	}
	return err
}
