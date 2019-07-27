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
	logSender              = "sftpd"
	sftpUploadLogSender    = "SFTPUpload"
	sftpdDownloadLogSender = "SFTPDownload"
	sftpdRenameLogSender   = "SFTPRename"
	sftpdRmdirLogSender    = "SFTPRmdir"
	sftpdMkdirLogSender    = "SFTPMkdir"
	sftpdSymlinkLogSender  = "SFTPSymlink"
	sftpdRemoveLogSender   = "SFTPRemove"
	operationDownload      = "download"
	operationUpload        = "upload"
	operationDelete        = "delete"
	operationRename        = "rename"
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
)

type connectionTransfer struct {
	OperationType string `json:"operation_type"`
	StartTime     int64  `json:"start_time"`
	Size          int64  `json:"size"`
	LastActivity  int64  `json:"last_activity"`
}

// ActiveQuotaScan username and start data for a quota scan
type ActiveQuotaScan struct {
	Username  string `json:"username"`
	StartTime int64  `json:"start_time"`
}

// Actions configuration for external script to execute on create, download, delete.
// A rename trigger delete script for the old file and create script for the new one
type Actions struct {
	ExecuteOn           []string `json:"execute_on"`
	Command             string   `json:"command"`
	HTTPNotificationURL string   `json:"http_notification_url"`
}

// ConnectionStatus status for an active connection
type ConnectionStatus struct {
	Username       string               `json:"username"`
	ConnectionID   string               `json:"connection_id"`
	ClientVersion  string               `json:"client_version"`
	RemoteAddress  string               `json:"remote_address"`
	ConnectionTime int64                `json:"connection_time"`
	LastActivity   int64                `json:"last_activity"`
	Transfers      []connectionTransfer `json:"active_transfers"`
}

func init() {
	openConnections = make(map[string]Connection)
	idleConnectionTicker = time.NewTicker(5 * time.Minute)
}

// SetDataProvider sets the data provider
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

// RemoveQuotaScan remove and user from the ones with active quota scans
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
		logger.Warn(logSender, "quota scan to remove not found for user: %v", username)
		err = fmt.Errorf("quota scan to remove not found for user: %v", username)
	}
	return err
}

// CloseActiveConnection close an active SFTP connection, returns true on success
func CloseActiveConnection(connectionID string) bool {
	result := false
	mutex.RLock()
	defer mutex.RUnlock()
	for _, c := range openConnections {
		if c.ID == connectionID {
			logger.Debug(logSender, "closing connection with id: %v", connectionID)
			c.sshConn.Close()
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
			Transfers:      []connectionTransfer{},
		}
		for _, t := range activeTransfers {
			if t.connectionID == c.ID {
				if utils.GetTimeAsMsSinceEpoch(t.lastActivity) > conn.LastActivity {
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
			logger.Debug(logSender, "idle connections check ticker %v", t)
			CheckIdleConnections()
		}
	}()
}

// CheckIdleConnections disconnects idle clients
func CheckIdleConnections() {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, c := range openConnections {
		idleTime := time.Since(c.lastActivity)
		for _, t := range activeTransfers {
			if t.connectionID == c.ID {
				transferIdleTime := time.Since(t.lastActivity)
				if transferIdleTime < idleTime {
					logger.Debug(logSender, "idle time: %v setted to transfer idle time: %v connection id: %v",
						idleTime, transferIdleTime, c.ID)
					idleTime = transferIdleTime
				}
			}
		}
		if idleTime > idleTimeout {
			logger.Debug(logSender, "close idle connection id: %v idle time: %v", c.ID, idleTime)
			err := c.sshConn.Close()
			if err != nil {
				logger.Warn(logSender, "error closing idle connection: %v", err)
			}
		}
	}
	logger.Debug(logSender, "check idle connections ended")
}

func addConnection(id string, conn Connection) {
	mutex.Lock()
	defer mutex.Unlock()
	openConnections[id] = conn
	logger.Debug(logSender, "connection added, num open connections: %v", len(openConnections))
}

func removeConnection(id string) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(openConnections, id)
	logger.Debug(logSender, "connection removed, num open connections: %v", len(openConnections))
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
		logger.Warn(logSender, "transfer to remove not found!")
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
			logger.Debug(logSender, "executed command \"%v\" with arguments: %v, %v, %v, error: %v",
				actions.Command, operation, path, target, err)
		} else {
			logger.Warn(logSender, "Invalid action command \"%v\" : %v", actions.Command, err)
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
				logger.Debug(logSender, "notified action to URL: %v status code: %v, elapsed: %v err: %v",
					url.String(), respCode, time.Since(startTime), err)
			}()
		} else {
			logger.Warn(logSender, "Invalid http_notification_url \"%v\" : %v", actions.HTTPNotificationURL, err)
		}
	}
	return err
}
