package sftpd

import (
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
)

var (
	mutex                sync.RWMutex
	openConnections      map[string]Connection
	activeTransfers      []*Transfer
	idleConnectionTicker *time.Ticker
	idleTimeout          time.Duration
	activeQuotaScans     []ActiveQuotaScan
	dataProvider         dataprovider.Provider
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
func RemoveQuotaScan(username string) {
	mutex.Lock()
	defer mutex.Unlock()
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
	}
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
	idleConnectionTicker = time.NewTicker(5 * time.Minute)
	idleTimeout = maxIdleTime
	go func() {
		for t := range idleConnectionTicker.C {
			logger.Debug(logSender, "idle connections check ticker %v", t)
			checkIdleConnections()
		}
	}()
}

func checkIdleConnections() {
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

func removeTransfer(transfer *Transfer) {
	mutex.Lock()
	defer mutex.Unlock()
	indexToRemove := -1
	for i, v := range activeTransfers {
		if v == transfer {
			indexToRemove = i
			break
		}
	}
	if indexToRemove >= 0 {
		//logger.Debug(logSender, "remove index %v from active transfer, size: %v", indexToRemove, len(activeTransfers))
		activeTransfers[indexToRemove] = activeTransfers[len(activeTransfers)-1]
		activeTransfers = activeTransfers[:len(activeTransfers)-1]
	} else {
		logger.Warn(logSender, "transfer to remove not found!")
	}
}

func updateConnectionActivity(id string) {
	mutex.Lock()
	defer mutex.Unlock()
	if c, ok := openConnections[id]; ok {
		//logger.Debug(logSender, "update connection activity, id: %v", id)
		c.lastActivity = time.Now()
		openConnections[id] = c
	}
	//logger.Debug(logSender, "connection activity updated: %+v", openConnections)
}

func logConnections() {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, c := range openConnections {
		logger.Debug(logSender, "active connection %+v", c)
	}
}

func logTransfers() {
	mutex.RLock()
	defer mutex.RUnlock()
	if len(activeTransfers) > 0 {
		for _, v := range activeTransfers {
			logger.Debug(logSender, "active transfer: %+v", v)
		}
	} else {
		logger.Debug(logSender, "no active transfer")
	}
}
