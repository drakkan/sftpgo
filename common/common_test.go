package common

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	logSenderTest    = "common_test"
	httpAddr         = "127.0.0.1:9999"
	configDir        = ".."
	osWindows        = "windows"
	userTestUsername = "common_test_username"
)

type fakeConnection struct {
	*BaseConnection
	command string
}

func (c *fakeConnection) AddUser(user dataprovider.User) error {
	_, err := user.GetFilesystem(c.GetID())
	if err != nil {
		return err
	}
	c.BaseConnection.User = user
	return nil
}

func (c *fakeConnection) Disconnect() error {
	Connections.Remove(c.GetID())
	return nil
}

func (c *fakeConnection) GetClientVersion() string {
	return ""
}

func (c *fakeConnection) GetCommand() string {
	return c.command
}

func (c *fakeConnection) GetLocalAddress() string {
	return ""
}

func (c *fakeConnection) GetRemoteAddress() string {
	return ""
}

type customNetConn struct {
	net.Conn
	id       string
	isClosed bool
}

func (c *customNetConn) Close() error {
	Connections.RemoveSSHConnection(c.id)
	c.isClosed = true
	return c.Conn.Close()
}

func TestSSHConnections(t *testing.T) {
	conn1, conn2 := net.Pipe()
	now := time.Now()
	sshConn1 := NewSSHConnection("id1", conn1)
	sshConn2 := NewSSHConnection("id2", conn2)
	sshConn3 := NewSSHConnection("id3", conn2)
	assert.Equal(t, "id1", sshConn1.GetID())
	assert.Equal(t, "id2", sshConn2.GetID())
	assert.Equal(t, "id3", sshConn3.GetID())
	sshConn1.UpdateLastActivity()
	assert.GreaterOrEqual(t, sshConn1.GetLastActivity().UnixNano(), now.UnixNano())
	Connections.AddSSHConnection(sshConn1)
	Connections.AddSSHConnection(sshConn2)
	Connections.AddSSHConnection(sshConn3)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 3)
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn1.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	assert.Equal(t, sshConn2.id, Connections.sshConnections[1].id)
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn1.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	assert.Equal(t, sshConn2.id, Connections.sshConnections[1].id)
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn2.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 1)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn3.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 0)
	Connections.RUnlock()
	assert.NoError(t, sshConn1.Close())
	assert.NoError(t, sshConn2.Close())
	assert.NoError(t, sshConn3.Close())
}

func TestDefenderIntegration(t *testing.T) {
	// by default defender is nil
	configCopy := Config

	wdPath, err := os.Getwd()
	require.NoError(t, err)
	pluginsConfig := []plugin.Config{
		{
			Type:     "ipfilter",
			Cmd:      filepath.Join(wdPath, "..", "tests", "ipfilter", "ipfilter"),
			AutoMTLS: true,
		},
	}
	if runtime.GOOS == osWindows {
		pluginsConfig[0].Cmd += ".exe"
	}
	err = plugin.Initialize(pluginsConfig, true)
	require.NoError(t, err)

	ip := "127.1.1.1"

	assert.Nil(t, Reload())
	// 192.168.1.12 is banned from the ipfilter plugin
	assert.True(t, IsBanned("192.168.1.12"))

	AddDefenderEvent(ip, HostEventNoLoginTried)
	assert.False(t, IsBanned(ip))

	banTime, err := GetDefenderBanTime(ip)
	assert.NoError(t, err)
	assert.Nil(t, banTime)
	assert.False(t, DeleteDefenderHost(ip))
	score, err := GetDefenderScore(ip)
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
	_, err = GetDefenderHost(ip)
	assert.Error(t, err)
	hosts, err := GetDefenderHosts()
	assert.NoError(t, err)
	assert.Nil(t, hosts)

	Config.DefenderConfig = DefenderConfig{
		Enabled:          true,
		Driver:           DefenderDriverProvider,
		BanTime:          10,
		BanTimeIncrement: 50,
		Threshold:        0,
		ScoreInvalid:     2,
		ScoreValid:       1,
		ObservationTime:  15,
		EntriesSoftLimit: 100,
		EntriesHardLimit: 150,
	}
	err = Initialize(Config, 0)
	// ScoreInvalid cannot be greater than threshold
	assert.Error(t, err)
	Config.DefenderConfig.Driver = "unsupported"
	err = Initialize(Config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported defender driver")
	}
	Config.DefenderConfig.Driver = DefenderDriverMemory
	err = Initialize(Config, 0)
	// ScoreInvalid cannot be greater than threshold
	assert.Error(t, err)
	Config.DefenderConfig.Threshold = 3
	Config.DefenderConfig.SafeListFile = filepath.Join(os.TempDir(), "sl.json")
	err = os.WriteFile(Config.DefenderConfig.SafeListFile, []byte(`{}`), 0644)
	assert.NoError(t, err)
	defer os.Remove(Config.DefenderConfig.SafeListFile)

	err = Initialize(Config, 0)
	assert.NoError(t, err)
	assert.Nil(t, Reload())
	err = os.WriteFile(Config.DefenderConfig.SafeListFile, []byte(`{`), 0644)
	assert.NoError(t, err)
	err = Reload()
	assert.Error(t, err)

	AddDefenderEvent(ip, HostEventNoLoginTried)
	assert.False(t, IsBanned(ip))
	score, err = GetDefenderScore(ip)
	assert.NoError(t, err)
	assert.Equal(t, 2, score)
	entry, err := GetDefenderHost(ip)
	assert.NoError(t, err)
	asJSON, err := json.Marshal(&entry)
	assert.NoError(t, err)
	assert.Equal(t, `{"id":"3132372e312e312e31","ip":"127.1.1.1","score":2}`, string(asJSON), "entry %v", entry)
	assert.True(t, DeleteDefenderHost(ip))
	banTime, err = GetDefenderBanTime(ip)
	assert.NoError(t, err)
	assert.Nil(t, banTime)

	AddDefenderEvent(ip, HostEventLoginFailed)
	AddDefenderEvent(ip, HostEventNoLoginTried)
	assert.True(t, IsBanned(ip))
	score, err = GetDefenderScore(ip)
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
	banTime, err = GetDefenderBanTime(ip)
	assert.NoError(t, err)
	assert.NotNil(t, banTime)
	hosts, err = GetDefenderHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 1)
	entry, err = GetDefenderHost(ip)
	assert.NoError(t, err)
	assert.False(t, entry.BanTime.IsZero())
	assert.True(t, DeleteDefenderHost(ip))
	hosts, err = GetDefenderHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)
	banTime, err = GetDefenderBanTime(ip)
	assert.NoError(t, err)
	assert.Nil(t, banTime)
	assert.False(t, DeleteDefenderHost(ip))

	Config = configCopy
}

func TestRateLimitersIntegration(t *testing.T) {
	// by default defender is nil
	configCopy := Config

	Config.RateLimitersConfig = []RateLimiterConfig{
		{
			Average:   100,
			Period:    10,
			Burst:     5,
			Type:      int(rateLimiterTypeGlobal),
			Protocols: rateLimiterProtocolValues,
		},
		{
			Average:                1,
			Period:                 1000,
			Burst:                  1,
			Type:                   int(rateLimiterTypeSource),
			Protocols:              []string{ProtocolWebDAV, ProtocolWebDAV, ProtocolFTP},
			GenerateDefenderEvents: true,
			EntriesSoftLimit:       100,
			EntriesHardLimit:       150,
		},
	}
	err := Initialize(Config, 0)
	assert.Error(t, err)
	Config.RateLimitersConfig[0].Period = 1000
	Config.RateLimitersConfig[0].AllowList = []string{"1.1.1", "1.1.1.2"}
	err = Initialize(Config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to parse rate limiter allow list")
	}
	Config.RateLimitersConfig[0].AllowList = []string{"172.16.24.7"}
	Config.RateLimitersConfig[1].AllowList = []string{"172.16.0.0/16"}

	err = Initialize(Config, 0)
	assert.NoError(t, err)

	assert.Len(t, rateLimiters, 4)
	assert.Len(t, rateLimiters[ProtocolSSH], 1)
	assert.Len(t, rateLimiters[ProtocolFTP], 2)
	assert.Len(t, rateLimiters[ProtocolWebDAV], 2)
	assert.Len(t, rateLimiters[ProtocolHTTP], 1)

	source1 := "127.1.1.1"
	source2 := "127.1.1.2"
	source3 := "172.16.24.7" // whitelisted

	_, err = LimitRate(ProtocolSSH, source1)
	assert.NoError(t, err)
	_, err = LimitRate(ProtocolFTP, source1)
	assert.NoError(t, err)
	// sleep to allow the add configured burst to the token.
	// This sleep is not enough to add the per-source burst
	time.Sleep(20 * time.Millisecond)
	_, err = LimitRate(ProtocolWebDAV, source2)
	assert.NoError(t, err)
	_, err = LimitRate(ProtocolFTP, source1)
	assert.Error(t, err)
	_, err = LimitRate(ProtocolWebDAV, source2)
	assert.Error(t, err)
	_, err = LimitRate(ProtocolSSH, source1)
	assert.NoError(t, err)
	_, err = LimitRate(ProtocolSSH, source2)
	assert.NoError(t, err)
	for i := 0; i < 10; i++ {
		_, err = LimitRate(ProtocolWebDAV, source3)
		assert.NoError(t, err)
	}

	Config = configCopy
}

func TestWhitelist(t *testing.T) {
	configCopy := Config

	Config.whitelist = &whitelist{}
	err := Config.whitelist.reload()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "cannot accept a nil whitelist")
	}
	wlFile := filepath.Join(os.TempDir(), "wl.json")
	Config.WhiteListFile = wlFile

	err = os.WriteFile(wlFile, []byte(`invalid list file`), 0664)
	assert.NoError(t, err)
	err = Initialize(Config, 0)
	assert.Error(t, err)

	wl := HostListFile{
		IPAddresses:  []string{"172.18.1.1", "172.18.1.2"},
		CIDRNetworks: []string{"10.8.7.0/24"},
	}
	data, err := json.Marshal(wl)
	assert.NoError(t, err)
	err = os.WriteFile(wlFile, data, 0664)
	assert.NoError(t, err)
	defer os.Remove(wlFile)

	err = Initialize(Config, 0)
	assert.NoError(t, err)

	assert.True(t, Connections.IsNewConnectionAllowed("172.18.1.1"))
	assert.False(t, Connections.IsNewConnectionAllowed("172.18.1.3"))
	assert.True(t, Connections.IsNewConnectionAllowed("10.8.7.3"))
	assert.False(t, Connections.IsNewConnectionAllowed("10.8.8.2"))

	wl.IPAddresses = append(wl.IPAddresses, "172.18.1.3")
	wl.CIDRNetworks = append(wl.CIDRNetworks, "10.8.8.0/24")
	data, err = json.Marshal(wl)
	assert.NoError(t, err)
	err = os.WriteFile(wlFile, data, 0664)
	assert.NoError(t, err)
	assert.False(t, Connections.IsNewConnectionAllowed("10.8.8.3"))

	err = Reload()
	assert.NoError(t, err)
	assert.True(t, Connections.IsNewConnectionAllowed("10.8.8.3"))
	assert.True(t, Connections.IsNewConnectionAllowed("172.18.1.3"))
	assert.True(t, Connections.IsNewConnectionAllowed("172.18.1.2"))
	assert.False(t, Connections.IsNewConnectionAllowed("172.18.1.12"))

	Config = configCopy
}

func TestMaxConnections(t *testing.T) {
	oldValue := Config.MaxTotalConnections
	perHost := Config.MaxPerHostConnections

	Config.MaxPerHostConnections = 0

	ipAddr := "192.168.7.8"
	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))

	Config.MaxTotalConnections = 1
	Config.MaxPerHostConnections = perHost

	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))
	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	assert.Len(t, Connections.GetStats(), 1)
	assert.False(t, Connections.IsNewConnectionAllowed(ipAddr))

	res := Connections.Close(fakeConn.GetID())
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 300*time.Millisecond, 50*time.Millisecond)

	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))
	Connections.AddClientConnection(ipAddr)
	Connections.AddClientConnection(ipAddr)
	assert.False(t, Connections.IsNewConnectionAllowed(ipAddr))
	Connections.RemoveClientConnection(ipAddr)
	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))
	Connections.RemoveClientConnection(ipAddr)

	Config.MaxTotalConnections = oldValue
}

func TestMaxConnectionPerHost(t *testing.T) {
	oldValue := Config.MaxPerHostConnections

	Config.MaxPerHostConnections = 2

	ipAddr := "192.168.9.9"
	Connections.AddClientConnection(ipAddr)
	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))

	Connections.AddClientConnection(ipAddr)
	assert.True(t, Connections.IsNewConnectionAllowed(ipAddr))

	Connections.AddClientConnection(ipAddr)
	assert.False(t, Connections.IsNewConnectionAllowed(ipAddr))
	assert.Equal(t, int32(3), Connections.GetClientConnections())

	Connections.RemoveClientConnection(ipAddr)
	Connections.RemoveClientConnection(ipAddr)
	Connections.RemoveClientConnection(ipAddr)

	assert.Equal(t, int32(0), Connections.GetClientConnections())

	Config.MaxPerHostConnections = oldValue
}

func TestIdleConnections(t *testing.T) {
	configCopy := Config

	Config.IdleTimeout = 1
	err := Initialize(Config, 0)
	assert.NoError(t, err)

	conn1, conn2 := net.Pipe()
	customConn1 := &customNetConn{
		Conn: conn1,
		id:   "id1",
	}
	customConn2 := &customNetConn{
		Conn: conn2,
		id:   "id2",
	}
	sshConn1 := NewSSHConnection(customConn1.id, customConn1)
	sshConn2 := NewSSHConnection(customConn2.id, customConn2)

	username := "test_user"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
		},
	}
	c := NewBaseConnection(sshConn1.id+"_1", ProtocolSFTP, "", "", user)
	c.lastActivity = time.Now().Add(-24 * time.Hour).UnixNano()
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	// both ssh connections are expired but they should get removed only
	// if there is no associated connection
	sshConn1.lastActivity = c.lastActivity
	sshConn2.lastActivity = c.lastActivity
	Connections.AddSSHConnection(sshConn1)
	Connections.Add(fakeConn)
	assert.Equal(t, Connections.GetActiveSessions(username), 1)
	c = NewBaseConnection(sshConn2.id+"_1", ProtocolSSH, "", "", user)
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	Connections.AddSSHConnection(sshConn2)
	Connections.Add(fakeConn)
	assert.Equal(t, Connections.GetActiveSessions(username), 2)

	cFTP := NewBaseConnection("id2", ProtocolFTP, "", "", dataprovider.User{})
	cFTP.lastActivity = time.Now().UnixNano()
	fakeConn = &fakeConnection{
		BaseConnection: cFTP,
	}
	Connections.Add(fakeConn)
	assert.Equal(t, Connections.GetActiveSessions(username), 2)
	assert.Len(t, Connections.GetStats(), 3)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	Connections.RUnlock()

	startPeriodicTimeoutTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return Connections.GetActiveSessions(username) == 1 }, 1*time.Second, 200*time.Millisecond)
	assert.Eventually(t, func() bool {
		Connections.RLock()
		defer Connections.RUnlock()
		return len(Connections.sshConnections) == 1
	}, 1*time.Second, 200*time.Millisecond)
	stopPeriodicTimeoutTicker()
	assert.Len(t, Connections.GetStats(), 2)
	c.lastActivity = time.Now().Add(-24 * time.Hour).UnixNano()
	cFTP.lastActivity = time.Now().Add(-24 * time.Hour).UnixNano()
	sshConn2.lastActivity = c.lastActivity
	startPeriodicTimeoutTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 1*time.Second, 200*time.Millisecond)
	assert.Eventually(t, func() bool {
		Connections.RLock()
		defer Connections.RUnlock()
		return len(Connections.sshConnections) == 0
	}, 1*time.Second, 200*time.Millisecond)
	assert.Equal(t, int32(0), Connections.GetClientConnections())
	stopPeriodicTimeoutTicker()
	assert.True(t, customConn1.isClosed)
	assert.True(t, customConn2.isClosed)

	Config = configCopy
}

func TestCloseConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	assert.True(t, Connections.IsNewConnectionAllowed("127.0.0.1"))
	Connections.Add(fakeConn)
	assert.Len(t, Connections.GetStats(), 1)
	res := Connections.Close(fakeConn.GetID())
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
	res = Connections.Close(fakeConn.GetID())
	assert.False(t, res)
	Connections.Remove(fakeConn.GetID())
}

func TestSwapConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	if assert.Len(t, Connections.GetStats(), 1) {
		assert.Equal(t, "", Connections.GetStats()[0].Username)
	}
	c = NewBaseConnection("id", ProtocolFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: userTestUsername,
		},
	})
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Swap(fakeConn)
	assert.NoError(t, err)
	if assert.Len(t, Connections.GetStats(), 1) {
		assert.Equal(t, userTestUsername, Connections.GetStats()[0].Username)
	}
	res := Connections.Close(fakeConn.GetID())
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
	err = Connections.Swap(fakeConn)
	assert.Error(t, err)
}

func TestAtomicUpload(t *testing.T) {
	configCopy := Config

	Config.UploadMode = UploadModeStandard
	assert.False(t, Config.IsAtomicUploadEnabled())
	Config.UploadMode = UploadModeAtomic
	assert.True(t, Config.IsAtomicUploadEnabled())
	Config.UploadMode = UploadModeAtomicWithResume
	assert.True(t, Config.IsAtomicUploadEnabled())

	Config = configCopy
}

func TestConnectionStatus(t *testing.T) {
	username := "test_user"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
		},
	}
	fs := vfs.NewOsFs("", os.TempDir(), "")
	c1 := NewBaseConnection("id1", ProtocolSFTP, "", "", user)
	fakeConn1 := &fakeConnection{
		BaseConnection: c1,
	}
	t1 := NewBaseTransfer(nil, c1, nil, "/p1", "/p1", "/r1", TransferUpload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	t1.BytesReceived = 123
	t2 := NewBaseTransfer(nil, c1, nil, "/p2", "/p2", "/r2", TransferDownload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	t2.BytesSent = 456
	c2 := NewBaseConnection("id2", ProtocolSSH, "", "", user)
	fakeConn2 := &fakeConnection{
		BaseConnection: c2,
		command:        "md5sum",
	}
	c3 := NewBaseConnection("id3", ProtocolWebDAV, "", "", user)
	fakeConn3 := &fakeConnection{
		BaseConnection: c3,
		command:        "PROPFIND",
	}
	t3 := NewBaseTransfer(nil, c3, nil, "/p2", "/p2", "/r2", TransferDownload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	Connections.Add(fakeConn1)
	Connections.Add(fakeConn2)
	Connections.Add(fakeConn3)

	stats := Connections.GetStats()
	assert.Len(t, stats, 3)
	for _, stat := range stats {
		assert.Equal(t, stat.Username, username)
		assert.True(t, strings.HasPrefix(stat.GetConnectionInfo(), stat.Protocol))
		assert.True(t, strings.HasPrefix(stat.GetConnectionDuration(), "00:"))
		if stat.ConnectionID == "SFTP_id1" {
			assert.Len(t, stat.Transfers, 2)
			assert.Greater(t, len(stat.GetTransfersAsString()), 0)
			for _, tr := range stat.Transfers {
				if tr.OperationType == operationDownload {
					assert.True(t, strings.HasPrefix(tr.getConnectionTransferAsString(), "DL"))
				} else if tr.OperationType == operationUpload {
					assert.True(t, strings.HasPrefix(tr.getConnectionTransferAsString(), "UL"))
				}
			}
		} else if stat.ConnectionID == "DAV_id3" {
			assert.Len(t, stat.Transfers, 1)
			assert.Greater(t, len(stat.GetTransfersAsString()), 0)
		} else {
			assert.Equal(t, 0, len(stat.GetTransfersAsString()))
		}
	}

	err := t1.Close()
	assert.NoError(t, err)
	err = t2.Close()
	assert.NoError(t, err)

	err = fakeConn3.SignalTransfersAbort()
	assert.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&t3.AbortTransfer))
	err = t3.Close()
	assert.NoError(t, err)
	err = fakeConn3.SignalTransfersAbort()
	assert.Error(t, err)

	Connections.Remove(fakeConn1.GetID())
	stats = Connections.GetStats()
	assert.Len(t, stats, 2)
	assert.Equal(t, fakeConn3.GetID(), stats[0].ConnectionID)
	assert.Equal(t, fakeConn2.GetID(), stats[1].ConnectionID)
	Connections.Remove(fakeConn2.GetID())
	stats = Connections.GetStats()
	assert.Len(t, stats, 1)
	assert.Equal(t, fakeConn3.GetID(), stats[0].ConnectionID)
	Connections.Remove(fakeConn3.GetID())
	stats = Connections.GetStats()
	assert.Len(t, stats, 0)
}

func TestQuotaScans(t *testing.T) {
	username := "username"
	assert.True(t, QuotaScans.AddUserQuotaScan(username))
	assert.False(t, QuotaScans.AddUserQuotaScan(username))
	usersScans := QuotaScans.GetUsersQuotaScans()
	if assert.Len(t, usersScans, 1) {
		assert.Equal(t, usersScans[0].Username, username)
		assert.Equal(t, QuotaScans.UserScans[0].StartTime, usersScans[0].StartTime)
		QuotaScans.UserScans[0].StartTime = 0
		assert.NotEqual(t, QuotaScans.UserScans[0].StartTime, usersScans[0].StartTime)
	}

	assert.True(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.False(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.Len(t, QuotaScans.GetUsersQuotaScans(), 0)
	assert.Len(t, usersScans, 1)

	folderName := "folder"
	assert.True(t, QuotaScans.AddVFolderQuotaScan(folderName))
	assert.False(t, QuotaScans.AddVFolderQuotaScan(folderName))
	if assert.Len(t, QuotaScans.GetVFoldersQuotaScans(), 1) {
		assert.Equal(t, QuotaScans.GetVFoldersQuotaScans()[0].Name, folderName)
	}

	assert.True(t, QuotaScans.RemoveVFolderQuotaScan(folderName))
	assert.False(t, QuotaScans.RemoveVFolderQuotaScan(folderName))
	assert.Len(t, QuotaScans.GetVFoldersQuotaScans(), 0)
}

func TestProxyProtocolVersion(t *testing.T) {
	c := Configuration{
		ProxyProtocol: 0,
	}
	_, err := c.GetProxyListener(nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "proxy protocol not configured")
	}
	c.ProxyProtocol = 1
	proxyListener, err := c.GetProxyListener(nil)
	assert.NoError(t, err)
	assert.Nil(t, proxyListener.Policy)

	c.ProxyProtocol = 2
	proxyListener, err = c.GetProxyListener(nil)
	assert.NoError(t, err)
	assert.NotNil(t, proxyListener.Policy)

	c.ProxyProtocol = 1
	c.ProxyAllowed = []string{"invalid"}
	_, err = c.GetProxyListener(nil)
	assert.Error(t, err)

	c.ProxyProtocol = 2
	_, err = c.GetProxyListener(nil)
	assert.Error(t, err)
}

func TestStartupHook(t *testing.T) {
	Config.StartupHook = ""

	assert.NoError(t, Config.ExecuteStartupHook())

	Config.StartupHook = "http://foo\x7f.com/startup"
	assert.Error(t, Config.ExecuteStartupHook())

	Config.StartupHook = "http://invalid:5678/"
	assert.Error(t, Config.ExecuteStartupHook())

	Config.StartupHook = fmt.Sprintf("http://%v", httpAddr)
	assert.NoError(t, Config.ExecuteStartupHook())

	Config.StartupHook = "invalidhook"
	assert.Error(t, Config.ExecuteStartupHook())

	if runtime.GOOS != osWindows {
		hookCmd, err := exec.LookPath("true")
		assert.NoError(t, err)
		Config.StartupHook = hookCmd
		assert.NoError(t, Config.ExecuteStartupHook())
	}

	Config.StartupHook = ""
}

func TestPostDisconnectHook(t *testing.T) {
	Config.PostDisconnectHook = "http://127.0.0.1/"

	remoteAddr := "127.0.0.1:80"
	Config.checkPostDisconnectHook(remoteAddr, ProtocolHTTP, "", "", time.Now())
	Config.checkPostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())

	Config.PostDisconnectHook = "http://bar\x7f.com/"
	Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())

	Config.PostDisconnectHook = fmt.Sprintf("http://%v", httpAddr)
	Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())

	Config.PostDisconnectHook = "relativePath"
	Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())

	if runtime.GOOS == osWindows {
		Config.PostDisconnectHook = "C:\\a\\bad\\command"
		Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())
	} else {
		Config.PostDisconnectHook = "/invalid/path"
		Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())

		hookCmd, err := exec.LookPath("true")
		assert.NoError(t, err)
		Config.PostDisconnectHook = hookCmd
		Config.executePostDisconnectHook(remoteAddr, ProtocolSFTP, "", "", time.Now())
	}
	Config.PostDisconnectHook = ""
}

func TestPostConnectHook(t *testing.T) {
	Config.PostConnectHook = ""

	ipAddr := "127.0.0.1"

	assert.NoError(t, Config.ExecutePostConnectHook(ipAddr, ProtocolFTP))

	Config.PostConnectHook = "http://foo\x7f.com/"
	assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolSFTP))

	Config.PostConnectHook = "http://invalid:1234/"
	assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolSFTP))

	Config.PostConnectHook = fmt.Sprintf("http://%v/404", httpAddr)
	assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolFTP))

	Config.PostConnectHook = fmt.Sprintf("http://%v", httpAddr)
	assert.NoError(t, Config.ExecutePostConnectHook(ipAddr, ProtocolFTP))

	Config.PostConnectHook = "invalid"
	assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolFTP))

	if runtime.GOOS == osWindows {
		Config.PostConnectHook = "C:\\bad\\command"
		assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolSFTP))
	} else {
		Config.PostConnectHook = "/invalid/path"
		assert.Error(t, Config.ExecutePostConnectHook(ipAddr, ProtocolSFTP))

		hookCmd, err := exec.LookPath("true")
		assert.NoError(t, err)
		Config.PostConnectHook = hookCmd
		assert.NoError(t, Config.ExecutePostConnectHook(ipAddr, ProtocolSFTP))
	}

	Config.PostConnectHook = ""
}

func TestCryptoConvertFileInfo(t *testing.T) {
	name := "name"
	fs, err := vfs.NewCryptFs("connID1", os.TempDir(), "", vfs.CryptFsConfig{
		Passphrase: kms.NewPlainSecret("secret"),
	})
	require.NoError(t, err)
	cryptFs := fs.(*vfs.CryptFs)
	info := vfs.NewFileInfo(name, true, 48, time.Now(), false)
	assert.Equal(t, info, cryptFs.ConvertFileInfo(info))
	info = vfs.NewFileInfo(name, false, 48, time.Now(), false)
	assert.NotEqual(t, info.Size(), cryptFs.ConvertFileInfo(info).Size())
	info = vfs.NewFileInfo(name, false, 33, time.Now(), false)
	assert.Equal(t, int64(0), cryptFs.ConvertFileInfo(info).Size())
	info = vfs.NewFileInfo(name, false, 1, time.Now(), false)
	assert.Equal(t, int64(0), cryptFs.ConvertFileInfo(info).Size())
}

func TestFolderCopy(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		ID:              1,
		Name:            "name",
		MappedPath:      filepath.Clean(os.TempDir()),
		UsedQuotaSize:   4096,
		UsedQuotaFiles:  2,
		LastQuotaUpdate: util.GetTimeAsMsSinceEpoch(time.Now()),
		Users:           []string{"user1", "user2"},
	}
	folderCopy := folder.GetACopy()
	folder.ID = 2
	folder.Users = []string{"user3"}
	require.Len(t, folderCopy.Users, 2)
	require.True(t, util.IsStringInSlice("user1", folderCopy.Users))
	require.True(t, util.IsStringInSlice("user2", folderCopy.Users))
	require.Equal(t, int64(1), folderCopy.ID)
	require.Equal(t, folder.Name, folderCopy.Name)
	require.Equal(t, folder.MappedPath, folderCopy.MappedPath)
	require.Equal(t, folder.UsedQuotaSize, folderCopy.UsedQuotaSize)
	require.Equal(t, folder.UsedQuotaFiles, folderCopy.UsedQuotaFiles)
	require.Equal(t, folder.LastQuotaUpdate, folderCopy.LastQuotaUpdate)

	folder.FsConfig = vfs.Filesystem{
		CryptConfig: vfs.CryptFsConfig{
			Passphrase: kms.NewPlainSecret("crypto secret"),
		},
	}
	folderCopy = folder.GetACopy()
	folder.FsConfig.CryptConfig.Passphrase = kms.NewEmptySecret()
	require.Len(t, folderCopy.Users, 1)
	require.True(t, util.IsStringInSlice("user3", folderCopy.Users))
	require.Equal(t, int64(2), folderCopy.ID)
	require.Equal(t, folder.Name, folderCopy.Name)
	require.Equal(t, folder.MappedPath, folderCopy.MappedPath)
	require.Equal(t, folder.UsedQuotaSize, folderCopy.UsedQuotaSize)
	require.Equal(t, folder.UsedQuotaFiles, folderCopy.UsedQuotaFiles)
	require.Equal(t, folder.LastQuotaUpdate, folderCopy.LastQuotaUpdate)
	require.Equal(t, "crypto secret", folderCopy.FsConfig.CryptConfig.Passphrase.GetPayload())
}

func TestCachedFs(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	conn := NewBaseConnection("id", ProtocolSFTP, "", "", user)
	// changing the user should not affect the connection
	user.HomeDir = filepath.Join(os.TempDir(), "temp")
	err := os.Mkdir(user.HomeDir, os.ModePerm)
	assert.NoError(t, err)
	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)
	p, err := fs.ResolvePath("/")
	assert.NoError(t, err)
	assert.Equal(t, user.GetHomeDir(), p)

	_, p, err = conn.GetFsAndResolvedPath("/")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Clean(os.TempDir()), p)
	// the filesystem is cached changing the provider will not affect the connection
	conn.User.FsConfig.Provider = sdk.S3FilesystemProvider
	_, p, err = conn.GetFsAndResolvedPath("/")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Clean(os.TempDir()), p)
	user = dataprovider.User{}
	user.HomeDir = filepath.Join(os.TempDir(), "temp")
	user.FsConfig.Provider = sdk.S3FilesystemProvider
	_, err = user.GetFilesystem("")
	assert.Error(t, err)

	err = os.Remove(user.HomeDir)
	assert.NoError(t, err)
}

func TestParseAllowedIPAndRanges(t *testing.T) {
	_, err := util.ParseAllowedIPAndRanges([]string{"1.1.1.1", "not an ip"})
	assert.Error(t, err)
	_, err = util.ParseAllowedIPAndRanges([]string{"1.1.1.5", "192.168.1.0/240"})
	assert.Error(t, err)
	allow, err := util.ParseAllowedIPAndRanges([]string{"192.168.1.2", "172.16.0.0/24"})
	assert.NoError(t, err)
	assert.True(t, allow[0](net.ParseIP("192.168.1.2")))
	assert.False(t, allow[0](net.ParseIP("192.168.2.2")))
	assert.True(t, allow[1](net.ParseIP("172.16.0.1")))
	assert.False(t, allow[1](net.ParseIP("172.16.1.1")))
}

func TestHideConfidentialData(t *testing.T) {
	for _, provider := range []sdk.FilesystemProvider{sdk.LocalFilesystemProvider,
		sdk.CryptedFilesystemProvider, sdk.S3FilesystemProvider, sdk.GCSFilesystemProvider,
		sdk.AzureBlobFilesystemProvider, sdk.SFTPFilesystemProvider,
	} {
		u := dataprovider.User{
			FsConfig: vfs.Filesystem{
				Provider: provider,
			},
		}
		u.PrepareForRendering()
		f := vfs.BaseVirtualFolder{
			FsConfig: vfs.Filesystem{
				Provider: provider,
			},
		}
		f.PrepareForRendering()
	}
	a := dataprovider.Admin{}
	a.HideConfidentialData()
}

func TestUserPerms(t *testing.T) {
	u := dataprovider.User{}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermDelete}
	assert.True(t, u.HasAnyPerm([]string{dataprovider.PermRename, dataprovider.PermDelete}, "/"))
	assert.False(t, u.HasAnyPerm([]string{dataprovider.PermRename, dataprovider.PermCreateDirs}, "/"))
	u.Permissions["/"] = []string{dataprovider.PermDelete, dataprovider.PermCreateDirs}
	assert.True(t, u.HasPermsDeleteAll("/"))
	assert.False(t, u.HasPermsRenameAll("/"))
	u.Permissions["/"] = []string{dataprovider.PermDeleteDirs, dataprovider.PermDeleteFiles, dataprovider.PermRenameDirs}
	assert.True(t, u.HasPermsDeleteAll("/"))
	assert.False(t, u.HasPermsRenameAll("/"))
	u.Permissions["/"] = []string{dataprovider.PermDeleteDirs, dataprovider.PermRenameFiles, dataprovider.PermRenameDirs}
	assert.False(t, u.HasPermsDeleteAll("/"))
	assert.True(t, u.HasPermsRenameAll("/"))
}

func TestGetTLSVersion(t *testing.T) {
	tlsVer := util.GetTLSVersion(0)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsVer)
	tlsVer = util.GetTLSVersion(12)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsVer)
	tlsVer = util.GetTLSVersion(2)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsVer)
	tlsVer = util.GetTLSVersion(13)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsVer)
}

func TestCleanPath(t *testing.T) {
	assert.Equal(t, "/", util.CleanPath("/"))
	assert.Equal(t, "/", util.CleanPath("."))
	assert.Equal(t, "/", util.CleanPath(""))
	assert.Equal(t, "/", util.CleanPath("/."))
	assert.Equal(t, "/", util.CleanPath("/a/.."))
	assert.Equal(t, "/a", util.CleanPath("/a/"))
	assert.Equal(t, "/a", util.CleanPath("a/"))
	// filepath.ToSlash does not touch \ as char on unix systems
	// so os.PathSeparator is used for windows compatible tests
	bslash := string(os.PathSeparator)
	assert.Equal(t, "/", util.CleanPath(bslash))
	assert.Equal(t, "/", util.CleanPath(bslash+bslash))
	assert.Equal(t, "/a", util.CleanPath(bslash+"a"+bslash))
	assert.Equal(t, "/a", util.CleanPath("a"+bslash))
	assert.Equal(t, "/a/b/c", util.CleanPath(bslash+"a"+bslash+bslash+"b"+bslash+bslash+"c"+bslash))
	assert.Equal(t, "/C:/a", util.CleanPath("C:"+bslash+"a"))
}

func TestUserRecentActivity(t *testing.T) {
	u := dataprovider.User{}
	res := u.HasRecentActivity()
	assert.False(t, res)
	u.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	res = u.HasRecentActivity()
	assert.True(t, res)
	u.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Minute))
	res = u.HasRecentActivity()
	assert.False(t, res)
	u.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Second))
	res = u.HasRecentActivity()
	assert.True(t, res)
}

func BenchmarkBcryptHashing(b *testing.B) {
	bcryptPassword := "bcryptpassword"
	for i := 0; i < b.N; i++ {
		_, err := bcrypt.GenerateFromPassword([]byte(bcryptPassword), 10)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkCompareBcryptPassword(b *testing.B) {
	bcryptPassword := "$2a$10$lPDdnDimJZ7d5/GwL6xDuOqoZVRXok6OHHhivCnanWUtcgN0Zafki"
	for i := 0; i < b.N; i++ {
		err := bcrypt.CompareHashAndPassword([]byte(bcryptPassword), []byte("password"))
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkArgon2Hashing(b *testing.B) {
	argonPassword := "argon2password"
	for i := 0; i < b.N; i++ {
		_, err := argon2id.CreateHash(argonPassword, argon2id.DefaultParams)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkCompareArgon2Password(b *testing.B) {
	argon2Password := "$argon2id$v=19$m=65536,t=1,p=2$aOoAOdAwvzhOgi7wUFjXlw$wn/y37dBWdKHtPXHR03nNaKHWKPXyNuVXOknaU+YZ+s"
	for i := 0; i < b.N; i++ {
		_, err := argon2id.ComparePasswordAndHash("password", argon2Password)
		if err != nil {
			panic(err)
		}
	}
}
