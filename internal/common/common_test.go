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
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/pires/go-proxyproto"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	logSenderTest    = "common_test"
	httpAddr         = "127.0.0.1:9999"
	osWindows        = "windows"
	userTestUsername = "common_test_username"
)

var (
	configDir = filepath.Join(".", "..", "..")
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
	c.User = user
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

func TestConnections(t *testing.T) {
	c1 := &fakeConnection{
		BaseConnection: NewBaseConnection("id1", ProtocolSFTP, "", "", dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: userTestUsername,
			},
		}),
	}
	c2 := &fakeConnection{
		BaseConnection: NewBaseConnection("id2", ProtocolSFTP, "", "", dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: userTestUsername,
			},
		}),
	}
	c3 := &fakeConnection{
		BaseConnection: NewBaseConnection("id3", ProtocolSFTP, "", "", dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: userTestUsername,
			},
		}),
	}
	c4 := &fakeConnection{
		BaseConnection: NewBaseConnection("id4", ProtocolSFTP, "", "", dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: userTestUsername,
			},
		}),
	}
	assert.Equal(t, "SFTP_id1", c1.GetID())
	assert.Equal(t, "SFTP_id2", c2.GetID())
	assert.Equal(t, "SFTP_id3", c3.GetID())
	assert.Equal(t, "SFTP_id4", c4.GetID())
	err := Connections.Add(c1)
	assert.NoError(t, err)
	err = Connections.Add(c2)
	assert.NoError(t, err)
	err = Connections.Add(c3)
	assert.NoError(t, err)
	err = Connections.Add(c4)
	assert.NoError(t, err)

	Connections.RLock()
	assert.Len(t, Connections.connections, 4)
	assert.Len(t, Connections.mapping, 4)
	_, ok := Connections.mapping[c1.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.mapping[c1.GetID()])
	assert.Equal(t, 1, Connections.mapping[c2.GetID()])
	assert.Equal(t, 2, Connections.mapping[c3.GetID()])
	assert.Equal(t, 3, Connections.mapping[c4.GetID()])
	Connections.RUnlock()

	c2 = &fakeConnection{
		BaseConnection: NewBaseConnection("id2", ProtocolSFTP, "", "", dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: userTestUsername + "_mod",
			},
		}),
	}
	err = Connections.Swap(c2)
	assert.NoError(t, err)

	Connections.RLock()
	assert.Len(t, Connections.connections, 4)
	assert.Len(t, Connections.mapping, 4)
	_, ok = Connections.mapping[c1.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.mapping[c1.GetID()])
	assert.Equal(t, 1, Connections.mapping[c2.GetID()])
	assert.Equal(t, 2, Connections.mapping[c3.GetID()])
	assert.Equal(t, 3, Connections.mapping[c4.GetID()])
	assert.Equal(t, userTestUsername+"_mod", Connections.connections[1].GetUsername())
	Connections.RUnlock()

	Connections.Remove(c2.GetID())

	Connections.RLock()
	assert.Len(t, Connections.connections, 3)
	assert.Len(t, Connections.mapping, 3)
	_, ok = Connections.mapping[c1.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.mapping[c1.GetID()])
	assert.Equal(t, 1, Connections.mapping[c4.GetID()])
	assert.Equal(t, 2, Connections.mapping[c3.GetID()])
	Connections.RUnlock()

	Connections.Remove(c3.GetID())

	Connections.RLock()
	assert.Len(t, Connections.connections, 2)
	assert.Len(t, Connections.mapping, 2)
	_, ok = Connections.mapping[c1.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.mapping[c1.GetID()])
	assert.Equal(t, 1, Connections.mapping[c4.GetID()])
	Connections.RUnlock()

	Connections.Remove(c1.GetID())

	Connections.RLock()
	assert.Len(t, Connections.connections, 1)
	assert.Len(t, Connections.mapping, 1)
	_, ok = Connections.mapping[c4.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.mapping[c4.GetID()])
	Connections.RUnlock()

	Connections.Remove(c4.GetID())

	Connections.RLock()
	assert.Len(t, Connections.connections, 0)
	assert.Len(t, Connections.mapping, 0)
	Connections.RUnlock()
}

func TestEventManagerCommandsInitialization(t *testing.T) {
	configCopy := Config

	c := Configuration{
		EventManager: EventManagerConfig{
			EnabledCommands: []string{"ls"}, // not an absolute path
		},
	}
	err := Initialize(c, 0)
	assert.ErrorContains(t, err, "invalid command")

	var commands []string
	if runtime.GOOS == osWindows {
		commands = []string{"C:\\command"}
	} else {
		commands = []string{"/bin/ls"}
	}

	c.EventManager.EnabledCommands = commands
	err = Initialize(c, 0)
	assert.NoError(t, err)
	assert.Equal(t, commands, dataprovider.EnabledActionCommands)

	dataprovider.EnabledActionCommands = configCopy.EventManager.EnabledCommands
	Config = configCopy
}

func TestInitializationProxyErrors(t *testing.T) {
	configCopy := Config

	c := Configuration{
		ProxyProtocol: 1,
		ProxyAllowed:  []string{"1.1.1.1111"},
	}
	err := Initialize(c, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid proxy allowed")
	}
	c.ProxyAllowed = nil
	c.ProxySkipped = []string{"invalid"}
	err = Initialize(c, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid proxy skipped")
	}
	c.ProxyAllowed = []string{"1.1.1.1"}
	c.ProxySkipped = []string{"2.2.2.2", "10.8.0.0/24"}
	err = Initialize(c, 0)
	assert.NoError(t, err)
	assert.Len(t, Config.proxyAllowed, 1)
	assert.Len(t, Config.proxySkipped, 2)

	Config = configCopy
	assert.Equal(t, 0, Config.ProxyProtocol)
	assert.Len(t, Config.proxyAllowed, 0)
	assert.Len(t, Config.proxySkipped, 0)
}

func TestInitializationClosedProvider(t *testing.T) {
	configCopy := Config

	providerConf := dataprovider.GetProviderConfig()
	err := dataprovider.Close()
	assert.NoError(t, err)

	config := Configuration{
		AllowListStatus: 1,
	}
	err = Initialize(config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to initialize the allow list")
	}

	config.AllowListStatus = 0
	config.RateLimitersConfig = []RateLimiterConfig{
		{
			Average:   100,
			Period:    1000,
			Burst:     5,
			Type:      int(rateLimiterTypeGlobal),
			Protocols: rateLimiterProtocolValues,
		},
	}
	err = Initialize(config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to initialize ratelimiters list")
	}

	config.RateLimitersConfig = nil
	config.DefenderConfig = DefenderConfig{
		Enabled:          true,
		Driver:           DefenderDriverProvider,
		BanTime:          10,
		BanTimeIncrement: 50,
		Threshold:        10,
		ScoreInvalid:     2,
		ScoreValid:       1,
		ScoreNoAuth:      2,
		ObservationTime:  15,
		EntriesSoftLimit: 100,
		EntriesHardLimit: 150,
	}
	err = Initialize(config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "defender initialization error")
	}
	config.DefenderConfig.Driver = DefenderDriverMemory
	err = Initialize(config, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "defender initialization error")
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	Config = configCopy
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
	_, ok := Connections.sshMapping[sshConn1.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.sshMapping[sshConn1.GetID()])
	assert.Equal(t, 1, Connections.sshMapping[sshConn2.GetID()])
	assert.Equal(t, 2, Connections.sshMapping[sshConn3.GetID()])
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn1.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	assert.Equal(t, sshConn2.id, Connections.sshConnections[1].id)
	_, ok = Connections.sshMapping[sshConn3.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.sshMapping[sshConn3.GetID()])
	assert.Equal(t, 1, Connections.sshMapping[sshConn2.GetID()])
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn1.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	assert.Equal(t, sshConn2.id, Connections.sshConnections[1].id)
	_, ok = Connections.sshMapping[sshConn3.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.sshMapping[sshConn3.GetID()])
	assert.Equal(t, 1, Connections.sshMapping[sshConn2.GetID()])
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn2.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 1)
	assert.Equal(t, sshConn3.id, Connections.sshConnections[0].id)
	_, ok = Connections.sshMapping[sshConn3.GetID()]
	assert.True(t, ok)
	assert.Equal(t, 0, Connections.sshMapping[sshConn3.GetID()])
	Connections.RUnlock()
	Connections.RemoveSSHConnection(sshConn3.id)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 0)
	assert.Len(t, Connections.sshMapping, 0)
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
			Cmd:      filepath.Join(wdPath, "..", "..", "tests", "ipfilter", "ipfilter"),
			AutoMTLS: true,
		},
	}
	if runtime.GOOS == osWindows {
		pluginsConfig[0].Cmd += ".exe"
	}
	err = plugin.Initialize(pluginsConfig, "debug")
	require.NoError(t, err)

	ip := "127.1.1.1"

	assert.Nil(t, Reload())
	// 192.168.1.12 is banned from the ipfilter plugin
	assert.True(t, IsBanned("192.168.1.12", ProtocolFTP))

	AddDefenderEvent(ip, ProtocolFTP, HostEventNoLoginTried)
	assert.False(t, IsBanned(ip, ProtocolFTP))

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
		ScoreNoAuth:      2,
		ObservationTime:  15,
		EntriesSoftLimit: 100,
		EntriesHardLimit: 150,
		LoginDelay: LoginDelay{
			PasswordFailed: 200,
		},
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

	err = Initialize(Config, 0)
	assert.NoError(t, err)
	assert.Nil(t, Reload())

	AddDefenderEvent(ip, ProtocolSSH, HostEventNoLoginTried)
	assert.False(t, IsBanned(ip, ProtocolSSH))
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

	AddDefenderEvent(ip, ProtocolHTTP, HostEventLoginFailed)
	AddDefenderEvent(ip, ProtocolHTTP, HostEventNoLoginTried)
	assert.True(t, IsBanned(ip, ProtocolHTTP))
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

	startTime := time.Now()
	DelayLogin(nil)
	elapsed := time.Since(startTime)
	assert.Less(t, elapsed, time.Millisecond*50)

	startTime = time.Now()
	DelayLogin(ErrInternalFailure)
	elapsed = time.Since(startTime)
	assert.Greater(t, elapsed, time.Millisecond*150)

	Config = configCopy
}

func TestRateLimitersIntegration(t *testing.T) {
	configCopy := Config

	enabled, protocols := Config.GetRateLimitersStatus()
	assert.False(t, enabled)
	assert.Len(t, protocols, 0)

	entries := []dataprovider.IPListEntry{
		{
			IPOrNet: "172.16.24.7/32",
			Type:    dataprovider.IPListTypeRateLimiterSafeList,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "172.16.0.0/16",
			Type:    dataprovider.IPListTypeRateLimiterSafeList,
			Mode:    dataprovider.ListModeAllow,
		},
	}

	for idx := range entries {
		e := entries[idx]
		err := dataprovider.AddIPListEntry(&e, "", "", "")
		assert.NoError(t, err)
	}

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

	err = Initialize(Config, 0)
	assert.NoError(t, err)
	assert.NotNil(t, Config.rateLimitersList)

	assert.Len(t, rateLimiters, 4)
	assert.Len(t, rateLimiters[ProtocolSSH], 1)
	assert.Len(t, rateLimiters[ProtocolFTP], 2)
	assert.Len(t, rateLimiters[ProtocolWebDAV], 2)
	assert.Len(t, rateLimiters[ProtocolHTTP], 1)

	enabled, protocols = Config.GetRateLimitersStatus()
	assert.True(t, enabled)
	assert.Len(t, protocols, 4)
	assert.Contains(t, protocols, ProtocolFTP)
	assert.Contains(t, protocols, ProtocolSSH)
	assert.Contains(t, protocols, ProtocolHTTP)
	assert.Contains(t, protocols, ProtocolWebDAV)

	source1 := "127.1.1.1"
	source2 := "127.1.1.2"
	source3 := "172.16.24.7" // in safelist

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
	for _, e := range entries {
		err := dataprovider.DeleteIPListEntry(e.IPOrNet, e.Type, "", "", "")
		assert.NoError(t, err)
	}

	assert.Nil(t, configCopy.rateLimitersList)
	Config = configCopy
}

func TestUserMaxSessions(t *testing.T) {
	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    userTestUsername,
			MaxSessions: 1,
		},
	})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Add(fakeConn)
	assert.NoError(t, err)
	err = Connections.Add(fakeConn)
	assert.Error(t, err)
	err = Connections.Swap(fakeConn)
	assert.NoError(t, err)
	Connections.Remove(fakeConn.GetID())
	Connections.Lock()
	Connections.removeUserConnection(userTestUsername)
	Connections.Unlock()
	assert.Len(t, Connections.GetStats(""), 0)
}

func TestMaxConnections(t *testing.T) {
	oldValue := Config.MaxTotalConnections
	perHost := Config.MaxPerHostConnections

	Config.MaxPerHostConnections = 0

	ipAddr := "192.168.7.8"
	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolFTP))
	assert.NoError(t, Connections.IsNewTransferAllowed(userTestUsername))

	Config.MaxTotalConnections = 1
	Config.MaxPerHostConnections = perHost

	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolHTTP))
	assert.NoError(t, Connections.IsNewTransferAllowed(userTestUsername))
	isShuttingDown.Store(true)
	assert.ErrorIs(t, Connections.IsNewTransferAllowed(userTestUsername), ErrShuttingDown)
	isShuttingDown.Store(false)

	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Add(fakeConn)
	assert.NoError(t, err)
	assert.Len(t, Connections.GetStats(""), 1)
	assert.Error(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))
	Connections.transfers.add(userTestUsername)
	assert.Error(t, Connections.IsNewTransferAllowed(userTestUsername))
	Connections.transfers.remove(userTestUsername)
	assert.Equal(t, int32(0), Connections.GetTotalTransfers())

	res := Connections.Close(fakeConn.GetID(), "")
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats("")) == 0 }, 300*time.Millisecond, 50*time.Millisecond)

	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))
	Connections.AddClientConnection(ipAddr)
	Connections.AddClientConnection(ipAddr)
	assert.Error(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))
	Connections.RemoveClientConnection(ipAddr)
	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolWebDAV))
	Connections.transfers.add(userTestUsername)
	assert.Error(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))
	Connections.transfers.remove(userTestUsername)
	Connections.RemoveClientConnection(ipAddr)

	Config.MaxTotalConnections = oldValue
}

func TestConnectionRoles(t *testing.T) {
	username := "testUsername"
	role1 := "testRole1"
	role2 := "testRole2"
	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Role:     role1,
		},
	})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Add(fakeConn)
	assert.NoError(t, err)
	assert.Len(t, Connections.GetStats(""), 1)
	assert.Len(t, Connections.GetStats(role1), 1)
	assert.Len(t, Connections.GetStats(role2), 0)

	res := Connections.Close(fakeConn.GetID(), role2)
	assert.False(t, res)
	assert.Len(t, Connections.GetStats(""), 1)
	res = Connections.Close(fakeConn.GetID(), role1)
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats("")) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
}

func TestMaxConnectionPerHost(t *testing.T) {
	defender, err := newInMemoryDefender(&DefenderConfig{
		Enabled:            true,
		Driver:             DefenderDriverMemory,
		BanTime:            30,
		BanTimeIncrement:   50,
		Threshold:          15,
		ScoreInvalid:       2,
		ScoreValid:         1,
		ScoreLimitExceeded: 3,
		ObservationTime:    30,
		EntriesSoftLimit:   100,
		EntriesHardLimit:   150,
	})
	require.NoError(t, err)

	oldMaxPerHostConn := Config.MaxPerHostConnections
	oldDefender := Config.defender

	Config.MaxPerHostConnections = 2
	Config.defender = defender

	ipAddr := "192.168.9.9"
	Connections.AddClientConnection(ipAddr)
	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))

	Connections.AddClientConnection(ipAddr)
	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolWebDAV))

	Connections.AddClientConnection(ipAddr)
	assert.Error(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolFTP))
	assert.Equal(t, int32(3), Connections.GetClientConnections())
	// Add the IP to the defender safe list
	entry := dataprovider.IPListEntry{
		IPOrNet: ipAddr,
		Type:    dataprovider.IPListTypeDefender,
		Mode:    dataprovider.ListModeAllow,
	}
	err = dataprovider.AddIPListEntry(&entry, "", "", "")
	assert.NoError(t, err)

	Connections.AddClientConnection(ipAddr)
	assert.NoError(t, Connections.IsNewConnectionAllowed(ipAddr, ProtocolSSH))

	err = dataprovider.DeleteIPListEntry(entry.IPOrNet, dataprovider.IPListTypeDefender, "", "", "")
	assert.NoError(t, err)

	Connections.RemoveClientConnection(ipAddr)
	Connections.RemoveClientConnection(ipAddr)
	Connections.RemoveClientConnection(ipAddr)
	Connections.RemoveClientConnection(ipAddr)

	assert.Equal(t, int32(0), Connections.GetClientConnections())

	Config.MaxPerHostConnections = oldMaxPerHostConn
	Config.defender = oldDefender
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
			Status:   1,
		},
	}
	c := NewBaseConnection(sshConn1.id+"_1", ProtocolSFTP, "", "", user)
	c.lastActivity.Store(time.Now().Add(-24 * time.Hour).UnixNano())
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	// both ssh connections are expired but they should get removed only
	// if there is no associated connection
	sshConn1.lastActivity.Store(c.lastActivity.Load())
	sshConn2.lastActivity.Store(c.lastActivity.Load())
	Connections.AddSSHConnection(sshConn1)
	err = Connections.Add(fakeConn)
	assert.NoError(t, err)
	assert.Equal(t, Connections.GetActiveSessions(username), 1)
	c = NewBaseConnection(sshConn2.id+"_1", ProtocolSSH, "", "", user)
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	Connections.AddSSHConnection(sshConn2)
	err = Connections.Add(fakeConn)
	assert.NoError(t, err)
	assert.Equal(t, Connections.GetActiveSessions(username), 2)

	cFTP := NewBaseConnection("id2", ProtocolFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Status: 1,
		},
	})
	cFTP.lastActivity.Store(time.Now().UnixNano())
	fakeConn = &fakeConnection{
		BaseConnection: cFTP,
	}
	err = Connections.Add(fakeConn)
	assert.NoError(t, err)
	// the user is expired, this connection will be removed
	cDAV := NewBaseConnection("id3", ProtocolWebDAV, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       username + "_2",
			Status:         1,
			ExpirationDate: util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour)),
		},
	})
	cDAV.lastActivity.Store(time.Now().UnixNano())
	fakeConn = &fakeConnection{
		BaseConnection: cDAV,
	}
	err = Connections.Add(fakeConn)
	assert.NoError(t, err)

	assert.Equal(t, 2, Connections.GetActiveSessions(username))
	assert.Len(t, Connections.GetStats(""), 4)
	Connections.RLock()
	assert.Len(t, Connections.sshConnections, 2)
	Connections.RUnlock()

	startPeriodicChecks(100*time.Millisecond, 0)
	assert.Eventually(t, func() bool { return Connections.GetActiveSessions(username) == 1 }, 2*time.Second, 200*time.Millisecond)
	assert.Eventually(t, func() bool {
		Connections.RLock()
		defer Connections.RUnlock()
		return len(Connections.sshConnections) == 1
	}, 1*time.Second, 200*time.Millisecond)
	stopEventScheduler()
	assert.Len(t, Connections.GetStats(""), 2)
	c.lastActivity.Store(time.Now().Add(-24 * time.Hour).UnixNano())
	cFTP.lastActivity.Store(time.Now().Add(-24 * time.Hour).UnixNano())
	sshConn2.lastActivity.Store(c.lastActivity.Load())
	startPeriodicChecks(100*time.Millisecond, 1)
	assert.Eventually(t, func() bool { return len(Connections.GetStats("")) == 0 }, 2*time.Second, 200*time.Millisecond)
	assert.Eventually(t, func() bool {
		Connections.RLock()
		defer Connections.RUnlock()
		return len(Connections.sshConnections) == 0
	}, 1*time.Second, 200*time.Millisecond)
	assert.Equal(t, int32(0), Connections.GetClientConnections())
	stopEventScheduler()
	assert.True(t, customConn1.isClosed)
	assert.True(t, customConn2.isClosed)

	Config = configCopy
}

func TestCloseConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	assert.NoError(t, Connections.IsNewConnectionAllowed("127.0.0.1", ProtocolHTTP))
	err := Connections.Add(fakeConn)
	assert.NoError(t, err)
	assert.Len(t, Connections.GetStats(""), 1)
	res := Connections.Close(fakeConn.GetID(), "")
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats("")) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
	res = Connections.Close(fakeConn.GetID(), "")
	assert.False(t, res)
	Connections.Remove(fakeConn.GetID())
}

func TestSwapConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolFTP, "", "", dataprovider.User{})
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Add(fakeConn)
	assert.NoError(t, err)
	if assert.Len(t, Connections.GetStats(""), 1) {
		assert.Equal(t, "", Connections.GetStats("")[0].Username)
	}
	c = NewBaseConnection("id", ProtocolFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    userTestUsername,
			MaxSessions: 1,
		},
	})
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	c1 := NewBaseConnection("id1", ProtocolFTP, "", "", dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: userTestUsername,
		},
	})
	fakeConn1 := &fakeConnection{
		BaseConnection: c1,
	}
	err = Connections.Add(fakeConn1)
	assert.NoError(t, err)
	err = Connections.Swap(fakeConn)
	assert.Error(t, err)
	Connections.Remove(fakeConn1.ID)
	err = Connections.Swap(fakeConn)
	assert.NoError(t, err)
	if assert.Len(t, Connections.GetStats(""), 1) {
		assert.Equal(t, userTestUsername, Connections.GetStats("")[0].Username)
	}
	res := Connections.Close(fakeConn.GetID(), "")
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats("")) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
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
	fs := vfs.NewOsFs("", os.TempDir(), "", nil)
	c1 := NewBaseConnection("id1", ProtocolSFTP, "", "", user)
	fakeConn1 := &fakeConnection{
		BaseConnection: c1,
	}
	t1 := NewBaseTransfer(nil, c1, nil, "/p1", "/p1", "/r1", TransferUpload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	t1.BytesReceived.Store(123)
	t2 := NewBaseTransfer(nil, c1, nil, "/p2", "/p2", "/r2", TransferDownload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	t2.BytesSent.Store(456)
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
	err := Connections.Add(fakeConn1)
	assert.NoError(t, err)
	err = Connections.Add(fakeConn2)
	assert.NoError(t, err)
	err = Connections.Add(fakeConn3)
	assert.NoError(t, err)

	stats := Connections.GetStats("")
	assert.Len(t, stats, 3)
	for _, stat := range stats {
		assert.Equal(t, stat.Username, username)
		switch stat.ConnectionID {
		case "SFTP_id1":
			assert.Len(t, stat.Transfers, 2)
		case "DAV_id3":
			assert.Len(t, stat.Transfers, 1)
		}
	}

	err = t1.Close()
	assert.NoError(t, err)
	err = t2.Close()
	assert.NoError(t, err)

	err = fakeConn3.SignalTransfersAbort()
	assert.NoError(t, err)
	assert.True(t, t3.AbortTransfer.Load())
	err = t3.Close()
	assert.NoError(t, err)
	err = fakeConn3.SignalTransfersAbort()
	assert.Error(t, err)

	Connections.Remove(fakeConn1.GetID())
	stats = Connections.GetStats("")
	assert.Len(t, stats, 2)
	assert.Equal(t, fakeConn3.GetID(), stats[0].ConnectionID)
	assert.Equal(t, fakeConn2.GetID(), stats[1].ConnectionID)
	Connections.Remove(fakeConn2.GetID())
	stats = Connections.GetStats("")
	assert.Len(t, stats, 1)
	assert.Equal(t, fakeConn3.GetID(), stats[0].ConnectionID)
	Connections.Remove(fakeConn3.GetID())
	stats = Connections.GetStats("")
	assert.Len(t, stats, 0)
}

func TestQuotaScans(t *testing.T) {
	username := "username"
	assert.True(t, QuotaScans.AddUserQuotaScan(username, ""))
	assert.False(t, QuotaScans.AddUserQuotaScan(username, ""))
	usersScans := QuotaScans.GetUsersQuotaScans("")
	if assert.Len(t, usersScans, 1) {
		assert.Equal(t, usersScans[0].Username, username)
		assert.Equal(t, QuotaScans.UserScans[0].StartTime, usersScans[0].StartTime)
		QuotaScans.UserScans[0].StartTime = 0
		assert.NotEqual(t, QuotaScans.UserScans[0].StartTime, usersScans[0].StartTime)
	}

	assert.True(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.False(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.Len(t, QuotaScans.GetUsersQuotaScans(""), 0)
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

func TestQuotaScansRole(t *testing.T) {
	username := "u"
	role1 := "r1"
	role2 := "r2"
	assert.True(t, QuotaScans.AddUserQuotaScan(username, role1))
	assert.False(t, QuotaScans.AddUserQuotaScan(username, ""))
	usersScans := QuotaScans.GetUsersQuotaScans("")
	assert.Len(t, usersScans, 1)
	assert.Empty(t, usersScans[0].Role)
	usersScans = QuotaScans.GetUsersQuotaScans(role1)
	assert.Len(t, usersScans, 1)
	usersScans = QuotaScans.GetUsersQuotaScans(role2)
	assert.Len(t, usersScans, 0)
	assert.True(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.False(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.Len(t, QuotaScans.GetUsersQuotaScans(""), 0)
}

func TestProxyPolicy(t *testing.T) {
	addr := net.TCPAddr{}
	downstream := net.TCPAddr{IP: net.ParseIP("1.1.1.1")}
	p := getProxyPolicy(nil, nil, proxyproto.IGNORE)
	policy, err := p(proxyproto.ConnPolicyOptions{
		Upstream:   &addr,
		Downstream: &downstream,
	})
	assert.ErrorIs(t, err, proxyproto.ErrInvalidUpstream)
	assert.Equal(t, proxyproto.REJECT, policy)
	ip1 := net.ParseIP("10.8.1.1")
	ip2 := net.ParseIP("10.8.1.2")
	ip3 := net.ParseIP("10.8.1.3")
	allowed, err := util.ParseAllowedIPAndRanges([]string{ip1.String()})
	assert.NoError(t, err)
	skipped, err := util.ParseAllowedIPAndRanges([]string{ip2.String(), ip3.String()})
	assert.NoError(t, err)
	p = getProxyPolicy(allowed, skipped, proxyproto.IGNORE)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip1},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.USE, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip2},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.SKIP, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip3},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.SKIP, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: net.ParseIP("10.8.1.4")},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.IGNORE, policy)
	p = getProxyPolicy(allowed, skipped, proxyproto.REQUIRE)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip1},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.REQUIRE, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip2},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.SKIP, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: ip3},
		Downstream: &downstream,
	})
	assert.NoError(t, err)
	assert.Equal(t, proxyproto.SKIP, policy)
	policy, err = p(proxyproto.ConnPolicyOptions{
		Upstream:   &net.TCPAddr{IP: net.ParseIP("10.8.1.5")},
		Downstream: &downstream,
	})
	assert.ErrorIs(t, err, proxyproto.ErrInvalidUpstream)
	assert.Equal(t, proxyproto.REJECT, policy)
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
	listener, err := c.GetProxyListener(nil)
	assert.NoError(t, err)
	proxyListener, ok := listener.(*proxyproto.Listener)
	require.True(t, ok)
	assert.NotNil(t, proxyListener.ConnPolicy)

	c.ProxyProtocol = 2
	listener, err = c.GetProxyListener(nil)
	assert.NoError(t, err)
	proxyListener, ok = listener.(*proxyproto.Listener)
	require.True(t, ok)
	assert.NotNil(t, proxyListener.ConnPolicy)
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
	require.True(t, slices.Contains(folderCopy.Users, "user1"))
	require.True(t, slices.Contains(folderCopy.Users, "user2"))
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
	require.True(t, slices.Contains(folderCopy.Users, "user3"))
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

func TestHideConfidentialData(_ *testing.T) {
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

func TestVfsSameResource(t *testing.T) {
	fs := vfs.Filesystem{}
	other := vfs.Filesystem{}
	res := fs.IsSameResource(other)
	assert.True(t, res)
	fs = vfs.Filesystem{
		Provider: sdk.S3FilesystemProvider,
		S3Config: vfs.S3FsConfig{
			BaseS3FsConfig: sdk.BaseS3FsConfig{
				Bucket: "a",
				Region: "b",
			},
		},
	}
	other = vfs.Filesystem{
		Provider: sdk.S3FilesystemProvider,
		S3Config: vfs.S3FsConfig{
			BaseS3FsConfig: sdk.BaseS3FsConfig{
				Bucket: "a",
				Region: "c",
			},
		},
	}
	res = fs.IsSameResource(other)
	assert.False(t, res)
	other = vfs.Filesystem{
		Provider: sdk.S3FilesystemProvider,
		S3Config: vfs.S3FsConfig{
			BaseS3FsConfig: sdk.BaseS3FsConfig{
				Bucket: "a",
				Region: "b",
			},
		},
	}
	res = fs.IsSameResource(other)
	assert.True(t, res)
	fs = vfs.Filesystem{
		Provider: sdk.GCSFilesystemProvider,
		GCSConfig: vfs.GCSFsConfig{
			BaseGCSFsConfig: sdk.BaseGCSFsConfig{
				Bucket: "b",
			},
		},
	}
	other = vfs.Filesystem{
		Provider: sdk.GCSFilesystemProvider,
		GCSConfig: vfs.GCSFsConfig{
			BaseGCSFsConfig: sdk.BaseGCSFsConfig{
				Bucket: "c",
			},
		},
	}
	res = fs.IsSameResource(other)
	assert.False(t, res)
	other = vfs.Filesystem{
		Provider: sdk.GCSFilesystemProvider,
		GCSConfig: vfs.GCSFsConfig{
			BaseGCSFsConfig: sdk.BaseGCSFsConfig{
				Bucket: "b",
			},
		},
	}
	res = fs.IsSameResource(other)
	assert.True(t, res)
	sasURL := kms.NewPlainSecret("http://127.0.0.1/sasurl")
	fs = vfs.Filesystem{
		Provider: sdk.AzureBlobFilesystemProvider,
		AzBlobConfig: vfs.AzBlobFsConfig{
			BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
				AccountName: "a",
			},
			SASURL: sasURL,
		},
	}
	err := fs.Validate("data1")
	assert.NoError(t, err)
	other = vfs.Filesystem{
		Provider: sdk.AzureBlobFilesystemProvider,
		AzBlobConfig: vfs.AzBlobFsConfig{
			BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
				AccountName: "a",
			},
			SASURL: sasURL,
		},
	}
	err = other.Validate("data2")
	assert.NoError(t, err)
	err = fs.AzBlobConfig.SASURL.TryDecrypt()
	assert.NoError(t, err)
	err = other.AzBlobConfig.SASURL.TryDecrypt()
	assert.NoError(t, err)
	res = fs.IsSameResource(other)
	assert.True(t, res)
	fs.AzBlobConfig.AccountName = "b"
	res = fs.IsSameResource(other)
	assert.False(t, res)
	fs.AzBlobConfig.AccountName = "a"
	other.AzBlobConfig.SASURL = kms.NewPlainSecret("http://127.1.1.1/sasurl")
	err = other.Validate("data2")
	assert.NoError(t, err)
	err = other.AzBlobConfig.SASURL.TryDecrypt()
	assert.NoError(t, err)
	res = fs.IsSameResource(other)
	assert.False(t, res)
	fs = vfs.Filesystem{
		Provider: sdk.HTTPFilesystemProvider,
		HTTPConfig: vfs.HTTPFsConfig{
			BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
				Endpoint: "http://127.0.0.1/httpfs",
				Username: "a",
			},
		},
	}
	other = vfs.Filesystem{
		Provider: sdk.HTTPFilesystemProvider,
		HTTPConfig: vfs.HTTPFsConfig{
			BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
				Endpoint: "http://127.0.0.1/httpfs",
				Username: "b",
			},
		},
	}
	res = fs.IsSameResource(other)
	assert.True(t, res)
	fs.HTTPConfig.EqualityCheckMode = 1
	res = fs.IsSameResource(other)
	assert.False(t, res)
}

func TestUpdateTransferTimestamps(t *testing.T) {
	username := "user_test_timestamps"
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	err := dataprovider.AddUser(user, "", "", "")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), user.FirstUpload)
	assert.Equal(t, int64(0), user.FirstDownload)

	err = dataprovider.UpdateUserTransferTimestamps(username, true)
	assert.NoError(t, err)
	userGet, err := dataprovider.UserExists(username, "")
	assert.NoError(t, err)
	assert.Greater(t, userGet.FirstUpload, int64(0))
	assert.Equal(t, int64(0), user.FirstDownload)
	err = dataprovider.UpdateUserTransferTimestamps(username, false)
	assert.NoError(t, err)
	userGet, err = dataprovider.UserExists(username, "")
	assert.NoError(t, err)
	assert.Greater(t, userGet.FirstUpload, int64(0))
	assert.Greater(t, userGet.FirstDownload, int64(0))
	// updating again must fail
	err = dataprovider.UpdateUserTransferTimestamps(username, true)
	assert.Error(t, err)
	err = dataprovider.UpdateUserTransferTimestamps(username, false)
	assert.Error(t, err)
	// cleanup
	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
}

func TestIPList(t *testing.T) {
	type test struct {
		ip            string
		protocol      string
		expectedMatch bool
		expectedMode  int
		expectedErr   bool
	}

	entries := []dataprovider.IPListEntry{
		{
			IPOrNet: "192.168.0.0/25",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet:   "192.168.0.128/25",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeDeny,
			Protocols: 3,
		},
		{
			IPOrNet:   "192.168.2.128/32",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeAllow,
			Protocols: 5,
		},
		{
			IPOrNet:   "::/0",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeDeny,
			Protocols: 4,
		},
		{
			IPOrNet:   "2001:4860:4860::8888/120",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeDeny,
			Protocols: 1,
		},
		{
			IPOrNet:   "2001:4860:4860::8988/120",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeAllow,
			Protocols: 3,
		},
		{
			IPOrNet:   "::1/128",
			Type:      dataprovider.IPListTypeDefender,
			Mode:      dataprovider.ListModeAllow,
			Protocols: 0,
		},
	}
	ipList, err := dataprovider.NewIPList(dataprovider.IPListTypeDefender)
	require.NoError(t, err)
	for idx := range entries {
		e := entries[idx]
		err := dataprovider.AddIPListEntry(&e, "", "", "")
		assert.NoError(t, err)
	}
	tests := []test{
		{ip: "1.1.1.1", protocol: ProtocolSSH, expectedMatch: false, expectedMode: 0, expectedErr: false},
		{ip: "invalid ip", protocol: ProtocolSSH, expectedMatch: false, expectedMode: 0, expectedErr: true},
		{ip: "192.168.0.1", protocol: ProtocolFTP, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "192.168.0.2", protocol: ProtocolHTTP, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "192.168.0.3", protocol: ProtocolWebDAV, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "192.168.0.4", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "192.168.0.156", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeDeny, expectedErr: false},
		{ip: "192.168.0.158", protocol: ProtocolFTP, expectedMatch: true, expectedMode: dataprovider.ListModeDeny, expectedErr: false},
		{ip: "192.168.0.158", protocol: ProtocolHTTP, expectedMatch: false, expectedMode: 0, expectedErr: false},
		{ip: "192.168.2.128", protocol: ProtocolHTTP, expectedMatch: false, expectedMode: 0, expectedErr: false},
		{ip: "192.168.2.128", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "::2", protocol: ProtocolSSH, expectedMatch: false, expectedMode: 0, expectedErr: false},
		{ip: "::2", protocol: ProtocolWebDAV, expectedMatch: true, expectedMode: dataprovider.ListModeDeny, expectedErr: false},
		{ip: "::1", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "::1", protocol: ProtocolHTTP, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "2001:4860:4860:0000:0000:0000:0000:8889", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeDeny, expectedErr: false},
		{ip: "2001:4860:4860:0000:0000:0000:0000:8889", protocol: ProtocolFTP, expectedMatch: false, expectedMode: 0, expectedErr: false},
		{ip: "2001:4860:4860:0000:0000:0000:0000:8989", protocol: ProtocolFTP, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "2001:4860:4860:0000:0000:0000:0000:89F1", protocol: ProtocolSSH, expectedMatch: true, expectedMode: dataprovider.ListModeAllow, expectedErr: false},
		{ip: "2001:4860:4860:0000:0000:0000:0000:89F1", protocol: ProtocolHTTP, expectedMatch: false, expectedMode: 0, expectedErr: false},
	}

	for _, tc := range tests {
		match, mode, err := ipList.IsListed(tc.ip, tc.protocol)
		if tc.expectedErr {
			assert.Error(t, err, "ip %s, protocol %s", tc.ip, tc.protocol)
		} else {
			assert.NoError(t, err, "ip %s, protocol %s", tc.ip, tc.protocol)
		}
		assert.Equal(t, tc.expectedMatch, match, "ip %s, protocol %s", tc.ip, tc.protocol)
		assert.Equal(t, tc.expectedMode, mode, "ip %s, protocol %s", tc.ip, tc.protocol)
	}

	ipList.DisableMemoryMode()

	for _, tc := range tests {
		match, mode, err := ipList.IsListed(tc.ip, tc.protocol)
		if tc.expectedErr {
			assert.Error(t, err, "ip %s, protocol %s", tc.ip, tc.protocol)
		} else {
			assert.NoError(t, err, "ip %s, protocol %s", tc.ip, tc.protocol)
		}
		assert.Equal(t, tc.expectedMatch, match, "ip %s, protocol %s", tc.ip, tc.protocol)
		assert.Equal(t, tc.expectedMode, mode, "ip %s, protocol %s", tc.ip, tc.protocol)
	}

	for _, e := range entries {
		err := dataprovider.DeleteIPListEntry(e.IPOrNet, e.Type, "", "", "")
		assert.NoError(t, err)
	}
}

func TestSQLPlaceholderLimits(t *testing.T) {
	numGroups := 120
	numUsers := 120
	var groupMapping []sdk.GroupMapping

	folder := vfs.BaseVirtualFolder{
		Name:       "testfolder",
		MappedPath: filepath.Join(os.TempDir(), "folder"),
	}
	err := dataprovider.AddFolder(&folder, "", "", "")
	assert.NoError(t, err)

	for i := 0; i < numGroups; i++ {
		group := dataprovider.Group{
			BaseGroup: sdk.BaseGroup{
				Name: fmt.Sprintf("testgroup%d", i),
			},
			UserSettings: dataprovider.GroupUserSettings{
				BaseGroupUserSettings: sdk.BaseGroupUserSettings{
					Permissions: map[string][]string{
						fmt.Sprintf("/dir%d", i): {dataprovider.PermAny},
					},
				},
			},
		}
		group.VirtualFolders = append(group.VirtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: folder,
			VirtualPath:       "/vdir",
		})
		err := dataprovider.AddGroup(&group, "", "", "")
		assert.NoError(t, err)

		groupMapping = append(groupMapping, sdk.GroupMapping{
			Name: group.Name,
			Type: sdk.GroupTypeSecondary,
		})
	}

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "testusername",
			HomeDir:  filepath.Join(os.TempDir(), "testhome"),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		Groups: groupMapping,
	}
	err = dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)

	users, err := dataprovider.GetUsersForQuotaCheck(map[string]bool{user.Username: true})
	assert.NoError(t, err)
	if assert.Len(t, users, 1) {
		for i := 0; i < numGroups; i++ {
			_, ok := users[0].Permissions[fmt.Sprintf("/dir%d", i)]
			assert.True(t, ok)
		}
	}

	err = dataprovider.DeleteUser(user.Username, "", "", "")
	assert.NoError(t, err)

	for i := 0; i < numUsers; i++ {
		user := dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: fmt.Sprintf("testusername%d", i),
				HomeDir:  filepath.Join(os.TempDir()),
				Status:   1,
				Permissions: map[string][]string{
					"/": {dataprovider.PermAny},
				},
			},
			Groups: []sdk.GroupMapping{
				{
					Name: "testgroup0",
					Type: sdk.GroupTypePrimary,
				},
			},
		}
		err := dataprovider.AddUser(&user, "", "", "")
		assert.NoError(t, err)
	}

	time.Sleep(100 * time.Millisecond)

	err = dataprovider.DeleteFolder(folder.Name, "", "", "")
	assert.NoError(t, err)

	for i := 0; i < numUsers; i++ {
		username := fmt.Sprintf("testusername%d", i)
		user, err := dataprovider.UserExists(username, "")
		assert.NoError(t, err)
		assert.Greater(t, user.UpdatedAt, user.CreatedAt)
		err = dataprovider.DeleteUser(username, "", "", "")
		assert.NoError(t, err)
	}

	for i := 0; i < numGroups; i++ {
		groupName := fmt.Sprintf("testgroup%d", i)
		err = dataprovider.DeleteGroup(groupName, "", "", "")
		assert.NoError(t, err)
	}
}

func TestALPNProtocols(t *testing.T) {
	protocols := util.GetALPNProtocols(nil)
	assert.Equal(t, []string{"http/1.1", "h2"}, protocols)
	protocols = util.GetALPNProtocols([]string{"invalid1", "invalid2"})
	assert.Equal(t, []string{"http/1.1", "h2"}, protocols)
	protocols = util.GetALPNProtocols([]string{"invalid1", "h2", "invalid2"})
	assert.Equal(t, []string{"h2"}, protocols)
	protocols = util.GetALPNProtocols([]string{"h2", "http/1.1"})
	assert.Equal(t, []string{"h2", "http/1.1"}, protocols)
}

func TestServerVersion(t *testing.T) {
	appName := "SFTPGo"
	version.SetConfig("")
	v := version.GetServerVersion("_", false)
	assert.Equal(t, fmt.Sprintf("%s_%s", appName, version.Get().Version), v)
	v = version.GetServerVersion("-", true)
	assert.Equal(t, fmt.Sprintf("%s-%s-", appName, version.Get().Version), v)
	version.SetConfig("short")
	v = version.GetServerVersion("_", false)
	assert.Equal(t, appName, v)
	v = version.GetServerVersion("_", true)
	assert.Equal(t, appName+"_", v)
	version.SetConfig("")
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

func BenchmarkAddRemoveConnections(b *testing.B) {
	var conns []ActiveConnection
	for i := 0; i < 100; i++ {
		conns = append(conns, &fakeConnection{
			BaseConnection: NewBaseConnection(fmt.Sprintf("id%d", i), ProtocolSFTP, "", "", dataprovider.User{
				BaseUser: sdk.BaseUser{
					Username: userTestUsername,
				},
			}),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range conns {
			if err := Connections.Add(c); err != nil {
				panic(err)
			}
		}
		var wg sync.WaitGroup
		for idx := len(conns) - 1; idx >= 0; idx-- {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				Connections.Remove(conns[index].GetID())
			}(idx)
		}
		wg.Wait()
	}
}

func BenchmarkAddRemoveSSHConnections(b *testing.B) {
	conn1, conn2 := net.Pipe()
	var conns []*SSHConnection
	for i := 0; i < 2000; i++ {
		conns = append(conns, NewSSHConnection(fmt.Sprintf("id%d", i), conn1))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range conns {
			Connections.AddSSHConnection(c)
		}
		for idx := len(conns) - 1; idx >= 0; idx-- {
			Connections.RemoveSSHConnection(conns[idx].GetID())
		}
	}
	conn1.Close()
	conn2.Close()
}
