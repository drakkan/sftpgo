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
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yl2chen/cidranger"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
)

func TestBasicDefender(t *testing.T) {
	entries := []dataprovider.IPListEntry{
		{
			IPOrNet: "172.16.1.1/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "172.16.1.2/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "10.8.0.0/24",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "192.168.1.1/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "192.168.1.2/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "10.8.9.0/24",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeDeny,
		},
		{
			IPOrNet: "172.16.1.3/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "172.16.1.4/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "192.168.8.0/24",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "192.168.1.3/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "192.168.1.4/32",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
		{
			IPOrNet: "192.168.9.0/24",
			Type:    dataprovider.IPListTypeDefender,
			Mode:    dataprovider.ListModeAllow,
		},
	}

	for idx := range entries {
		e := entries[idx]
		err := dataprovider.AddIPListEntry(&e, "", "", "")
		assert.NoError(t, err)
	}

	config := &DefenderConfig{
		Enabled:            true,
		BanTime:            10,
		BanTimeIncrement:   2,
		Threshold:          5,
		ScoreInvalid:       2,
		ScoreValid:         1,
		ScoreNoAuth:        2,
		ScoreLimitExceeded: 3,
		ObservationTime:    15,
		EntriesSoftLimit:   1,
		EntriesHardLimit:   2,
	}

	d, err := newInMemoryDefender(config)
	assert.NoError(t, err)

	defender := d.(*memoryDefender)
	assert.True(t, defender.IsBanned("172.16.1.1", ProtocolSSH))
	assert.True(t, defender.IsBanned("192.168.1.1", ProtocolFTP))
	assert.False(t, defender.IsBanned("172.16.1.10", ProtocolSSH))
	assert.False(t, defender.IsBanned("192.168.1.10", ProtocolSSH))
	assert.False(t, defender.IsBanned("10.8.2.3", ProtocolSSH))
	assert.False(t, defender.IsBanned("10.9.2.3", ProtocolSSH))
	assert.True(t, defender.IsBanned("10.8.0.3", ProtocolSSH))
	assert.True(t, defender.IsBanned("10.8.9.3", ProtocolSSH))
	assert.False(t, defender.IsBanned("invalid ip", ProtocolSSH))
	assert.Equal(t, 0, defender.countBanned())
	assert.Equal(t, 0, defender.countHosts())
	hosts, err := defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)
	_, err = defender.GetHost("10.8.0.4")
	assert.Error(t, err)

	defender.AddEvent("172.16.1.4", ProtocolSSH, HostEventLoginFailed)
	defender.AddEvent("192.168.1.4", ProtocolSSH, HostEventLoginFailed)
	defender.AddEvent("192.168.8.4", ProtocolSSH, HostEventUserNotFound)
	defender.AddEvent("172.16.1.3", ProtocolSSH, HostEventLimitExceeded)
	defender.AddEvent("192.168.1.3", ProtocolSSH, HostEventLimitExceeded)
	assert.Equal(t, 0, defender.countHosts())

	testIP := "12.34.56.78"
	defender.AddEvent(testIP, ProtocolSSH, HostEventLoginFailed)
	assert.Equal(t, 1, defender.countHosts())
	assert.Equal(t, 0, defender.countBanned())
	score, err := defender.GetScore(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 1, score)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		assert.Equal(t, 1, hosts[0].Score)
		assert.True(t, hosts[0].BanTime.IsZero())
		assert.Empty(t, hosts[0].GetBanTime())
	}
	host, err := defender.GetHost(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 1, host.Score)
	assert.Empty(t, host.GetBanTime())
	banTime, err := defender.GetBanTime(testIP)
	assert.NoError(t, err)
	assert.Nil(t, banTime)
	defender.AddEvent(testIP, ProtocolSSH, HostEventLimitExceeded)
	assert.Equal(t, 1, defender.countHosts())
	assert.Equal(t, 0, defender.countBanned())
	score, err = defender.GetScore(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 4, score)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		assert.Equal(t, 4, hosts[0].Score)
		assert.True(t, hosts[0].BanTime.IsZero())
		assert.Empty(t, hosts[0].GetBanTime())
	}
	defender.AddEvent(testIP, ProtocolSSH, HostEventUserNotFound)
	defender.AddEvent(testIP, ProtocolSSH, HostEventNoLoginTried)
	assert.Equal(t, 0, defender.countHosts())
	assert.Equal(t, 1, defender.countBanned())
	score, err = defender.GetScore(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
	banTime, err = defender.GetBanTime(testIP)
	assert.NoError(t, err)
	assert.NotNil(t, banTime)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		assert.Equal(t, 0, hosts[0].Score)
		assert.False(t, hosts[0].BanTime.IsZero())
		assert.NotEmpty(t, hosts[0].GetBanTime())
		assert.Equal(t, hex.EncodeToString([]byte(testIP)), hosts[0].GetID())
	}
	host, err = defender.GetHost(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 0, host.Score)
	assert.NotEmpty(t, host.GetBanTime())

	// now test cleanup, testIP is already banned
	testIP1 := "12.34.56.79"
	testIP2 := "12.34.56.80"
	testIP3 := "12.34.56.81"

	defender.AddEvent(testIP1, ProtocolSSH, HostEventNoLoginTried)
	defender.AddEvent(testIP2, ProtocolSSH, HostEventNoLoginTried)
	assert.Equal(t, 2, defender.countHosts())
	time.Sleep(20 * time.Millisecond)
	defender.AddEvent(testIP3, ProtocolSSH, HostEventNoLoginTried)
	assert.Equal(t, defender.config.EntriesSoftLimit, defender.countHosts())
	// testIP1 and testIP2 should be removed
	assert.Equal(t, defender.config.EntriesSoftLimit, defender.countHosts())
	score, err = defender.GetScore(testIP1)
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
	score, err = defender.GetScore(testIP2)
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
	score, err = defender.GetScore(testIP3)
	assert.NoError(t, err)
	assert.Equal(t, 2, score)

	defender.AddEvent(testIP3, ProtocolSSH, HostEventNoLoginTried)
	defender.AddEvent(testIP3, ProtocolSSH, HostEventNoLoginTried)
	// IP3 is now banned
	banTime, err = defender.GetBanTime(testIP3)
	assert.NoError(t, err)
	assert.NotNil(t, banTime)
	assert.Equal(t, 0, defender.countHosts())

	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		defender.AddEvent(testIP1, ProtocolSSH, HostEventNoLoginTried)
	}
	assert.Equal(t, 0, defender.countHosts())
	assert.Equal(t, config.EntriesSoftLimit, defender.countBanned())
	banTime, err = defender.GetBanTime(testIP)
	assert.NoError(t, err)
	assert.Nil(t, banTime)
	banTime, err = defender.GetBanTime(testIP3)
	assert.NoError(t, err)
	assert.Nil(t, banTime)
	banTime, err = defender.GetBanTime(testIP1)
	assert.NoError(t, err)
	assert.NotNil(t, banTime)

	for i := 0; i < 3; i++ {
		defender.AddEvent(testIP, ProtocolSSH, HostEventNoLoginTried)
		time.Sleep(10 * time.Millisecond)
		defender.AddEvent(testIP3, ProtocolSSH, HostEventNoLoginTried)
	}
	assert.Equal(t, 0, defender.countHosts())
	assert.Equal(t, defender.config.EntriesSoftLimit, defender.countBanned())

	banTime, err = defender.GetBanTime(testIP3)
	assert.NoError(t, err)
	if assert.NotNil(t, banTime) {
		assert.True(t, defender.IsBanned(testIP3, ProtocolFTP))
		// ban time should increase
		newBanTime, err := defender.GetBanTime(testIP3)
		assert.NoError(t, err)
		assert.True(t, newBanTime.After(*banTime))
	}

	assert.True(t, defender.DeleteHost(testIP3))
	assert.False(t, defender.DeleteHost(testIP3))

	for _, e := range entries {
		err := dataprovider.DeleteIPListEntry(e.IPOrNet, e.Type, "", "", "")
		assert.NoError(t, err)
	}
}

func TestExpiredHostBans(t *testing.T) {
	config := &DefenderConfig{
		Enabled:            true,
		BanTime:            10,
		BanTimeIncrement:   2,
		Threshold:          5,
		ScoreInvalid:       2,
		ScoreValid:         1,
		ScoreLimitExceeded: 3,
		ObservationTime:    15,
		EntriesSoftLimit:   1,
		EntriesHardLimit:   2,
	}

	d, err := newInMemoryDefender(config)
	assert.NoError(t, err)

	defender := d.(*memoryDefender)

	testIP := "1.2.3.4"
	defender.banned[testIP] = time.Now().Add(-24 * time.Hour)

	// the ban is expired testIP should not be listed
	res, err := defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, res, 0)

	assert.False(t, defender.IsBanned(testIP, ProtocolFTP))
	_, err = defender.GetHost(testIP)
	assert.Error(t, err)
	_, ok := defender.banned[testIP]
	assert.True(t, ok)
	// now add an event for an expired banned ip, it should be removed
	defender.AddEvent(testIP, ProtocolFTP, HostEventLoginFailed)
	assert.False(t, defender.IsBanned(testIP, ProtocolFTP))
	entry, err := defender.GetHost(testIP)
	assert.NoError(t, err)
	assert.Equal(t, testIP, entry.IP)
	assert.Empty(t, entry.GetBanTime())
	assert.Equal(t, 1, entry.Score)

	res, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, res, 1) {
		assert.Equal(t, testIP, res[0].IP)
		assert.Empty(t, res[0].GetBanTime())
		assert.Equal(t, 1, res[0].Score)
	}

	events := []hostEvent{
		{
			dateTime: time.Now().Add(-24 * time.Hour),
			score:    2,
		},
		{
			dateTime: time.Now().Add(-24 * time.Hour),
			score:    3,
		},
	}

	hs := hostScore{
		Events:     events,
		TotalScore: 5,
	}

	defender.hosts[testIP] = hs
	// the recorded scored are too old
	res, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, res, 0)
	_, err = defender.GetHost(testIP)
	assert.Error(t, err)
	_, ok = defender.hosts[testIP]
	assert.True(t, ok)
}

func TestDefenderCleanup(t *testing.T) {
	d := memoryDefender{
		baseDefender: baseDefender{
			config: &DefenderConfig{
				ObservationTime:  1,
				EntriesSoftLimit: 2,
				EntriesHardLimit: 3,
			},
		},
		banned: make(map[string]time.Time),
		hosts:  make(map[string]hostScore),
	}

	d.banned["1.1.1.1"] = time.Now().Add(-24 * time.Hour)
	d.banned["1.1.1.2"] = time.Now().Add(-24 * time.Hour)
	d.banned["1.1.1.3"] = time.Now().Add(-24 * time.Hour)
	d.banned["1.1.1.4"] = time.Now().Add(-24 * time.Hour)

	d.cleanupBanned()
	assert.Equal(t, 0, d.countBanned())

	d.banned["2.2.2.2"] = time.Now().Add(2 * time.Minute)
	d.banned["2.2.2.3"] = time.Now().Add(1 * time.Minute)
	d.banned["2.2.2.4"] = time.Now().Add(3 * time.Minute)
	d.banned["2.2.2.5"] = time.Now().Add(4 * time.Minute)

	d.cleanupBanned()
	assert.Equal(t, d.config.EntriesSoftLimit, d.countBanned())
	banTime, err := d.GetBanTime("2.2.2.3")
	assert.NoError(t, err)
	assert.Nil(t, banTime)

	d.hosts["3.3.3.3"] = hostScore{
		TotalScore: 0,
		Events: []hostEvent{
			{
				dateTime: time.Now().Add(-5 * time.Minute),
				score:    1,
			},
			{
				dateTime: time.Now().Add(-3 * time.Minute),
				score:    1,
			},
			{
				dateTime: time.Now(),
				score:    1,
			},
		},
	}
	d.hosts["3.3.3.4"] = hostScore{
		TotalScore: 1,
		Events: []hostEvent{
			{
				dateTime: time.Now().Add(-3 * time.Minute),
				score:    1,
			},
		},
	}
	d.hosts["3.3.3.5"] = hostScore{
		TotalScore: 1,
		Events: []hostEvent{
			{
				dateTime: time.Now().Add(-2 * time.Minute),
				score:    1,
			},
		},
	}
	d.hosts["3.3.3.6"] = hostScore{
		TotalScore: 1,
		Events: []hostEvent{
			{
				dateTime: time.Now().Add(-1 * time.Minute),
				score:    1,
			},
		},
	}

	score, err := d.GetScore("3.3.3.3")
	assert.NoError(t, err)
	assert.Equal(t, 1, score)

	d.cleanupHosts()
	assert.Equal(t, d.config.EntriesSoftLimit, d.countHosts())
	score, err = d.GetScore("3.3.3.4")
	assert.NoError(t, err)
	assert.Equal(t, 0, score)
}

func TestDefenderConfig(t *testing.T) {
	c := DefenderConfig{}
	err := c.validate()
	require.NoError(t, err)

	c.Enabled = true
	c.Threshold = 10
	c.ScoreInvalid = 10
	err = c.validate()
	require.Error(t, err)

	c.ScoreInvalid = 2
	c.ScoreLimitExceeded = 10
	err = c.validate()
	require.Error(t, err)

	c.ScoreLimitExceeded = 2
	c.ScoreValid = 10
	err = c.validate()
	require.Error(t, err)

	c.ScoreValid = 1
	c.ScoreNoAuth = 10
	err = c.validate()
	require.Error(t, err)

	c.ScoreNoAuth = 2
	c.BanTime = 0
	err = c.validate()
	require.Error(t, err)

	c.BanTime = 30
	c.BanTimeIncrement = 0
	err = c.validate()
	require.Error(t, err)

	c.BanTimeIncrement = 50
	c.ObservationTime = 0
	err = c.validate()
	require.Error(t, err)

	c.ObservationTime = 30
	err = c.validate()
	require.Error(t, err)

	c.EntriesSoftLimit = 10
	err = c.validate()
	require.Error(t, err)

	c.EntriesHardLimit = 10
	err = c.validate()
	require.Error(t, err)

	c.EntriesHardLimit = 20
	err = c.validate()
	require.NoError(t, err)

	c = DefenderConfig{
		Enabled:            true,
		ScoreInvalid:       -1,
		ScoreLimitExceeded: -1,
		ScoreNoAuth:        -1,
		ScoreValid:         -1,
	}
	err = c.validate()
	require.Error(t, err)
	assert.Equal(t, 0, c.ScoreInvalid)
	assert.Equal(t, 0, c.ScoreValid)
	assert.Equal(t, 0, c.ScoreLimitExceeded)
	assert.Equal(t, 0, c.ScoreNoAuth)
}

func BenchmarkDefenderBannedSearch(b *testing.B) {
	d := getDefenderForBench()

	ip, ipnet, err := net.ParseCIDR("10.8.0.0/12") // 1048574 ip addresses
	if err != nil {
		panic(err)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		d.banned[ip.String()] = time.Now().Add(10 * time.Minute)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		d.IsBanned("192.168.1.1", ProtocolSSH)
	}
}

func BenchmarkCleanup(b *testing.B) {
	d := getDefenderForBench()

	ip, ipnet, err := net.ParseCIDR("192.168.4.0/24")
	if err != nil {
		panic(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			d.AddEvent(ip.String(), ProtocolSSH, HostEventLoginFailed)
			if d.countHosts() > d.config.EntriesHardLimit {
				panic("too many hosts")
			}
			if d.countBanned() > d.config.EntriesSoftLimit {
				panic("too many ip banned")
			}
		}
	}
}

func BenchmarkCIDRanger(b *testing.B) {
	ranger := cidranger.NewPCTrieRanger()
	for i := 0; i < 255; i++ {
		cidr := fmt.Sprintf("192.168.%d.1/24", i)
		_, network, _ := net.ParseCIDR(cidr)
		if err := ranger.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			panic(err)
		}
	}

	ipToMatch := net.ParseIP("192.167.1.2")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ranger.Contains(ipToMatch); err != nil {
			panic(err)
		}
	}
}

func BenchmarkNetContains(b *testing.B) {
	var nets []*net.IPNet
	for i := 0; i < 255; i++ {
		cidr := fmt.Sprintf("192.168.%d.1/24", i)
		_, network, _ := net.ParseCIDR(cidr)
		nets = append(nets, network)
	}

	ipToMatch := net.ParseIP("192.167.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, n := range nets {
			n.Contains(ipToMatch)
		}
	}
}

func getDefenderForBench() *memoryDefender {
	config := &DefenderConfig{
		Enabled:          true,
		BanTime:          30,
		BanTimeIncrement: 50,
		Threshold:        10,
		ScoreInvalid:     2,
		ScoreValid:       2,
		ObservationTime:  30,
		EntriesSoftLimit: 50,
		EntriesHardLimit: 100,
	}
	return &memoryDefender{
		baseDefender: baseDefender{
			config: config,
		},
		hosts:  make(map[string]hostScore),
		banned: make(map[string]time.Time),
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
