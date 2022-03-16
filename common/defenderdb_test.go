package common

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/util"
)

func TestBasicDbDefender(t *testing.T) {
	if !isDbDefenderSupported() {
		t.Skip("this test is not supported with the current database provider")
	}
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
		EntriesHardLimit:   10,
		SafeListFile:       "slFile",
		BlockListFile:      "blFile",
	}
	_, err := newDBDefender(config)
	assert.Error(t, err)

	bl := HostListFile{
		IPAddresses:  []string{"172.16.1.1", "172.16.1.2"},
		CIDRNetworks: []string{"10.8.0.0/24"},
	}
	sl := HostListFile{
		IPAddresses:  []string{"172.16.1.3", "172.16.1.4"},
		CIDRNetworks: []string{"192.168.8.0/24"},
	}
	blFile := filepath.Join(os.TempDir(), "bl.json")
	slFile := filepath.Join(os.TempDir(), "sl.json")

	data, err := json.Marshal(bl)
	assert.NoError(t, err)
	err = os.WriteFile(blFile, data, os.ModePerm)
	assert.NoError(t, err)

	data, err = json.Marshal(sl)
	assert.NoError(t, err)
	err = os.WriteFile(slFile, data, os.ModePerm)
	assert.NoError(t, err)

	config.BlockListFile = blFile
	_, err = newDBDefender(config)
	assert.Error(t, err)
	config.SafeListFile = slFile
	d, err := newDBDefender(config)
	assert.NoError(t, err)
	defender := d.(*dbDefender)
	assert.True(t, defender.IsBanned("172.16.1.1"))
	assert.False(t, defender.IsBanned("172.16.1.10"))
	assert.False(t, defender.IsBanned("10.8.1.3"))
	assert.True(t, defender.IsBanned("10.8.0.4"))
	assert.False(t, defender.IsBanned("invalid ip"))
	hosts, err := defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)
	_, err = defender.GetHost("10.8.0.3")
	assert.Error(t, err)

	defender.AddEvent("172.16.1.4", HostEventLoginFailed)
	defender.AddEvent("192.168.8.4", HostEventUserNotFound)
	defender.AddEvent("172.16.1.3", HostEventLimitExceeded)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)
	assert.True(t, defender.getLastCleanup().IsZero())

	testIP := "123.45.67.89"
	defender.AddEvent(testIP, HostEventLoginFailed)
	lastCleanup := defender.getLastCleanup()
	assert.False(t, lastCleanup.IsZero())
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
	defender.AddEvent(testIP, HostEventLimitExceeded)
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
	defender.AddEvent(testIP, HostEventNoLoginTried)
	defender.AddEvent(testIP, HostEventNoLoginTried)
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
	// ban time should increase
	assert.True(t, defender.IsBanned(testIP))
	newBanTime, err := defender.GetBanTime(testIP)
	assert.NoError(t, err)
	assert.True(t, newBanTime.After(*banTime))

	assert.True(t, defender.DeleteHost(testIP))
	assert.False(t, defender.DeleteHost(testIP))
	// test cleanup
	testIP1 := "123.45.67.90"
	testIP2 := "123.45.67.91"
	testIP3 := "123.45.67.92"
	for i := 0; i < 3; i++ {
		defender.AddEvent(testIP, HostEventNoLoginTried)
		defender.AddEvent(testIP1, HostEventNoLoginTried)
		defender.AddEvent(testIP2, HostEventNoLoginTried)
	}
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 3)
	for _, host := range hosts {
		assert.Equal(t, 0, host.Score)
		assert.False(t, host.BanTime.IsZero())
		assert.NotEmpty(t, host.GetBanTime())
	}
	defender.AddEvent(testIP3, HostEventLoginFailed)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 4)
	// now set a ban time in the past, so the host will be cleanead up
	for _, ip := range []string{testIP1, testIP2} {
		err = dataprovider.SetDefenderBanTime(ip, util.GetTimeAsMsSinceEpoch(time.Now().Add(-1*time.Minute)))
		assert.NoError(t, err)
	}
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 4)
	for _, host := range hosts {
		switch host.IP {
		case testIP:
			assert.Equal(t, 0, host.Score)
			assert.False(t, host.BanTime.IsZero())
			assert.NotEmpty(t, host.GetBanTime())
		case testIP3:
			assert.Equal(t, 1, host.Score)
			assert.True(t, host.BanTime.IsZero())
			assert.Empty(t, host.GetBanTime())
		default:
			assert.Equal(t, 6, host.Score)
			assert.True(t, host.BanTime.IsZero())
			assert.Empty(t, host.GetBanTime())
		}
	}
	host, err = defender.GetHost(testIP)
	assert.NoError(t, err)
	assert.Equal(t, 0, host.Score)
	assert.False(t, host.BanTime.IsZero())
	assert.NotEmpty(t, host.GetBanTime())
	host, err = defender.GetHost(testIP3)
	assert.NoError(t, err)
	assert.Equal(t, 1, host.Score)
	assert.True(t, host.BanTime.IsZero())
	assert.Empty(t, host.GetBanTime())
	// set a negative observation time so the from field in the queries will be in the future
	// we still should get the banned hosts
	defender.config.ObservationTime = -2
	assert.Greater(t, defender.getStartObservationTime(), time.Now().UnixMilli())
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		assert.Equal(t, testIP, hosts[0].IP)
		assert.Equal(t, 0, hosts[0].Score)
		assert.False(t, hosts[0].BanTime.IsZero())
		assert.NotEmpty(t, hosts[0].GetBanTime())
	}
	_, err = defender.GetHost(testIP)
	assert.NoError(t, err)
	// cleanup db
	err = dataprovider.CleanupDefender(util.GetTimeAsMsSinceEpoch(time.Now().Add(10 * time.Minute)))
	assert.NoError(t, err)
	// the banned host must still be there
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		assert.Equal(t, testIP, hosts[0].IP)
		assert.Equal(t, 0, hosts[0].Score)
		assert.False(t, hosts[0].BanTime.IsZero())
		assert.NotEmpty(t, hosts[0].GetBanTime())
	}
	_, err = defender.GetHost(testIP)
	assert.NoError(t, err)
	err = dataprovider.SetDefenderBanTime(testIP, util.GetTimeAsMsSinceEpoch(time.Now().Add(-1*time.Minute)))
	assert.NoError(t, err)
	err = dataprovider.CleanupDefender(util.GetTimeAsMsSinceEpoch(time.Now().Add(10 * time.Minute)))
	assert.NoError(t, err)
	hosts, err = defender.GetHosts()
	assert.NoError(t, err)
	assert.Len(t, hosts, 0)

	err = os.Remove(slFile)
	assert.NoError(t, err)
	err = os.Remove(blFile)
	assert.NoError(t, err)
}

func TestDbDefenderCleanup(t *testing.T) {
	if !isDbDefenderSupported() {
		t.Skip("this test is not supported with the current database provider")
	}
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
		EntriesHardLimit:   10,
	}
	d, err := newDBDefender(config)
	assert.NoError(t, err)
	defender := d.(*dbDefender)
	lastCleanup := defender.getLastCleanup()
	assert.True(t, lastCleanup.IsZero())
	defender.cleanup()
	lastCleanup = defender.getLastCleanup()
	assert.False(t, lastCleanup.IsZero())
	defender.cleanup()
	assert.Equal(t, lastCleanup, defender.getLastCleanup())
	defender.setLastCleanup(time.Now().Add(-time.Duration(config.ObservationTime) * time.Minute * 4))
	time.Sleep(20 * time.Millisecond)
	defender.cleanup()
	assert.True(t, lastCleanup.Before(defender.getLastCleanup()))

	providerConf := dataprovider.GetProviderConfig()
	err = dataprovider.Close()
	assert.NoError(t, err)

	lastCleanup = time.Now().Add(-time.Duration(config.ObservationTime) * time.Minute * 4)
	defender.setLastCleanup(lastCleanup)
	defender.cleanup()
	// cleanup will fail and so last cleanup should be reset to the previous value
	assert.Equal(t, lastCleanup, defender.getLastCleanup())

	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func isDbDefenderSupported() bool {
	// SQLite shares the implementation with other SQL-based provider but it makes no sense
	// to use it outside test cases
	switch dataprovider.GetProviderStatus().Driver {
	case dataprovider.MySQLDataProviderName, dataprovider.PGSQLDataProviderName,
		dataprovider.CockroachDataProviderName, dataprovider.SQLiteDataProviderName:
		return true
	default:
		return false
	}
}
