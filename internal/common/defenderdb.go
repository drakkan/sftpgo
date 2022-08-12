// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package common

import (
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type dbDefender struct {
	baseDefender
	lastCleanup time.Time
}

func newDBDefender(config *DefenderConfig) (Defender, error) {
	err := config.validate()
	if err != nil {
		return nil, err
	}
	defender := &dbDefender{
		baseDefender: baseDefender{
			config: config,
		},
		lastCleanup: time.Time{},
	}

	if err := defender.Reload(); err != nil {
		return nil, err
	}

	return defender, nil
}

// GetHosts returns hosts that are banned or for which some violations have been detected
func (d *dbDefender) GetHosts() ([]dataprovider.DefenderEntry, error) {
	return dataprovider.GetDefenderHosts(d.getStartObservationTime(), d.config.EntriesHardLimit)
}

// GetHost returns a defender host by ip, if any
func (d *dbDefender) GetHost(ip string) (dataprovider.DefenderEntry, error) {
	return dataprovider.GetDefenderHostByIP(ip, d.getStartObservationTime())
}

// IsBanned returns true if the specified IP is banned
// and increase ban time if the IP is found.
// This method must be called as soon as the client connects
func (d *dbDefender) IsBanned(ip string) bool {
	d.RLock()
	if d.baseDefender.isBanned(ip) {
		d.RUnlock()
		return true
	}
	d.RUnlock()

	_, err := dataprovider.IsDefenderHostBanned(ip)
	if err != nil {
		// not found or another error, we allow this host
		return false
	}
	increment := d.config.BanTime * d.config.BanTimeIncrement / 100
	if increment == 0 {
		increment++
	}
	dataprovider.UpdateDefenderBanTime(ip, increment) //nolint:errcheck
	return true
}

// DeleteHost removes the specified IP from the defender lists
func (d *dbDefender) DeleteHost(ip string) bool {
	if _, err := d.GetHost(ip); err != nil {
		return false
	}
	return dataprovider.DeleteDefenderHost(ip) == nil
}

// AddEvent adds an event for the given IP.
// This method must be called for clients not yet banned
func (d *dbDefender) AddEvent(ip string, event HostEvent) {
	d.RLock()
	if d.safeList != nil && d.safeList.isListed(ip) {
		d.RUnlock()
		return
	}
	d.RUnlock()

	score := d.baseDefender.getScore(event)

	host, err := dataprovider.AddDefenderEvent(ip, score, d.getStartObservationTime())
	if err != nil {
		return
	}
	if host.Score > d.config.Threshold {
		banTime := time.Now().Add(time.Duration(d.config.BanTime) * time.Minute)
		err = dataprovider.SetDefenderBanTime(ip, util.GetTimeAsMsSinceEpoch(banTime))
		if err == nil {
			eventManager.handleIPBlockedEvent(EventParams{
				Event:     ipBlockedEventName,
				IP:        ip,
				Timestamp: time.Now().UnixNano(),
				Status:    1,
			})
		}
	}

	if err == nil {
		d.cleanup()
	}
}

// GetBanTime returns the ban time for the given IP or nil if the IP is not banned
func (d *dbDefender) GetBanTime(ip string) (*time.Time, error) {
	host, err := d.GetHost(ip)
	if err != nil {
		return nil, err
	}
	if host.BanTime.IsZero() {
		return nil, nil
	}
	return &host.BanTime, nil
}

// GetScore returns the score for the given IP
func (d *dbDefender) GetScore(ip string) (int, error) {
	host, err := d.GetHost(ip)
	if err != nil {
		return 0, err
	}
	return host.Score, nil
}

func (d *dbDefender) cleanup() {
	lastCleanup := d.getLastCleanup()
	if lastCleanup.IsZero() || lastCleanup.Add(time.Duration(d.config.ObservationTime)*time.Minute*3).Before(time.Now()) {
		// FIXME: this could be racy in rare cases but it is better than acquire the lock for the cleanup duration
		// or to always acquire a read/write lock.
		// Concurrent cleanups could happen anyway from multiple SFTPGo instances and should not cause any issues
		d.setLastCleanup(time.Now())
		expireTime := time.Now().Add(-time.Duration(d.config.ObservationTime+1) * time.Minute)
		logger.Debug(logSender, "", "cleanup defender hosts before %v, last cleanup %v", expireTime, lastCleanup)
		if err := dataprovider.CleanupDefender(util.GetTimeAsMsSinceEpoch(expireTime)); err != nil {
			logger.Error(logSender, "", "defender cleanup error, reset last cleanup to %v", lastCleanup)
			d.setLastCleanup(lastCleanup)
		}
	}
}

func (d *dbDefender) getStartObservationTime() int64 {
	t := time.Now().Add(-time.Duration(d.config.ObservationTime) * time.Minute)
	return util.GetTimeAsMsSinceEpoch(t)
}

func (d *dbDefender) getLastCleanup() time.Time {
	d.RLock()
	defer d.RUnlock()

	return d.lastCleanup
}

func (d *dbDefender) setLastCleanup(when time.Time) {
	d.Lock()
	defer d.Unlock()

	d.lastCleanup = when
}
