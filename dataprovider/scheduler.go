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

package dataprovider

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	scheduler        *cron.Cron
	lastCachesUpdate int64
	// used for bolt and memory providers, so we avoid iterating all users
	// to find recently modified ones
	lastUserUpdate int64
)

func stopScheduler() {
	if scheduler != nil {
		scheduler.Stop()
		scheduler = nil
	}
}

func startScheduler() error {
	stopScheduler()

	scheduler = cron.New()
	_, err := scheduler.AddFunc("@every 30s", checkDataprovider)
	if err != nil {
		return fmt.Errorf("unable to schedule dataprovider availability check: %w", err)
	}

	if config.AutoBackup.Enabled {
		spec := fmt.Sprintf("0 %v * * %v", config.AutoBackup.Hour, config.AutoBackup.DayOfWeek)
		_, err = scheduler.AddFunc(spec, config.doBackup)
		if err != nil {
			return fmt.Errorf("unable to schedule auto backup: %w", err)
		}
	}

	err = addScheduledCacheUpdates()
	if err != nil {
		return err
	}
	scheduler.Start()
	return nil
}

func addScheduledCacheUpdates() error {
	lastCachesUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	_, err := scheduler.AddFunc("@every 10m", checkCacheUpdates)
	if err != nil {
		return fmt.Errorf("unable to schedule cache updates: %w", err)
	}
	return nil
}

func checkDataprovider() {
	err := provider.checkAvailability()
	if err != nil {
		providerLog(logger.LevelError, "check availability error: %v", err)
	}
	metric.UpdateDataProviderAvailability(err)
}

func checkCacheUpdates() {
	providerLog(logger.LevelDebug, "start caches check, update time %v", util.GetTimeFromMsecSinceEpoch(lastCachesUpdate))
	checkTime := util.GetTimeAsMsSinceEpoch(time.Now())
	users, err := provider.getRecentlyUpdatedUsers(lastCachesUpdate)
	if err != nil {
		providerLog(logger.LevelError, "unable to get recently updated users: %v", err)
		return
	}
	for _, user := range users {
		providerLog(logger.LevelDebug, "invalidate caches for user %#v", user.Username)
		webDAVUsersCache.swap(&user)
		cachedPasswords.Remove(user.Username)
	}

	lastCachesUpdate = checkTime
	providerLog(logger.LevelDebug, "end caches check, new update time %v", util.GetTimeFromMsecSinceEpoch(lastCachesUpdate))
}

func setLastUserUpdate() {
	atomic.StoreInt64(&lastUserUpdate, util.GetTimeAsMsSinceEpoch(time.Now()))
}

func getLastUserUpdate() int64 {
	return atomic.LoadInt64(&lastUserUpdate)
}
