package dataprovider

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	scheduler        *cron.Cron
	lastCachesUpdate int64
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
	if config.IsShared == 0 {
		return nil
	}
	if !util.IsStringInSlice(config.Driver, sharedProviders) {
		providerLog(logger.LevelError, "update caches not supported for provider %v", config.Driver)
		return nil
	}
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
