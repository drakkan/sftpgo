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
	scheduler           *cron.Cron
	lastUserCacheUpdate int64
	// used for bolt and memory providers, so we avoid iterating all users/rules
	// to find recently modified ones
	lastUserUpdate int64
	lastRuleUpdate int64
)

func stopScheduler() {
	if scheduler != nil {
		scheduler.Stop()
		scheduler = nil
	}
}

func startScheduler() error {
	stopScheduler()

	scheduler = cron.New(cron.WithLocation(time.UTC))
	_, err := scheduler.AddFunc("@every 60s", checkDataprovider)
	if err != nil {
		return fmt.Errorf("unable to schedule dataprovider availability check: %w", err)
	}
	err = addScheduledCacheUpdates()
	if err != nil {
		return err
	}
	EventManager.loadRules()
	scheduler.Start()
	return nil
}

func addScheduledCacheUpdates() error {
	lastUserCacheUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
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
	providerLog(logger.LevelDebug, "start caches check, update time %v", util.GetTimeFromMsecSinceEpoch(lastUserCacheUpdate))
	checkTime := util.GetTimeAsMsSinceEpoch(time.Now())
	users, err := provider.getRecentlyUpdatedUsers(lastUserCacheUpdate)
	if err != nil {
		providerLog(logger.LevelError, "unable to get recently updated users: %v", err)
		return
	}
	for _, user := range users {
		providerLog(logger.LevelDebug, "invalidate caches for user %q", user.Username)
		if user.DeletedAt > 0 {
			deletedAt := util.GetTimeFromMsecSinceEpoch(user.DeletedAt)
			if deletedAt.Add(30 * time.Minute).Before(time.Now()) {
				providerLog(logger.LevelDebug, "removing user %q deleted at %s", user.Username, deletedAt)
				go provider.deleteUser(user, false) //nolint:errcheck
			}
			webDAVUsersCache.remove(user.Username)
			delayedQuotaUpdater.resetUserQuota(user.Username)
		} else {
			webDAVUsersCache.swap(&user)
		}
		cachedPasswords.Remove(user.Username)
	}

	lastUserCacheUpdate = checkTime
	EventManager.loadRules()
	providerLog(logger.LevelDebug, "end caches check, new update time %v", util.GetTimeFromMsecSinceEpoch(lastUserCacheUpdate))
}

func setLastUserUpdate() {
	atomic.StoreInt64(&lastUserUpdate, util.GetTimeAsMsSinceEpoch(time.Now()))
}

func getLastUserUpdate() int64 {
	return atomic.LoadInt64(&lastUserUpdate)
}

func setLastRuleUpdate() {
	atomic.StoreInt64(&lastRuleUpdate, util.GetTimeAsMsSinceEpoch(time.Now()))
}

func getLastRuleUpdate() int64 {
	return atomic.LoadInt64(&lastRuleUpdate)
}
