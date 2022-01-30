package dataprovider

import (
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/logger"
)

var delayedQuotaUpdater quotaUpdater

func init() {
	delayedQuotaUpdater = newQuotaUpdater()
}

type quotaObject struct {
	size  int64
	files int
}

type transferQuotaObject struct {
	ulSize int64
	dlSize int64
}

type quotaUpdater struct {
	paramsMutex sync.RWMutex
	waitTime    time.Duration
	sync.RWMutex
	pendingUserQuotaUpdates     map[string]quotaObject
	pendingFolderQuotaUpdates   map[string]quotaObject
	pendingTransferQuotaUpdates map[string]transferQuotaObject
}

func newQuotaUpdater() quotaUpdater {
	return quotaUpdater{
		pendingUserQuotaUpdates:     make(map[string]quotaObject),
		pendingFolderQuotaUpdates:   make(map[string]quotaObject),
		pendingTransferQuotaUpdates: make(map[string]transferQuotaObject),
	}
}

func (q *quotaUpdater) start() {
	q.setWaitTime(config.DelayedQuotaUpdate)

	go q.loop()
}

func (q *quotaUpdater) loop() {
	waitTime := q.getWaitTime()
	providerLog(logger.LevelDebug, "delayed quota update loop started, wait time: %v", waitTime)
	for waitTime > 0 {
		// We do this with a time.Sleep instead of a time.Ticker because we don't know
		// how long each quota processing cycle will take, and we want to make
		// sure we wait the configured seconds between each iteration
		time.Sleep(waitTime)
		providerLog(logger.LevelDebug, "delayed quota update check start")
		q.storeUsersQuota()
		q.storeFoldersQuota()
		q.storeUsersTransferQuota()
		providerLog(logger.LevelDebug, "delayed quota update check end")
		waitTime = q.getWaitTime()
	}
	providerLog(logger.LevelDebug, "delayed quota update loop ended, wait time: %v", waitTime)
}

func (q *quotaUpdater) setWaitTime(secs int) {
	q.paramsMutex.Lock()
	defer q.paramsMutex.Unlock()

	q.waitTime = time.Duration(secs) * time.Second
}

func (q *quotaUpdater) getWaitTime() time.Duration {
	q.paramsMutex.RLock()
	defer q.paramsMutex.RUnlock()

	return q.waitTime
}

func (q *quotaUpdater) resetUserQuota(username string) {
	q.Lock()
	defer q.Unlock()

	delete(q.pendingUserQuotaUpdates, username)
}

func (q *quotaUpdater) updateUserQuota(username string, files int, size int64) {
	q.Lock()
	defer q.Unlock()

	obj := q.pendingUserQuotaUpdates[username]
	obj.size += size
	obj.files += files
	if obj.files == 0 && obj.size == 0 {
		delete(q.pendingUserQuotaUpdates, username)
		return
	}
	q.pendingUserQuotaUpdates[username] = obj
}

func (q *quotaUpdater) getUserPendingQuota(username string) (int, int64) {
	q.RLock()
	defer q.RUnlock()

	obj := q.pendingUserQuotaUpdates[username]

	return obj.files, obj.size
}

func (q *quotaUpdater) resetFolderQuota(name string) {
	q.Lock()
	defer q.Unlock()

	delete(q.pendingFolderQuotaUpdates, name)
}

func (q *quotaUpdater) updateFolderQuota(name string, files int, size int64) {
	q.Lock()
	defer q.Unlock()

	obj := q.pendingFolderQuotaUpdates[name]
	obj.size += size
	obj.files += files
	if obj.files == 0 && obj.size == 0 {
		delete(q.pendingFolderQuotaUpdates, name)
		return
	}
	q.pendingFolderQuotaUpdates[name] = obj
}

func (q *quotaUpdater) getFolderPendingQuota(name string) (int, int64) {
	q.RLock()
	defer q.RUnlock()

	obj := q.pendingFolderQuotaUpdates[name]

	return obj.files, obj.size
}

func (q *quotaUpdater) resetUserTransferQuota(username string) {
	q.Lock()
	defer q.Unlock()

	delete(q.pendingTransferQuotaUpdates, username)
}

func (q *quotaUpdater) updateUserTransferQuota(username string, ulSize, dlSize int64) {
	q.Lock()
	defer q.Unlock()

	obj := q.pendingTransferQuotaUpdates[username]
	obj.ulSize += ulSize
	obj.dlSize += dlSize
	if obj.ulSize == 0 && obj.dlSize == 0 {
		delete(q.pendingTransferQuotaUpdates, username)
		return
	}
	q.pendingTransferQuotaUpdates[username] = obj
}

func (q *quotaUpdater) getUserPendingTransferQuota(username string) (int64, int64) {
	q.RLock()
	defer q.RUnlock()

	obj := q.pendingTransferQuotaUpdates[username]

	return obj.ulSize, obj.dlSize
}

func (q *quotaUpdater) getUsernames() []string {
	q.RLock()
	defer q.RUnlock()

	result := make([]string, 0, len(q.pendingUserQuotaUpdates))
	for username := range q.pendingUserQuotaUpdates {
		result = append(result, username)
	}

	return result
}

func (q *quotaUpdater) getFoldernames() []string {
	q.RLock()
	defer q.RUnlock()

	result := make([]string, 0, len(q.pendingFolderQuotaUpdates))
	for name := range q.pendingFolderQuotaUpdates {
		result = append(result, name)
	}

	return result
}

func (q *quotaUpdater) getTransferQuotaUsernames() []string {
	q.RLock()
	defer q.RUnlock()

	result := make([]string, 0, len(q.pendingTransferQuotaUpdates))
	for username := range q.pendingTransferQuotaUpdates {
		result = append(result, username)
	}

	return result
}

func (q *quotaUpdater) storeUsersQuota() {
	for _, username := range q.getUsernames() {
		files, size := q.getUserPendingQuota(username)
		if size != 0 || files != 0 {
			err := provider.updateQuota(username, files, size, false)
			if err != nil {
				providerLog(logger.LevelWarn, "unable to update quota delayed for user %#v: %v", username, err)
				continue
			}
			q.updateUserQuota(username, -files, -size)
		}
	}
}

func (q *quotaUpdater) storeFoldersQuota() {
	for _, name := range q.getFoldernames() {
		files, size := q.getFolderPendingQuota(name)
		if size != 0 || files != 0 {
			err := provider.updateFolderQuota(name, files, size, false)
			if err != nil {
				providerLog(logger.LevelWarn, "unable to update quota delayed for folder %#v: %v", name, err)
				continue
			}
			q.updateFolderQuota(name, -files, -size)
		}
	}
}

func (q *quotaUpdater) storeUsersTransferQuota() {
	for _, username := range q.getTransferQuotaUsernames() {
		ulSize, dlSize := q.getUserPendingTransferQuota(username)
		if ulSize != 0 || dlSize != 0 {
			err := provider.updateTransferQuota(username, ulSize, dlSize, false)
			if err != nil {
				providerLog(logger.LevelWarn, "unable to update transfer quota delayed for user %#v: %v", username, err)
				continue
			}
			q.updateUserTransferQuota(username, -ulSize, -dlSize)
		}
	}
}
