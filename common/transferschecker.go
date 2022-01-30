package common

import (
	"errors"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

type overquotaTransfer struct {
	ConnID       string
	TransferID   int64
	TransferType int
}

type uploadAggregationKey struct {
	Username   string
	FolderName string
}

// TransfersChecker defines the interface that transfer checkers must implement.
// A transfer checker ensure that multiple concurrent transfers does not exceeded
// the remaining user quota
type TransfersChecker interface {
	AddTransfer(transfer dataprovider.ActiveTransfer)
	RemoveTransfer(ID int64, connectionID string)
	UpdateTransferCurrentSizes(ulSize, dlSize, ID int64, connectionID string)
	GetOverquotaTransfers() []overquotaTransfer
}

func getTransfersChecker(isShared int) TransfersChecker {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider transfer checker")
		return &transfersCheckerDB{}
	}
	logger.Info(logSender, "", "using memory transfer checker")
	return &transfersCheckerMem{}
}

type baseTransferChecker struct {
	transfers []dataprovider.ActiveTransfer
}

func (t *baseTransferChecker) isDataTransferExceeded(user dataprovider.User, transfer dataprovider.ActiveTransfer, ulSize,
	dlSize int64,
) bool {
	ulQuota, dlQuota, totalQuota := user.GetDataTransferLimits(transfer.IP)
	if totalQuota > 0 {
		allowedSize := totalQuota - (user.UsedUploadDataTransfer + user.UsedDownloadDataTransfer)
		if ulSize+dlSize > allowedSize {
			return transfer.CurrentDLSize > 0 || transfer.CurrentULSize > 0
		}
	}
	if dlQuota > 0 {
		allowedSize := dlQuota - user.UsedDownloadDataTransfer
		if dlSize > allowedSize {
			return transfer.CurrentDLSize > 0
		}
	}
	if ulQuota > 0 {
		allowedSize := ulQuota - user.UsedUploadDataTransfer
		if ulSize > allowedSize {
			return transfer.CurrentULSize > 0
		}
	}
	return false
}

func (t *baseTransferChecker) getRemainingDiskQuota(user dataprovider.User, folderName string) (int64, error) {
	var result int64

	if folderName != "" {
		for _, folder := range user.VirtualFolders {
			if folder.Name == folderName {
				if folder.QuotaSize > 0 {
					return folder.QuotaSize - folder.UsedQuotaSize, nil
				}
			}
		}
	} else {
		if user.QuotaSize > 0 {
			return user.QuotaSize - user.UsedQuotaSize, nil
		}
	}

	return result, errors.New("no quota limit defined")
}

func (t *baseTransferChecker) aggregateTransfersByUser(usersToFetch map[string]bool,
) (map[string]bool, map[string][]dataprovider.ActiveTransfer) {
	aggregations := make(map[string][]dataprovider.ActiveTransfer)
	for _, transfer := range t.transfers {
		aggregations[transfer.Username] = append(aggregations[transfer.Username], transfer)
		if len(aggregations[transfer.Username]) > 1 {
			if _, ok := usersToFetch[transfer.Username]; !ok {
				usersToFetch[transfer.Username] = false
			}
		}
	}

	return usersToFetch, aggregations
}

func (t *baseTransferChecker) aggregateUploadTransfers() (map[string]bool, map[int][]dataprovider.ActiveTransfer) {
	usersToFetch := make(map[string]bool)
	aggregations := make(map[int][]dataprovider.ActiveTransfer)
	var keys []uploadAggregationKey

	for _, transfer := range t.transfers {
		if transfer.Type != TransferUpload {
			continue
		}
		key := -1
		for idx, k := range keys {
			if k.Username == transfer.Username && k.FolderName == transfer.FolderName {
				key = idx
				break
			}
		}
		if key == -1 {
			key = len(keys)
		}
		keys = append(keys, uploadAggregationKey{
			Username:   transfer.Username,
			FolderName: transfer.FolderName,
		})

		aggregations[key] = append(aggregations[key], transfer)
		if len(aggregations[key]) > 1 {
			if transfer.FolderName != "" {
				usersToFetch[transfer.Username] = true
			} else {
				if _, ok := usersToFetch[transfer.Username]; !ok {
					usersToFetch[transfer.Username] = false
				}
			}
		}
	}

	return usersToFetch, aggregations
}

func (t *baseTransferChecker) getUsersToCheck(usersToFetch map[string]bool) (map[string]dataprovider.User, error) {
	users, err := dataprovider.GetUsersForQuotaCheck(usersToFetch)
	if err != nil {
		return nil, err
	}

	usersMap := make(map[string]dataprovider.User)

	for _, user := range users {
		usersMap[user.Username] = user
	}

	return usersMap, nil
}

func (t *baseTransferChecker) getOverquotaTransfers(usersToFetch map[string]bool,
	uploadAggregations map[int][]dataprovider.ActiveTransfer,
	userAggregations map[string][]dataprovider.ActiveTransfer,
) []overquotaTransfer {
	if len(usersToFetch) == 0 {
		return nil
	}
	usersMap, err := t.getUsersToCheck(usersToFetch)
	if err != nil {
		logger.Warn(logSender, "", "unable to check transfers, error getting users quota: %v", err)
		return nil
	}

	var overquotaTransfers []overquotaTransfer

	for _, transfers := range uploadAggregations {
		username := transfers[0].Username
		folderName := transfers[0].FolderName
		remaningDiskQuota, err := t.getRemainingDiskQuota(usersMap[username], folderName)
		if err != nil {
			continue
		}
		var usedDiskQuota int64
		for _, tr := range transfers {
			// We optimistically assume that a cloud transfer that replaces an existing
			// file will be successful
			usedDiskQuota += tr.CurrentULSize - tr.TruncatedSize
		}
		logger.Debug(logSender, "", "username %#v, folder %#v, concurrent transfers: %v, remaining disk quota (bytes): %v, disk quota used in ongoing transfers (bytes): %v",
			username, folderName, len(transfers), remaningDiskQuota, usedDiskQuota)
		if usedDiskQuota > remaningDiskQuota {
			for _, tr := range transfers {
				if tr.CurrentULSize > tr.TruncatedSize {
					overquotaTransfers = append(overquotaTransfers, overquotaTransfer{
						ConnID:       tr.ConnID,
						TransferID:   tr.ID,
						TransferType: tr.Type,
					})
				}
			}
		}
	}

	for username, transfers := range userAggregations {
		var ulSize, dlSize int64
		for _, tr := range transfers {
			ulSize += tr.CurrentULSize
			dlSize += tr.CurrentDLSize
		}
		logger.Debug(logSender, "", "username %#v, concurrent transfers: %v, quota (bytes) used in ongoing transfers, ul: %v, dl: %v",
			username, len(transfers), ulSize, dlSize)
		for _, tr := range transfers {
			if t.isDataTransferExceeded(usersMap[username], tr, ulSize, dlSize) {
				overquotaTransfers = append(overquotaTransfers, overquotaTransfer{
					ConnID:       tr.ConnID,
					TransferID:   tr.ID,
					TransferType: tr.Type,
				})
			}
		}
	}

	return overquotaTransfers
}

type transfersCheckerMem struct {
	sync.RWMutex
	baseTransferChecker
}

func (t *transfersCheckerMem) AddTransfer(transfer dataprovider.ActiveTransfer) {
	t.Lock()
	defer t.Unlock()

	t.transfers = append(t.transfers, transfer)
}

func (t *transfersCheckerMem) RemoveTransfer(ID int64, connectionID string) {
	t.Lock()
	defer t.Unlock()

	for idx, transfer := range t.transfers {
		if transfer.ID == ID && transfer.ConnID == connectionID {
			lastIdx := len(t.transfers) - 1
			t.transfers[idx] = t.transfers[lastIdx]
			t.transfers = t.transfers[:lastIdx]
			return
		}
	}
}

func (t *transfersCheckerMem) UpdateTransferCurrentSizes(ulSize, dlSize, ID int64, connectionID string) {
	t.Lock()
	defer t.Unlock()

	for idx := range t.transfers {
		if t.transfers[idx].ID == ID && t.transfers[idx].ConnID == connectionID {
			t.transfers[idx].CurrentDLSize = dlSize
			t.transfers[idx].CurrentULSize = ulSize
			t.transfers[idx].UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
			return
		}
	}
}

func (t *transfersCheckerMem) GetOverquotaTransfers() []overquotaTransfer {
	t.RLock()

	usersToFetch, uploadAggregations := t.aggregateUploadTransfers()
	usersToFetch, userAggregations := t.aggregateTransfersByUser(usersToFetch)

	t.RUnlock()

	return t.getOverquotaTransfers(usersToFetch, uploadAggregations, userAggregations)
}

type transfersCheckerDB struct {
	baseTransferChecker
	lastCleanup time.Time
}

func (t *transfersCheckerDB) AddTransfer(transfer dataprovider.ActiveTransfer) {
	dataprovider.AddActiveTransfer(transfer)
}

func (t *transfersCheckerDB) RemoveTransfer(ID int64, connectionID string) {
	dataprovider.RemoveActiveTransfer(ID, connectionID)
}

func (t *transfersCheckerDB) UpdateTransferCurrentSizes(ulSize, dlSize, ID int64, connectionID string) {
	dataprovider.UpdateActiveTransferSizes(ulSize, dlSize, ID, connectionID)
}

func (t *transfersCheckerDB) GetOverquotaTransfers() []overquotaTransfer {
	if t.lastCleanup.IsZero() || t.lastCleanup.Add(periodicTimeoutCheckInterval*15).Before(time.Now()) {
		before := time.Now().Add(-periodicTimeoutCheckInterval * 5)
		err := dataprovider.CleanupActiveTransfers(before)
		logger.Debug(logSender, "", "cleanup active transfers completed, err: %v", err)
		if err == nil {
			t.lastCleanup = time.Now()
		}
	}
	var err error
	from := time.Now().Add(-periodicTimeoutCheckInterval * 2)
	t.transfers, err = dataprovider.GetActiveTransfers(from)
	if err != nil {
		logger.Error(logSender, "", "unable to check overquota transfers, error getting active transfers: %v", err)
		return nil
	}

	usersToFetch, uploadAggregations := t.aggregateUploadTransfers()
	usersToFetch, userAggregations := t.aggregateTransfersByUser(usersToFetch)

	return t.getOverquotaTransfers(usersToFetch, uploadAggregations, userAggregations)
}
