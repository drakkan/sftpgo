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
	ConnID     string
	TransferID int64
}

// TransfersChecker defines the interface that transfer checkers must implement.
// A transfer checker ensure that multiple concurrent transfers does not exceeded
// the remaining user quota
type TransfersChecker interface {
	AddTransfer(transfer dataprovider.ActiveTransfer)
	RemoveTransfer(ID int64, connectionID string)
	UpdateTransferCurrentSize(ulSize int64, dlSize int64, ID int64, connectionID string)
	GetOverquotaTransfers() []overquotaTransfer
}

func getTransfersChecker() TransfersChecker {
	return &transfersCheckerMem{}
}

type transfersCheckerMem struct {
	sync.RWMutex
	transfers []dataprovider.ActiveTransfer
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

func (t *transfersCheckerMem) UpdateTransferCurrentSize(ulSize int64, dlSize int64, ID int64, connectionID string) {
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

func (t *transfersCheckerMem) getRemainingDiskQuota(user dataprovider.User, folderName string) (int64, error) {
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

func (t *transfersCheckerMem) aggregateTransfers() (map[string]bool, map[string][]dataprovider.ActiveTransfer) {
	t.RLock()
	defer t.RUnlock()

	usersToFetch := make(map[string]bool)
	aggregations := make(map[string][]dataprovider.ActiveTransfer)
	for _, transfer := range t.transfers {
		key := transfer.GetKey()
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

func (t *transfersCheckerMem) GetOverquotaTransfers() []overquotaTransfer {
	usersToFetch, aggregations := t.aggregateTransfers()

	if len(usersToFetch) == 0 {
		return nil
	}

	users, err := dataprovider.GetUsersForQuotaCheck(usersToFetch)
	if err != nil {
		logger.Warn(logSender, "", "unable to check transfers, error getting users quota: %v", err)
		return nil
	}

	usersMap := make(map[string]dataprovider.User)

	for _, user := range users {
		usersMap[user.Username] = user
	}

	var overquotaTransfers []overquotaTransfer

	for _, transfers := range aggregations {
		if len(transfers) > 1 {
			username := transfers[0].Username
			folderName := transfers[0].FolderName
			// transfer type is always upload for now
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
			logger.Debug(logSender, "", "username %#v, folder %#v, concurrent transfers: %v, remaining disk quota: %v, disk quota used in ongoing transfers: %v",
				username, folderName, len(transfers), remaningDiskQuota, usedDiskQuota)
			if usedDiskQuota > remaningDiskQuota {
				for _, tr := range transfers {
					if tr.CurrentULSize > tr.TruncatedSize {
						overquotaTransfers = append(overquotaTransfers, overquotaTransfer{
							ConnID:     tr.ConnID,
							TransferID: tr.ID,
						})
					}
				}
			}
		}
	}

	return overquotaTransfers
}
