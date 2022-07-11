package dataprovider

import (
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/util"
)

var (
	// QuotaScans is the list of active quota scans
	QuotaScans ActiveScans
)

// ActiveQuotaScan defines an active quota scan for a user home dir
type ActiveQuotaScan struct {
	// Username to which the quota scan refers
	Username string `json:"username"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// ActiveVirtualFolderQuotaScan defines an active quota scan for a virtual folder
type ActiveVirtualFolderQuotaScan struct {
	// folder name to which the quota scan refers
	Name string `json:"name"`
	// quota scan start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// ActiveScans holds the active quota scans
type ActiveScans struct {
	sync.RWMutex
	UserScans   []ActiveQuotaScan
	FolderScans []ActiveVirtualFolderQuotaScan
}

// GetUsersQuotaScans returns the active quota scans for users home directories
func (s *ActiveScans) GetUsersQuotaScans() []ActiveQuotaScan {
	s.RLock()
	defer s.RUnlock()

	scans := make([]ActiveQuotaScan, len(s.UserScans))
	copy(scans, s.UserScans)
	return scans
}

// AddUserQuotaScan adds a user to the ones with active quota scans.
// Returns false if the user has a quota scan already running
func (s *ActiveScans) AddUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.UserScans {
		if scan.Username == username {
			return false
		}
	}
	s.UserScans = append(s.UserScans, ActiveQuotaScan{
		Username:  username,
		StartTime: util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveUserQuotaScan removes a user from the ones with active quota scans.
// Returns false if the user has no active quota scans
func (s *ActiveScans) RemoveUserQuotaScan(username string) bool {
	s.Lock()
	defer s.Unlock()

	for idx, scan := range s.UserScans {
		if scan.Username == username {
			lastIdx := len(s.UserScans) - 1
			s.UserScans[idx] = s.UserScans[lastIdx]
			s.UserScans = s.UserScans[:lastIdx]
			return true
		}
	}

	return false
}

// GetVFoldersQuotaScans returns the active quota scans for virtual folders
func (s *ActiveScans) GetVFoldersQuotaScans() []ActiveVirtualFolderQuotaScan {
	s.RLock()
	defer s.RUnlock()
	scans := make([]ActiveVirtualFolderQuotaScan, len(s.FolderScans))
	copy(scans, s.FolderScans)
	return scans
}

// AddVFolderQuotaScan adds a virtual folder to the ones with active quota scans.
// Returns false if the folder has a quota scan already running
func (s *ActiveScans) AddVFolderQuotaScan(folderName string) bool {
	s.Lock()
	defer s.Unlock()

	for _, scan := range s.FolderScans {
		if scan.Name == folderName {
			return false
		}
	}
	s.FolderScans = append(s.FolderScans, ActiveVirtualFolderQuotaScan{
		Name:      folderName,
		StartTime: util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	return true
}

// RemoveVFolderQuotaScan removes a folder from the ones with active quota scans.
// Returns false if the folder has no active quota scans
func (s *ActiveScans) RemoveVFolderQuotaScan(folderName string) bool {
	s.Lock()
	defer s.Unlock()

	for idx, scan := range s.FolderScans {
		if scan.Name == folderName {
			lastIdx := len(s.FolderScans) - 1
			s.FolderScans[idx] = s.FolderScans[lastIdx]
			s.FolderScans = s.FolderScans[:lastIdx]
			return true
		}
	}

	return false
}
