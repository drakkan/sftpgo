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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	// RetentionChecks is the list of active retention checks
	RetentionChecks ActiveRetentionChecks
)

// ActiveRetentionChecks holds the active retention checks
type ActiveRetentionChecks struct {
	sync.RWMutex
	Checks []RetentionCheck
}

// Get returns the active retention checks
func (c *ActiveRetentionChecks) Get(role string) []RetentionCheck {
	c.RLock()
	defer c.RUnlock()

	checks := make([]RetentionCheck, 0, len(c.Checks))
	for _, check := range c.Checks {
		if role == "" || role == check.Role {
			foldersCopy := make([]dataprovider.FolderRetention, len(check.Folders))
			copy(foldersCopy, check.Folders)
			checks = append(checks, RetentionCheck{
				Username:  check.Username,
				StartTime: check.StartTime,
				Folders:   foldersCopy,
			})
		}
	}
	return checks
}

// Add a new retention check, returns nil if a retention check for the given
// username is already active. The returned result can be used to start the check
func (c *ActiveRetentionChecks) Add(check RetentionCheck, user *dataprovider.User) *RetentionCheck {
	c.Lock()
	defer c.Unlock()

	for _, val := range c.Checks {
		if val.Username == user.Username {
			return nil
		}
	}
	// we silently ignore file patterns
	user.Filters.FilePatterns = nil
	conn := NewBaseConnection("", "", "", "", *user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.Username = user.Username
	check.Role = user.Role
	check.StartTime = util.GetTimeAsMsSinceEpoch(time.Now())
	check.conn = conn
	check.updateUserPermissions()
	c.Checks = append(c.Checks, check)

	return &check
}

// remove a user from the ones with active retention checks
// and returns true if the user is removed
func (c *ActiveRetentionChecks) remove(username string) bool {
	c.Lock()
	defer c.Unlock()

	for idx, check := range c.Checks {
		if check.Username == username {
			lastIdx := len(c.Checks) - 1
			c.Checks[idx] = c.Checks[lastIdx]
			c.Checks = c.Checks[:lastIdx]
			return true
		}
	}

	return false
}

type folderRetentionCheckResult struct {
	Path         string        `json:"path"`
	Retention    int           `json:"retention"`
	DeletedFiles int           `json:"deleted_files"`
	DeletedSize  int64         `json:"deleted_size"`
	Elapsed      time.Duration `json:"-"`
	Info         string        `json:"info,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// RetentionCheck defines an active retention check
type RetentionCheck struct {
	// Username to which the retention check refers
	Username string `json:"username"`
	// retention check start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
	// affected folders
	Folders []dataprovider.FolderRetention `json:"folders"`
	Role    string                         `json:"-"`
	// Cleanup results
	results []folderRetentionCheckResult `json:"-"`
	conn    *BaseConnection              `json:"-"`
}

func (c *RetentionCheck) updateUserPermissions() {
	for k := range c.conn.User.Permissions {
		c.conn.User.Permissions[k] = []string{dataprovider.PermAny}
	}
}

func (c *RetentionCheck) getFolderRetention(folderPath string) (dataprovider.FolderRetention, error) {
	dirsForPath := util.GetDirsForVirtualPath(folderPath)
	for _, dirPath := range dirsForPath {
		for _, folder := range c.Folders {
			if folder.Path == dirPath {
				return folder, nil
			}
		}
	}

	return dataprovider.FolderRetention{}, fmt.Errorf("unable to find folder retention for %q", folderPath)
}

func (c *RetentionCheck) removeFile(virtualPath string, info os.FileInfo) error {
	fs, fsPath, err := c.conn.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	return c.conn.RemoveFile(fs, fsPath, virtualPath, info)
}

func (c *RetentionCheck) cleanupFolder(folderPath string, recursion int) error {
	startTime := time.Now()
	result := folderRetentionCheckResult{
		Path: folderPath,
	}
	defer func() {
		c.results = append(c.results, result)
	}()
	if recursion >= util.MaxRecursion {
		result.Elapsed = time.Since(startTime)
		result.Info = "data retention check skipped: recursion too deep"
		c.conn.Log(logger.LevelError, "data retention check skipped, recursion too depth for %q: %d",
			folderPath, recursion)
		return util.ErrRecursionTooDeep
	}
	recursion++

	folderRetention, err := c.getFolderRetention(folderPath)
	if err != nil {
		result.Elapsed = time.Since(startTime)
		result.Error = "unable to get folder retention"
		c.conn.Log(logger.LevelError, "unable to get folder retention for path %q", folderPath)
		return err
	}
	result.Retention = folderRetention.Retention
	if folderRetention.Retention == 0 {
		result.Elapsed = time.Since(startTime)
		result.Info = "data retention check skipped: retention is set to 0"
		c.conn.Log(logger.LevelDebug, "retention check skipped for folder %q, retention is set to 0", folderPath)
		return nil
	}
	c.conn.Log(logger.LevelDebug, "start retention check for folder %q, retention: %v hours, delete empty dirs? %v",
		folderPath, folderRetention.Retention, folderRetention.DeleteEmptyDirs)
	lister, err := c.conn.ListDir(folderPath)
	if err != nil {
		result.Elapsed = time.Since(startTime)
		if err == c.conn.GetNotExistError() {
			result.Info = "data retention check skipped, folder does not exist"
			c.conn.Log(logger.LevelDebug, "folder %q does not exist, retention check skipped", folderPath)
			return nil
		}
		result.Error = fmt.Sprintf("unable to get lister for directory %q", folderPath)
		c.conn.Log(logger.LevelError, "%s", result.Error)
		return err
	}
	defer lister.Close()

	for {
		files, err := lister.Next(vfs.ListerBatchSize)
		finished := errors.Is(err, io.EOF)
		if err := lister.convertError(err); err != nil {
			result.Elapsed = time.Since(startTime)
			result.Error = fmt.Sprintf("unable to list directory %q", folderPath)
			c.conn.Log(logger.LevelError, "unable to list dir %q: %v", folderPath, err)
			return err
		}
		for _, info := range files {
			virtualPath := path.Join(folderPath, info.Name())
			if info.IsDir() {
				if err := c.cleanupFolder(virtualPath, recursion); err != nil {
					result.Elapsed = time.Since(startTime)
					result.Error = fmt.Sprintf("unable to check folder: %v", err)
					c.conn.Log(logger.LevelError, "unable to cleanup folder %q: %v", virtualPath, err)
					return err
				}
			} else {
				retentionTime := info.ModTime().Add(time.Duration(folderRetention.Retention) * time.Hour)
				if retentionTime.Before(time.Now()) {
					if err := c.removeFile(virtualPath, info); err != nil {
						result.Elapsed = time.Since(startTime)
						result.Error = fmt.Sprintf("unable to remove file %q: %v", virtualPath, err)
						c.conn.Log(logger.LevelError, "unable to remove file %q, retention %v: %v",
							virtualPath, retentionTime, err)
						return err
					}
					c.conn.Log(logger.LevelDebug, "removed file %q, modification time: %v, retention: %v hours, retention time: %v",
						virtualPath, info.ModTime(), folderRetention.Retention, retentionTime)
					result.DeletedFiles++
					result.DeletedSize += info.Size()
				}
			}
		}
		if finished {
			break
		}
	}

	lister.Close()
	c.checkEmptyDirRemoval(folderPath, folderRetention.DeleteEmptyDirs)
	result.Elapsed = time.Since(startTime)
	c.conn.Log(logger.LevelDebug, "retention check completed for folder %q, deleted files: %v, deleted size: %v bytes",
		folderPath, result.DeletedFiles, result.DeletedSize)

	return nil
}

func (c *RetentionCheck) checkEmptyDirRemoval(folderPath string, checkVal bool) {
	if folderPath == "/" || !checkVal {
		return
	}
	for _, folder := range c.Folders {
		if folderPath == folder.Path {
			return
		}
	}
	if c.conn.User.HasAnyPerm([]string{
		dataprovider.PermDelete,
		dataprovider.PermDeleteDirs,
	}, path.Dir(folderPath),
	) {
		lister, err := c.conn.ListDir(folderPath)
		if err == nil {
			files, err := lister.Next(1)
			lister.Close()
			if len(files) == 0 && errors.Is(err, io.EOF) {
				err = c.conn.RemoveDir(folderPath)
				c.conn.Log(logger.LevelDebug, "tried to remove empty dir %q, error: %v", folderPath, err)
			}
		}
	}
}

// Start starts the retention check
func (c *RetentionCheck) Start() error {
	c.conn.Log(logger.LevelInfo, "retention check started")
	defer RetentionChecks.remove(c.conn.User.Username)
	defer c.conn.CloseFS() //nolint:errcheck

	startTime := time.Now()
	for _, folder := range c.Folders {
		if folder.Retention > 0 {
			if err := c.cleanupFolder(folder.Path, 0); err != nil {
				c.conn.Log(logger.LevelError, "retention check failed, unable to cleanup folder %q, elapsed: %s",
					folder.Path, time.Since(startTime))
				return err
			}
		}
	}

	c.conn.Log(logger.LevelInfo, "retention check completed, elapsed: %s", time.Since(startTime))
	return nil
}
