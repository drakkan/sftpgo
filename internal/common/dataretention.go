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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wneessen/go-mail"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// RetentionCheckNotification defines the supported notification methods for a retention check result
type RetentionCheckNotification = string

// Supported notification methods
const (
	// notify results using the defined "data_retention_hook"
	RetentionCheckNotificationHook = "Hook"
	// notify results by email
	RetentionCheckNotificationEmail = "Email"
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
			notificationsCopy := make([]string, len(check.Notifications))
			copy(notificationsCopy, check.Notifications)
			checks = append(checks, RetentionCheck{
				Username:      check.Username,
				StartTime:     check.StartTime,
				Notifications: notificationsCopy,
				Email:         check.Email,
				Folders:       foldersCopy,
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
	// how cleanup results will be notified
	Notifications []RetentionCheckNotification `json:"notifications,omitempty"`
	// email to use if the notification method is set to email
	Email string `json:"email,omitempty"`
	Role  string `json:"-"`
	// Cleanup results
	results []folderRetentionCheckResult `json:"-"`
	conn    *BaseConnection
}

// Validate returns an error if the specified folders are not valid
func (c *RetentionCheck) Validate() error {
	folderPaths := make(map[string]bool)
	nothingToDo := true
	for idx := range c.Folders {
		f := &c.Folders[idx]
		if err := f.Validate(); err != nil {
			return err
		}
		if f.Retention > 0 {
			nothingToDo = false
		}
		if _, ok := folderPaths[f.Path]; ok {
			return util.NewValidationError(fmt.Sprintf("duplicated folder path %q", f.Path))
		}
		folderPaths[f.Path] = true
	}
	if nothingToDo {
		return util.NewValidationError("nothing to delete!")
	}
	for _, notification := range c.Notifications {
		switch notification {
		case RetentionCheckNotificationEmail:
			if !smtp.IsEnabled() {
				return util.NewValidationError("in order to notify results via email you must configure an SMTP server")
			}
			if c.Email == "" {
				return util.NewValidationError("in order to notify results via email you must add a valid email address to your profile")
			}
		case RetentionCheckNotificationHook:
			if Config.DataRetentionHook == "" {
				return util.NewValidationError("in order to notify results via hook you must define a data_retention_hook")
			}
		default:
			return util.NewValidationError(fmt.Sprintf("invalid notification %q", notification))
		}
	}
	return nil
}

func (c *RetentionCheck) updateUserPermissions() {
	for _, folder := range c.Folders {
		if folder.IgnoreUserPermissions {
			c.conn.User.Permissions[folder.Path] = []string{dataprovider.PermAny}
		}
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

func (c *RetentionCheck) hasCleanupPerms(folderPath string) bool {
	if !c.conn.User.HasPerm(dataprovider.PermListItems, folderPath) {
		return false
	}
	if !c.conn.User.HasAnyPerm([]string{dataprovider.PermDelete, dataprovider.PermDeleteFiles}, folderPath) {
		return false
	}
	return true
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
	if !c.hasCleanupPerms(folderPath) {
		result.Elapsed = time.Since(startTime)
		result.Info = "data retention check skipped: no permissions"
		c.conn.Log(logger.LevelInfo, "user %q does not have permissions to check retention on %q, retention check skipped",
			c.conn.User.Username, folderPath)
		return nil
	}

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
	c.conn.Log(logger.LevelDebug, "start retention check for folder %q, retention: %v hours, delete empty dirs? %v, ignore user perms? %v",
		folderPath, folderRetention.Retention, folderRetention.DeleteEmptyDirs, folderRetention.IgnoreUserPermissions)
	lister, err := c.conn.ListDir(folderPath)
	if err != nil {
		result.Elapsed = time.Since(startTime)
		if err == c.conn.GetNotExistError() {
			result.Info = "data retention check skipped, folder does not exist"
			c.conn.Log(logger.LevelDebug, "folder %q does not exist, retention check skipped", folderPath)
			return nil
		}
		result.Error = fmt.Sprintf("unable to get lister for directory %q", folderPath)
		c.conn.Log(logger.LevelError, result.Error)
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
				c.conn.Log(logger.LevelError, "retention check failed, unable to cleanup folder %q", folder.Path)
				c.sendNotifications(time.Since(startTime), err)
				return err
			}
		}
	}

	c.conn.Log(logger.LevelInfo, "retention check completed")
	c.sendNotifications(time.Since(startTime), nil)
	return nil
}

func (c *RetentionCheck) sendNotifications(elapsed time.Duration, err error) {
	for _, notification := range c.Notifications {
		switch notification {
		case RetentionCheckNotificationEmail:
			c.sendEmailNotification(err) //nolint:errcheck
		case RetentionCheckNotificationHook:
			c.sendHookNotification(elapsed, err) //nolint:errcheck
		}
	}
}

func (c *RetentionCheck) sendEmailNotification(errCheck error) error {
	params := EventParams{}
	if len(c.results) > 0 || errCheck != nil {
		params.retentionChecks = append(params.retentionChecks, executedRetentionCheck{
			Username:   c.conn.User.Username,
			ActionName: "Retention check",
			Results:    c.results,
		})
	}
	var files []*mail.File
	f, err := params.getRetentionReportsAsMailAttachment()
	if err != nil {
		c.conn.Log(logger.LevelError, "unable to get retention report as mail attachment: %v", err)
		return err
	}
	f.Name = "retention-report.zip"
	files = append(files, f)

	startTime := time.Now()
	var subject string
	if errCheck == nil {
		subject = fmt.Sprintf("Successful retention check for user %q", c.conn.User.Username)
	} else {
		subject = fmt.Sprintf("Retention check failed for user %q", c.conn.User.Username)
	}
	body := "Further details attached."
	err = smtp.SendEmail([]string{c.Email}, nil, subject, body, smtp.EmailContentTypeTextPlain, files...)
	if err != nil {
		c.conn.Log(logger.LevelError, "unable to notify retention check result via email: %v, elapsed: %s", err,
			time.Since(startTime))
		return err
	}
	c.conn.Log(logger.LevelInfo, "retention check result successfully notified via email, elapsed: %s", time.Since(startTime))
	return nil
}

func (c *RetentionCheck) sendHookNotification(elapsed time.Duration, errCheck error) error {
	startNewHook()
	defer hookEnded()

	data := make(map[string]any)
	totalDeletedFiles := 0
	totalDeletedSize := int64(0)
	for _, result := range c.results {
		totalDeletedFiles += result.DeletedFiles
		totalDeletedSize += result.DeletedSize
	}
	data["username"] = c.conn.User.Username
	data["start_time"] = c.StartTime
	data["elapsed"] = elapsed.Milliseconds()
	if errCheck == nil {
		data["status"] = 1
	} else {
		data["status"] = 0
	}
	data["total_deleted_files"] = totalDeletedFiles
	data["total_deleted_size"] = totalDeletedSize
	data["details"] = c.results
	jsonData, _ := json.Marshal(data)

	startTime := time.Now()

	if strings.HasPrefix(Config.DataRetentionHook, "http") {
		var url *url.URL
		url, err := url.Parse(Config.DataRetentionHook)
		if err != nil {
			c.conn.Log(logger.LevelError, "invalid data retention hook %q: %v", Config.DataRetentionHook, err)
			return err
		}
		respCode := 0

		resp, err := httpclient.RetryablePost(url.String(), "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			respCode = resp.StatusCode
			resp.Body.Close()

			if respCode != http.StatusOK {
				err = errUnexpectedHTTResponse
			}
		}

		c.conn.Log(logger.LevelDebug, "notified result to URL: %q, status code: %v, elapsed: %v err: %v",
			url.Redacted(), respCode, time.Since(startTime), err)

		return err
	}
	if !filepath.IsAbs(Config.DataRetentionHook) {
		err := fmt.Errorf("invalid data retention hook %q", Config.DataRetentionHook)
		c.conn.Log(logger.LevelError, "%v", err)
		return err
	}
	timeout, env, args := command.GetConfig(Config.DataRetentionHook, command.HookDataRetention)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.DataRetentionHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_DATA_RETENTION_RESULT=%s", string(jsonData)))
	err := cmd.Run()

	c.conn.Log(logger.LevelDebug, "notified result using command: %q, elapsed: %s err: %v",
		Config.DataRetentionHook, time.Since(startTime), err)
	return err
}
