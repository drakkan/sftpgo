package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
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
	// RetentionChecks is the list of active quota scans
	RetentionChecks ActiveRetentionChecks
)

// ActiveRetentionChecks holds the active quota scans
type ActiveRetentionChecks struct {
	sync.RWMutex
	Checks []RetentionCheck
}

// Get returns the active retention checks
func (c *ActiveRetentionChecks) Get() []RetentionCheck {
	c.RLock()
	defer c.RUnlock()

	checks := make([]RetentionCheck, 0, len(c.Checks))
	for _, check := range c.Checks {
		foldersCopy := make([]FolderRetention, len(check.Folders))
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

// FolderRetention defines the retention policy for the specified directory path
type FolderRetention struct {
	// Path is the exposed virtual directory path, if no other specific retention is defined,
	// the retention applies for sub directories too. For example if retention is defined
	// for the paths "/" and "/sub" then the retention for "/" is applied for any file outside
	// the "/sub" directory
	Path string `json:"path"`
	// Retention time in hours. 0 means exclude this path
	Retention int `json:"retention"`
	// DeleteEmptyDirs defines if empty directories will be deleted.
	// The user need the delete permission
	DeleteEmptyDirs bool `json:"delete_empty_dirs,omitempty"`
	// IgnoreUserPermissions defines if delete files even if the user does not have the delete permission.
	// The default is "false" which means that files will be skipped if the user does not have the permission
	// to delete them. This applies to sub directories too.
	IgnoreUserPermissions bool `json:"ignore_user_permissions,omitempty"`
}

func (f *FolderRetention) isValid() error {
	f.Path = path.Clean(f.Path)
	if !path.IsAbs(f.Path) {
		return util.NewValidationError(fmt.Sprintf("folder retention: invalid path %#v, please specify an absolute POSIX path",
			f.Path))
	}
	if f.Retention < 0 {
		return util.NewValidationError(fmt.Sprintf("invalid folder retention %v, it must be greater or equal to zero",
			f.Retention))
	}
	return nil
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
	Folders []FolderRetention `json:"folders"`
	// how cleanup results will be notified
	Notifications []RetentionCheckNotification `json:"notifications,omitempty"`
	// email to use if the notification method is set to email
	Email string `json:"email,omitempty"`
	// Cleanup results
	results []*folderRetentionCheckResult `json:"-"`
	conn    *BaseConnection
}

// Validate returns an error if the specified folders are not valid
func (c *RetentionCheck) Validate() error {
	folderPaths := make(map[string]bool)
	nothingToDo := true
	for idx := range c.Folders {
		f := &c.Folders[idx]
		if err := f.isValid(); err != nil {
			return err
		}
		if f.Retention > 0 {
			nothingToDo = false
		}
		if _, ok := folderPaths[f.Path]; ok {
			return util.NewValidationError(fmt.Sprintf("duplicated folder path %#v", f.Path))
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
			return util.NewValidationError(fmt.Sprintf("invalid notification %#v", notification))
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

func (c *RetentionCheck) getFolderRetention(folderPath string) (FolderRetention, error) {
	dirsForPath := util.GetDirsForVirtualPath(folderPath)
	for _, dirPath := range dirsForPath {
		for _, folder := range c.Folders {
			if folder.Path == dirPath {
				return folder, nil
			}
		}
	}

	return FolderRetention{}, fmt.Errorf("unable to find folder retention for %#v", folderPath)
}

func (c *RetentionCheck) removeFile(virtualPath string, info os.FileInfo) error {
	fs, fsPath, err := c.conn.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return err
	}
	return c.conn.RemoveFile(fs, fsPath, virtualPath, info)
}

func (c *RetentionCheck) cleanupFolder(folderPath string) error {
	deleteFilesPerms := []string{dataprovider.PermDelete, dataprovider.PermDeleteFiles}
	startTime := time.Now()
	result := &folderRetentionCheckResult{
		Path: folderPath,
	}
	c.results = append(c.results, result)
	if !c.conn.User.HasPerm(dataprovider.PermListItems, folderPath) || !c.conn.User.HasAnyPerm(deleteFilesPerms, folderPath) {
		result.Elapsed = time.Since(startTime)
		result.Info = "data retention check skipped: no permissions"
		c.conn.Log(logger.LevelInfo, "user %#v does not have permissions to check retention on %#v, retention check skipped",
			c.conn.User, folderPath)
		return nil
	}

	folderRetention, err := c.getFolderRetention(folderPath)
	if err != nil {
		result.Elapsed = time.Since(startTime)
		result.Error = "unable to get folder retention"
		c.conn.Log(logger.LevelError, "unable to get folder retention for path %#v", folderPath)
		return err
	}
	result.Retention = folderRetention.Retention
	if folderRetention.Retention == 0 {
		result.Elapsed = time.Since(startTime)
		result.Info = "data retention check skipped: retention is set to 0"
		c.conn.Log(logger.LevelDebug, "retention check skipped for folder %#v, retention is set to 0", folderPath)
		return nil
	}
	c.conn.Log(logger.LevelDebug, "start retention check for folder %#v, retention: %v hours, delete empty dirs? %v, ignore user perms? %v",
		folderPath, folderRetention.Retention, folderRetention.DeleteEmptyDirs, folderRetention.IgnoreUserPermissions)
	files, err := c.conn.ListDir(folderPath)
	if err != nil {
		result.Elapsed = time.Since(startTime)
		if err == c.conn.GetNotExistError() {
			result.Info = "data retention check skipped, folder does not exist"
			c.conn.Log(logger.LevelDebug, "folder %#v does not exist, retention check skipped", folderPath)
			return nil
		}
		result.Error = fmt.Sprintf("unable to list directory %#v", folderPath)
		c.conn.Log(logger.LevelError, result.Error)
		return err
	}
	for _, info := range files {
		virtualPath := path.Join(folderPath, info.Name())
		if info.IsDir() {
			if err := c.cleanupFolder(virtualPath); err != nil {
				result.Elapsed = time.Since(startTime)
				result.Error = fmt.Sprintf("unable to check folder: %v", err)
				c.conn.Log(logger.LevelError, "unable to cleanup folder %#v: %v", virtualPath, err)
				return err
			}
		} else {
			retentionTime := info.ModTime().Add(time.Duration(folderRetention.Retention) * time.Hour)
			if retentionTime.Before(time.Now()) {
				if err := c.removeFile(virtualPath, info); err != nil {
					result.Elapsed = time.Since(startTime)
					result.Error = fmt.Sprintf("unable to remove file %#v: %v", virtualPath, err)
					c.conn.Log(logger.LevelError, "unable to remove file %#v, retention %v: %v",
						virtualPath, retentionTime, err)
					return err
				}
				c.conn.Log(logger.LevelDebug, "removed file %#v, modification time: %v, retention: %v hours, retention time: %v",
					virtualPath, info.ModTime(), folderRetention.Retention, retentionTime)
				result.DeletedFiles++
				result.DeletedSize += info.Size()
			}
		}
	}

	if folderRetention.DeleteEmptyDirs {
		c.checkEmptyDirRemoval(folderPath)
	}
	result.Elapsed = time.Since(startTime)
	c.conn.Log(logger.LevelDebug, "retention check completed for folder %#v, deleted files: %v, deleted size: %v bytes",
		folderPath, result.DeletedFiles, result.DeletedSize)

	return nil
}

func (c *RetentionCheck) checkEmptyDirRemoval(folderPath string) {
	if folderPath != "/" && c.conn.User.HasAnyPerm([]string{
		dataprovider.PermDelete,
		dataprovider.PermDeleteDirs,
	}, path.Dir(folderPath),
	) {
		files, err := c.conn.ListDir(folderPath)
		if err == nil && len(files) == 0 {
			err = c.conn.RemoveDir(folderPath)
			c.conn.Log(logger.LevelDebug, "tryed to remove empty dir %#v, error: %v", folderPath, err)
		}
	}
}

// Start starts the retention check
func (c *RetentionCheck) Start() {
	c.conn.Log(logger.LevelInfo, "retention check started")
	defer RetentionChecks.remove(c.conn.User.Username)
	defer c.conn.CloseFS() //nolint:errcheck

	startTime := time.Now()
	for _, folder := range c.Folders {
		if folder.Retention > 0 {
			if err := c.cleanupFolder(folder.Path); err != nil {
				c.conn.Log(logger.LevelError, "retention check failed, unable to cleanup folder %#v", folder.Path)
				c.sendNotifications(time.Since(startTime), err)
				return
			}
		}
	}

	c.conn.Log(logger.LevelInfo, "retention check completed")
	c.sendNotifications(time.Since(startTime), nil)
}

func (c *RetentionCheck) sendNotifications(elapsed time.Duration, err error) {
	for _, notification := range c.Notifications {
		switch notification {
		case RetentionCheckNotificationEmail:
			c.sendEmailNotification(elapsed, err) //nolint:errcheck
		case RetentionCheckNotificationHook:
			c.sendHookNotification(elapsed, err) //nolint:errcheck
		}
	}
}

func (c *RetentionCheck) sendEmailNotification(elapsed time.Duration, errCheck error) error {
	body := new(bytes.Buffer)
	data := make(map[string]interface{})
	data["Results"] = c.results
	totalDeletedFiles := 0
	totalDeletedSize := int64(0)
	for _, result := range c.results {
		totalDeletedFiles += result.DeletedFiles
		totalDeletedSize += result.DeletedSize
	}
	data["HumanizeSize"] = util.ByteCountIEC
	data["TotalFiles"] = totalDeletedFiles
	data["TotalSize"] = totalDeletedSize
	data["Elapsed"] = elapsed
	data["Username"] = c.conn.User.Username
	data["StartTime"] = util.GetTimeFromMsecSinceEpoch(c.StartTime)
	if errCheck == nil {
		data["Status"] = "Succeeded"
	} else {
		data["Status"] = "Failed"
	}
	if err := smtp.RenderRetentionReportTemplate(body, data); err != nil {
		c.conn.Log(logger.LevelError, "unable to render retention check template: %v", err)
		return err
	}
	startTime := time.Now()
	subject := fmt.Sprintf("Retention check completed for user %#v", c.conn.User.Username)
	if err := smtp.SendEmail(c.Email, subject, body.String(), smtp.EmailContentTypeTextHTML); err != nil {
		c.conn.Log(logger.LevelError, "unable to notify retention check result via email: %v, elapsed: %v", err,
			time.Since(startTime))
		return err
	}
	c.conn.Log(logger.LevelInfo, "retention check result successfully notified via email, elapsed: %v", time.Since(startTime))
	return nil
}

func (c *RetentionCheck) sendHookNotification(elapsed time.Duration, errCheck error) error {
	data := make(map[string]interface{})
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
			c.conn.Log(logger.LevelError, "invalid data retention hook %#v: %v", Config.DataRetentionHook, err)
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

		c.conn.Log(logger.LevelDebug, "notified result to URL: %#v, status code: %v, elapsed: %v err: %v",
			url.Redacted(), respCode, time.Since(startTime), err)

		return err
	}
	if !filepath.IsAbs(Config.DataRetentionHook) {
		err := fmt.Errorf("invalid data retention hook %#v", Config.DataRetentionHook)
		c.conn.Log(logger.LevelError, "%v", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.DataRetentionHook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_DATA_RETENTION_RESULT=%v", string(jsonData)))
	err := cmd.Run()

	c.conn.Log(logger.LevelDebug, "notified result using command: %v, elapsed: %v err: %v",
		Config.DataRetentionHook, time.Since(startTime), err)
	return err
}
