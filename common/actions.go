package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

var (
	errUnconfiguredAction    = errors.New("no hook is configured for this action")
	errNoHook                = errors.New("unable to execute action, no hook defined")
	errUnexpectedHTTResponse = errors.New("unexpected HTTP response code")
)

// ProtocolActions defines the action to execute on file operations and SSH commands
type ProtocolActions struct {
	// Valid values are download, upload, pre-delete, delete, rename, ssh_cmd. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

// actionNotification defines a notification for a Protocol Action
type actionNotification struct {
	Action     string `json:"action"`
	Username   string `json:"username"`
	Path       string `json:"path"`
	TargetPath string `json:"target_path,omitempty"`
	SSHCmd     string `json:"ssh_cmd,omitempty"`
	FileSize   int64  `json:"file_size,omitempty"`
	FsProvider int    `json:"fs_provider"`
	Bucket     string `json:"bucket,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Status     int    `json:"status"`
	Protocol   string `json:"protocol"`
}

// SSHCommandActionNotification executes the defined action for the specified SSH command
func SSHCommandActionNotification(user *dataprovider.User, filePath, target, sshCmd string, err error) {
	action := newActionNotification(user, operationSSHCmd, filePath, target, sshCmd, ProtocolSSH, 0, err)
	go action.execute() //nolint:errcheck
}

func newActionNotification(user *dataprovider.User, operation, filePath, target, sshCmd, protocol string, fileSize int64,
	err error) actionNotification {
	bucket := ""
	endpoint := ""
	status := 1
	if user.FsConfig.Provider == dataprovider.S3FilesystemProvider {
		bucket = user.FsConfig.S3Config.Bucket
		endpoint = user.FsConfig.S3Config.Endpoint
	} else if user.FsConfig.Provider == dataprovider.GCSFilesystemProvider {
		bucket = user.FsConfig.GCSConfig.Bucket
	}
	if err == ErrQuotaExceeded {
		status = 2
	} else if err != nil {
		status = 0
	}
	return actionNotification{
		Action:     operation,
		Username:   user.Username,
		Path:       filePath,
		TargetPath: target,
		SSHCmd:     sshCmd,
		FileSize:   fileSize,
		FsProvider: int(user.FsConfig.Provider),
		Bucket:     bucket,
		Endpoint:   endpoint,
		Status:     status,
		Protocol:   protocol,
	}
}

func (a *actionNotification) asJSON() []byte {
	res, _ := json.Marshal(a)
	return res
}

func (a *actionNotification) asEnvVars() []string {
	return []string{fmt.Sprintf("SFTPGO_ACTION=%v", a.Action),
		fmt.Sprintf("SFTPGO_ACTION_USERNAME=%v", a.Username),
		fmt.Sprintf("SFTPGO_ACTION_PATH=%v", a.Path),
		fmt.Sprintf("SFTPGO_ACTION_TARGET=%v", a.TargetPath),
		fmt.Sprintf("SFTPGO_ACTION_SSH_CMD=%v", a.SSHCmd),
		fmt.Sprintf("SFTPGO_ACTION_FILE_SIZE=%v", a.FileSize),
		fmt.Sprintf("SFTPGO_ACTION_FS_PROVIDER=%v", a.FsProvider),
		fmt.Sprintf("SFTPGO_ACTION_BUCKET=%v", a.Bucket),
		fmt.Sprintf("SFTPGO_ACTION_ENDPOINT=%v", a.Endpoint),
		fmt.Sprintf("SFTPGO_ACTION_STATUS=%v", a.Status),
		fmt.Sprintf("SFTPGO_ACTION_PROTOCOL=%v", a.Protocol),
	}
}

func (a *actionNotification) executeNotificationCommand() error {
	if !filepath.IsAbs(Config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", Config.Actions.Hook)
		logger.Warn(a.Protocol, "", "unable to execute notification command: %v", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, Config.Actions.Hook, a.Action, a.Username, a.Path, a.TargetPath, a.SSHCmd)
	cmd.Env = append(os.Environ(), a.asEnvVars()...)
	startTime := time.Now()
	err := cmd.Run()
	logger.Debug(a.Protocol, "", "executed command %#v with arguments: %#v, %#v, %#v, %#v, %#v, elapsed: %v, error: %v",
		Config.Actions.Hook, a.Action, a.Username, a.Path, a.TargetPath, a.SSHCmd, time.Since(startTime), err)
	return err
}

func (a *actionNotification) execute() error {
	if !utils.IsStringInSlice(a.Action, Config.Actions.ExecuteOn) {
		return errUnconfiguredAction
	}
	if len(Config.Actions.Hook) == 0 {
		logger.Warn(a.Protocol, "", "Unable to send notification, no hook is defined")
		return errNoHook
	}
	if strings.HasPrefix(Config.Actions.Hook, "http") {
		var url *url.URL
		url, err := url.Parse(Config.Actions.Hook)
		if err != nil {
			logger.Warn(a.Protocol, "", "Invalid hook %#v for operation %#v: %v", Config.Actions.Hook, a.Action, err)
			return err
		}
		startTime := time.Now()
		httpClient := httpclient.GetHTTPClient()
		resp, err := httpClient.Post(url.String(), "application/json", bytes.NewBuffer(a.asJSON()))
		respCode := 0
		if err == nil {
			respCode = resp.StatusCode
			resp.Body.Close()
			if respCode != http.StatusOK {
				err = errUnexpectedHTTResponse
			}
		}
		logger.Debug(a.Protocol, "", "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v",
			a.Action, url.String(), respCode, time.Since(startTime), err)
		return err
	}
	return a.executeNotificationCommand()
}
