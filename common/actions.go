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

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/sdk"
	"github.com/drakkan/sftpgo/v2/sdk/plugin"
	"github.com/drakkan/sftpgo/v2/util"
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
	// Actions to be performed synchronously.
	// The pre-delete action is always executed synchronously while the other ones are asynchronous.
	// Executing an action synchronously means that SFTPGo will not return a result code to the client
	// (which is waiting for it) until your hook have completed its execution.
	ExecuteSync []string `json:"execute_sync" mapstructure:"execute_sync"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

var actionHandler ActionHandler = &defaultActionHandler{}

// InitializeActionHandler lets the user choose an action handler implementation.
//
// Do NOT call this function after application initialization.
func InitializeActionHandler(handler ActionHandler) {
	actionHandler = handler
}

// ExecutePreAction executes a pre-* action and returns the result
func ExecutePreAction(user *dataprovider.User, operation, filePath, virtualPath, protocol, ip string, fileSize int64,
	openFlags int,
) error {
	plugin.Handler.NotifyFsEvent(time.Now().UnixNano(), operation, user.Username, filePath, "", "", protocol, ip, virtualPath, "", fileSize, nil)
	if !util.IsStringInSlice(operation, Config.Actions.ExecuteOn) {
		// for pre-delete we execute the internal handling on error, so we must return errUnconfiguredAction.
		// Other pre action will deny the operation on error so if we have no configuration we must return
		// a nil error
		if operation == operationPreDelete {
			return errUnconfiguredAction
		}
		return nil
	}
	notification := newActionNotification(user, operation, filePath, virtualPath, "", "", "", protocol, ip, fileSize,
		openFlags, nil)
	return actionHandler.Handle(notification)
}

// ExecuteActionNotification executes the defined hook, if any, for the specified action
func ExecuteActionNotification(user *dataprovider.User, operation, filePath, virtualPath, target, virtualTarget, sshCmd,
	protocol, ip string, fileSize int64, err error,
) {
	plugin.Handler.NotifyFsEvent(time.Now().UnixNano(), operation, user.Username, filePath, target, sshCmd, protocol, ip, virtualPath,
		virtualTarget, fileSize, err)
	notification := newActionNotification(user, operation, filePath, virtualPath, target, virtualTarget, sshCmd, protocol,
		ip, fileSize, 0, err)

	if util.IsStringInSlice(operation, Config.Actions.ExecuteSync) {
		actionHandler.Handle(notification) //nolint:errcheck
		return
	}

	go actionHandler.Handle(notification) //nolint:errcheck
}

// ActionHandler handles a notification for a Protocol Action.
type ActionHandler interface {
	Handle(notification *ActionNotification) error
}

// ActionNotification defines a notification for a Protocol Action.
type ActionNotification struct {
	Action            string `json:"action"`
	Username          string `json:"username"`
	Path              string `json:"path"`
	TargetPath        string `json:"target_path,omitempty"`
	VirtualPath       string `json:"virtual_path"`
	VirtualTargetPath string `json:"virtual_target_path,omitempty"`
	SSHCmd            string `json:"ssh_cmd,omitempty"`
	FileSize          int64  `json:"file_size,omitempty"`
	FsProvider        int    `json:"fs_provider"`
	Bucket            string `json:"bucket,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	Status            int    `json:"status"`
	Protocol          string `json:"protocol"`
	IP                string `json:"ip"`
	Timestamp         int64  `json:"timestamp"`
	OpenFlags         int    `json:"open_flags,omitempty"`
}

func newActionNotification(
	user *dataprovider.User,
	operation, filePath, virtualPath, target, virtualTarget, sshCmd, protocol, ip string,
	fileSize int64,
	openFlags int,
	err error,
) *ActionNotification {
	var bucket, endpoint string
	status := 1

	fsConfig := user.GetFsConfigForPath(virtualPath)

	switch fsConfig.Provider {
	case sdk.S3FilesystemProvider:
		bucket = fsConfig.S3Config.Bucket
		endpoint = fsConfig.S3Config.Endpoint
	case sdk.GCSFilesystemProvider:
		bucket = fsConfig.GCSConfig.Bucket
	case sdk.AzureBlobFilesystemProvider:
		bucket = fsConfig.AzBlobConfig.Container
		if fsConfig.AzBlobConfig.Endpoint != "" {
			endpoint = fsConfig.AzBlobConfig.Endpoint
		}
	case sdk.SFTPFilesystemProvider:
		endpoint = fsConfig.SFTPConfig.Endpoint
	}

	if err == ErrQuotaExceeded {
		status = 3
	} else if err != nil {
		status = 2
	}

	return &ActionNotification{
		Action:            operation,
		Username:          user.Username,
		Path:              filePath,
		TargetPath:        target,
		VirtualPath:       virtualPath,
		VirtualTargetPath: virtualTarget,
		SSHCmd:            sshCmd,
		FileSize:          fileSize,
		FsProvider:        int(fsConfig.Provider),
		Bucket:            bucket,
		Endpoint:          endpoint,
		Status:            status,
		Protocol:          protocol,
		IP:                ip,
		OpenFlags:         openFlags,
		Timestamp:         time.Now().UnixNano(),
	}
}

type defaultActionHandler struct{}

func (h *defaultActionHandler) Handle(notification *ActionNotification) error {
	if !util.IsStringInSlice(notification.Action, Config.Actions.ExecuteOn) {
		return errUnconfiguredAction
	}

	if Config.Actions.Hook == "" {
		logger.Warn(notification.Protocol, "", "Unable to send notification, no hook is defined")

		return errNoHook
	}

	if strings.HasPrefix(Config.Actions.Hook, "http") {
		return h.handleHTTP(notification)
	}

	return h.handleCommand(notification)
}

func (h *defaultActionHandler) handleHTTP(notification *ActionNotification) error {
	u, err := url.Parse(Config.Actions.Hook)
	if err != nil {
		logger.Warn(notification.Protocol, "", "Invalid hook %#v for operation %#v: %v", Config.Actions.Hook, notification.Action, err)
		return err
	}

	startTime := time.Now()
	respCode := 0

	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(notification)

	resp, err := httpclient.RetryablePost(Config.Actions.Hook, "application/json", &b)
	if err == nil {
		respCode = resp.StatusCode
		resp.Body.Close()

		if respCode != http.StatusOK {
			err = errUnexpectedHTTResponse
		}
	}

	logger.Debug(notification.Protocol, "", "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v",
		notification.Action, u.Redacted(), respCode, time.Since(startTime), err)

	return err
}

func (h *defaultActionHandler) handleCommand(notification *ActionNotification) error {
	if !filepath.IsAbs(Config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", Config.Actions.Hook)
		logger.Warn(notification.Protocol, "", "unable to execute notification command: %v", err)

		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.Actions.Hook)
	cmd.Env = append(os.Environ(), notificationAsEnvVars(notification)...)

	startTime := time.Now()
	err := cmd.Run()

	logger.Debug(notification.Protocol, "", "executed command %#v, elapsed: %v, error: %v",
		Config.Actions.Hook, time.Since(startTime), err)

	return err
}

func notificationAsEnvVars(notification *ActionNotification) []string {
	return []string{
		fmt.Sprintf("SFTPGO_ACTION=%v", notification.Action),
		fmt.Sprintf("SFTPGO_ACTION_USERNAME=%v", notification.Username),
		fmt.Sprintf("SFTPGO_ACTION_PATH=%v", notification.Path),
		fmt.Sprintf("SFTPGO_ACTION_TARGET=%v", notification.TargetPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_PATH=%v", notification.VirtualPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_TARGET=%v", notification.VirtualTargetPath),
		fmt.Sprintf("SFTPGO_ACTION_SSH_CMD=%v", notification.SSHCmd),
		fmt.Sprintf("SFTPGO_ACTION_FILE_SIZE=%v", notification.FileSize),
		fmt.Sprintf("SFTPGO_ACTION_FS_PROVIDER=%v", notification.FsProvider),
		fmt.Sprintf("SFTPGO_ACTION_BUCKET=%v", notification.Bucket),
		fmt.Sprintf("SFTPGO_ACTION_ENDPOINT=%v", notification.Endpoint),
		fmt.Sprintf("SFTPGO_ACTION_STATUS=%v", notification.Status),
		fmt.Sprintf("SFTPGO_ACTION_PROTOCOL=%v", notification.Protocol),
		fmt.Sprintf("SFTPGO_ACTION_IP=%v", notification.IP),
		fmt.Sprintf("SFTPGO_ACTION_OPEN_FLAGS=%v", notification.OpenFlags),
		fmt.Sprintf("SFTPGO_ACTION_TIMESTAMP=%v", notification.Timestamp),
	}
}
