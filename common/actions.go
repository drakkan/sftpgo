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

	"github.com/sftpgo/sdk"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/plugin"
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

func handleUnconfiguredPreAction(operation string) error {
	// for pre-delete we execute the internal handling on error, so we must return errUnconfiguredAction.
	// Other pre action will deny the operation on error so if we have no configuration we must return
	// a nil error
	if operation == operationPreDelete {
		return errUnconfiguredAction
	}
	return nil
}

// ExecutePreAction executes a pre-* action and returns the result
func ExecutePreAction(conn *BaseConnection, operation, filePath, virtualPath string, fileSize int64, openFlags int) error {
	var event *notifier.FsEvent
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	hasHook := util.IsStringInSlice(operation, Config.Actions.ExecuteOn)
	if !hasHook && !hasNotifiersPlugin {
		return handleUnconfiguredPreAction(operation)
	}
	event = newActionNotification(&conn.User, operation, filePath, virtualPath, "", "", "",
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, openFlags, nil)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(event)
	}
	if !hasHook {
		return handleUnconfiguredPreAction(operation)
	}
	return actionHandler.Handle(event)
}

// ExecuteActionNotification executes the defined hook, if any, for the specified action
func ExecuteActionNotification(conn *BaseConnection, operation, filePath, virtualPath, target, virtualTarget, sshCmd string,
	fileSize int64, err error,
) {
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	hasHook := util.IsStringInSlice(operation, Config.Actions.ExecuteOn)
	if !hasHook && !hasNotifiersPlugin {
		return
	}
	notification := newActionNotification(&conn.User, operation, filePath, virtualPath, target, virtualTarget, sshCmd,
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, 0, err)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(notification)
	}

	if hasHook {
		if util.IsStringInSlice(operation, Config.Actions.ExecuteSync) {
			actionHandler.Handle(notification) //nolint:errcheck
			return
		}

		go actionHandler.Handle(notification) //nolint:errcheck
	}
}

// ActionHandler handles a notification for a Protocol Action.
type ActionHandler interface {
	Handle(notification *notifier.FsEvent) error
}

func newActionNotification(
	user *dataprovider.User,
	operation, filePath, virtualPath, target, virtualTarget, sshCmd, protocol, ip, sessionID string,
	fileSize int64,
	openFlags int,
	err error,
) *notifier.FsEvent {
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

	return &notifier.FsEvent{
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
		SessionID:         sessionID,
		OpenFlags:         openFlags,
		Timestamp:         time.Now().UnixNano(),
	}
}

type defaultActionHandler struct{}

func (h *defaultActionHandler) Handle(event *notifier.FsEvent) error {
	if !util.IsStringInSlice(event.Action, Config.Actions.ExecuteOn) {
		return errUnconfiguredAction
	}

	if Config.Actions.Hook == "" {
		logger.Warn(event.Protocol, "", "Unable to send notification, no hook is defined")

		return errNoHook
	}

	if strings.HasPrefix(Config.Actions.Hook, "http") {
		return h.handleHTTP(event)
	}

	return h.handleCommand(event)
}

func (h *defaultActionHandler) handleHTTP(event *notifier.FsEvent) error {
	u, err := url.Parse(Config.Actions.Hook)
	if err != nil {
		logger.Error(event.Protocol, "", "Invalid hook %#v for operation %#v: %v",
			Config.Actions.Hook, event.Action, err)
		return err
	}

	startTime := time.Now()
	respCode := 0

	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(event)

	resp, err := httpclient.RetryablePost(Config.Actions.Hook, "application/json", &b)
	if err == nil {
		respCode = resp.StatusCode
		resp.Body.Close()

		if respCode != http.StatusOK {
			err = errUnexpectedHTTResponse
		}
	}

	logger.Debug(event.Protocol, "", "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v",
		event.Action, u.Redacted(), respCode, time.Since(startTime), err)

	return err
}

func (h *defaultActionHandler) handleCommand(event *notifier.FsEvent) error {
	if !filepath.IsAbs(Config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", Config.Actions.Hook)
		logger.Warn(event.Protocol, "", "unable to execute notification command: %v", err)

		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.Actions.Hook)
	cmd.Env = append(os.Environ(), notificationAsEnvVars(event)...)

	startTime := time.Now()
	err := cmd.Run()

	logger.Debug(event.Protocol, "", "executed command %#v, elapsed: %v, error: %v",
		Config.Actions.Hook, time.Since(startTime), err)

	return err
}

func notificationAsEnvVars(event *notifier.FsEvent) []string {
	return []string{
		fmt.Sprintf("SFTPGO_ACTION=%v", event.Action),
		fmt.Sprintf("SFTPGO_ACTION_USERNAME=%v", event.Username),
		fmt.Sprintf("SFTPGO_ACTION_PATH=%v", event.Path),
		fmt.Sprintf("SFTPGO_ACTION_TARGET=%v", event.TargetPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_PATH=%v", event.VirtualPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_TARGET=%v", event.VirtualTargetPath),
		fmt.Sprintf("SFTPGO_ACTION_SSH_CMD=%v", event.SSHCmd),
		fmt.Sprintf("SFTPGO_ACTION_FILE_SIZE=%v", event.FileSize),
		fmt.Sprintf("SFTPGO_ACTION_FS_PROVIDER=%v", event.FsProvider),
		fmt.Sprintf("SFTPGO_ACTION_BUCKET=%v", event.Bucket),
		fmt.Sprintf("SFTPGO_ACTION_ENDPOINT=%v", event.Endpoint),
		fmt.Sprintf("SFTPGO_ACTION_STATUS=%v", event.Status),
		fmt.Sprintf("SFTPGO_ACTION_PROTOCOL=%v", event.Protocol),
		fmt.Sprintf("SFTPGO_ACTION_IP=%v", event.IP),
		fmt.Sprintf("SFTPGO_ACTION_SESSION_ID=%v", event.SessionID),
		fmt.Sprintf("SFTPGO_ACTION_OPEN_FLAGS=%v", event.OpenFlags),
		fmt.Sprintf("SFTPGO_ACTION_TIMESTAMP=%v", event.Timestamp),
	}
}
