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
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	errUnexpectedHTTResponse = errors.New("unexpected HTTP hook response code")
	hooksConcurrencyGuard    = make(chan struct{}, 150)
	activeHooks              atomic.Int32
)

func startNewHook() {
	activeHooks.Add(1)
	hooksConcurrencyGuard <- struct{}{}
}

func hookEnded() {
	activeHooks.Add(-1)
	<-hooksConcurrencyGuard
}

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

// ExecutePreAction executes a pre-* action and returns the result.
// The returned status has the following meaning:
// - 0 not executed
// - 1 executed using an external hook
// - 2 executed using the event manager
func ExecutePreAction(conn *BaseConnection, operation, filePath, virtualPath string, fileSize int64, openFlags int) (int, error) {
	var event *notifier.FsEvent
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	hasHook := util.Contains(Config.Actions.ExecuteOn, operation)
	hasRules := eventManager.hasFsRules()
	if !hasHook && !hasNotifiersPlugin && !hasRules {
		return 0, nil
	}
	event = newActionNotification(&conn.User, operation, filePath, virtualPath, "", "", "",
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, openFlags, conn.getNotificationStatus(nil), 0, nil)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(event)
	}
	if hasRules {
		params := EventParams{
			Name:              event.Username,
			Groups:            conn.User.Groups,
			Event:             event.Action,
			Status:            event.Status,
			VirtualPath:       event.VirtualPath,
			FsPath:            event.Path,
			VirtualTargetPath: event.VirtualTargetPath,
			FsTargetPath:      event.TargetPath,
			ObjectName:        path.Base(event.VirtualPath),
			Extension:         path.Ext(event.VirtualPath),
			FileSize:          event.FileSize,
			Protocol:          event.Protocol,
			IP:                event.IP,
			Role:              event.Role,
			Timestamp:         event.Timestamp,
			Email:             conn.User.Email,
			Object:            nil,
		}
		executedSync, err := eventManager.handleFsEvent(params)
		if executedSync {
			return 2, err
		}
	}
	if !hasHook {
		return 0, nil
	}
	return actionHandler.Handle(event)
}

// ExecuteActionNotification executes the defined hook, if any, for the specified action
func ExecuteActionNotification(conn *BaseConnection, operation, filePath, virtualPath, target, virtualTarget, sshCmd string,
	fileSize int64, err error, elapsed int64, metadata map[string]string,
) error {
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	hasHook := util.Contains(Config.Actions.ExecuteOn, operation)
	hasRules := eventManager.hasFsRules()
	if !hasHook && !hasNotifiersPlugin && !hasRules {
		return nil
	}
	notification := newActionNotification(&conn.User, operation, filePath, virtualPath, target, virtualTarget, sshCmd,
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, 0, conn.getNotificationStatus(err), elapsed, metadata)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(notification)
	}
	if hasRules {
		params := EventParams{
			Name:              notification.Username,
			Groups:            conn.User.Groups,
			Event:             notification.Action,
			Status:            notification.Status,
			VirtualPath:       notification.VirtualPath,
			FsPath:            notification.Path,
			VirtualTargetPath: notification.VirtualTargetPath,
			FsTargetPath:      notification.TargetPath,
			ObjectName:        path.Base(notification.VirtualPath),
			Extension:         path.Ext(notification.VirtualPath),
			FileSize:          notification.FileSize,
			Elapsed:           notification.Elapsed,
			Protocol:          notification.Protocol,
			IP:                notification.IP,
			Role:              notification.Role,
			Timestamp:         notification.Timestamp,
			Email:             conn.User.Email,
			Object:            nil,
			Metadata:          metadata,
		}
		if err != nil {
			params.AddError(fmt.Errorf("%q failed: %w", params.Event, err))
		}
		executedSync, err := eventManager.handleFsEvent(params)
		if executedSync {
			return err
		}
	}
	if hasHook {
		if util.Contains(Config.Actions.ExecuteSync, operation) {
			_, err := actionHandler.Handle(notification)
			return err
		}
		go func() {
			startNewHook()
			defer hookEnded()

			actionHandler.Handle(notification) //nolint:errcheck
		}()
	}
	return nil
}

// ActionHandler handles a notification for a Protocol Action.
type ActionHandler interface {
	Handle(notification *notifier.FsEvent) (int, error)
}

func newActionNotification(
	user *dataprovider.User,
	operation, filePath, virtualPath, target, virtualTarget, sshCmd, protocol, ip, sessionID string,
	fileSize int64,
	openFlags, status int, elapsed int64,
	metadata map[string]string,
) *notifier.FsEvent {
	var bucket, endpoint string

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
	case sdk.HTTPFilesystemProvider:
		endpoint = fsConfig.HTTPConfig.Endpoint
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
		Role:              user.Role,
		Timestamp:         time.Now().UnixNano(),
		Elapsed:           elapsed,
		Metadata:          metadata,
	}
}

type defaultActionHandler struct{}

func (h *defaultActionHandler) Handle(event *notifier.FsEvent) (int, error) {
	if !util.Contains(Config.Actions.ExecuteOn, event.Action) {
		return 0, nil
	}

	if Config.Actions.Hook == "" {
		logger.Warn(event.Protocol, "", "Unable to send notification, no hook is defined")

		return 0, nil
	}

	if strings.HasPrefix(Config.Actions.Hook, "http") {
		err := h.handleHTTP(event)
		return 1, err
	}

	err := h.handleCommand(event)
	return 1, err
}

func (h *defaultActionHandler) handleHTTP(event *notifier.FsEvent) error {
	u, err := url.Parse(Config.Actions.Hook)
	if err != nil {
		logger.Error(event.Protocol, "", "Invalid hook %q for operation %q: %v",
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

	logger.Debug(event.Protocol, "", "notified operation %q to URL: %s status code: %d, elapsed: %s err: %v",
		event.Action, u.Redacted(), respCode, time.Since(startTime), err)

	return err
}

func (h *defaultActionHandler) handleCommand(event *notifier.FsEvent) error {
	if !filepath.IsAbs(Config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %q", Config.Actions.Hook)
		logger.Warn(event.Protocol, "", "unable to execute notification command: %v", err)

		return err
	}

	timeout, env, args := command.GetConfig(Config.Actions.Hook, command.HookFsActions)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.Actions.Hook, args...)
	cmd.Env = append(env, notificationAsEnvVars(event)...)

	startTime := time.Now()
	err := cmd.Run()

	logger.Debug(event.Protocol, "", "executed command %q, elapsed: %s, error: %v",
		Config.Actions.Hook, time.Since(startTime), err)

	return err
}

func notificationAsEnvVars(event *notifier.FsEvent) []string {
	result := []string{
		fmt.Sprintf("SFTPGO_ACTION=%s", event.Action),
		fmt.Sprintf("SFTPGO_ACTION_USERNAME=%s", event.Username),
		fmt.Sprintf("SFTPGO_ACTION_PATH=%s", event.Path),
		fmt.Sprintf("SFTPGO_ACTION_TARGET=%s", event.TargetPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_PATH=%s", event.VirtualPath),
		fmt.Sprintf("SFTPGO_ACTION_VIRTUAL_TARGET=%s", event.VirtualTargetPath),
		fmt.Sprintf("SFTPGO_ACTION_SSH_CMD=%s", event.SSHCmd),
		fmt.Sprintf("SFTPGO_ACTION_FILE_SIZE=%d", event.FileSize),
		fmt.Sprintf("SFTPGO_ACTION_ELAPSED=%d", event.Elapsed),
		fmt.Sprintf("SFTPGO_ACTION_FS_PROVIDER=%d", event.FsProvider),
		fmt.Sprintf("SFTPGO_ACTION_BUCKET=%s", event.Bucket),
		fmt.Sprintf("SFTPGO_ACTION_ENDPOINT=%s", event.Endpoint),
		fmt.Sprintf("SFTPGO_ACTION_STATUS=%d", event.Status),
		fmt.Sprintf("SFTPGO_ACTION_PROTOCOL=%s", event.Protocol),
		fmt.Sprintf("SFTPGO_ACTION_IP=%s", event.IP),
		fmt.Sprintf("SFTPGO_ACTION_SESSION_ID=%s", event.SessionID),
		fmt.Sprintf("SFTPGO_ACTION_OPEN_FLAGS=%d", event.OpenFlags),
		fmt.Sprintf("SFTPGO_ACTION_TIMESTAMP=%d", event.Timestamp),
		fmt.Sprintf("SFTPGO_ACTION_ROLE=%s", event.Role),
	}
	if len(event.Metadata) > 0 {
		data, err := json.Marshal(event.Metadata)
		if err == nil {
			result = append(result, fmt.Sprintf("SFTPGO_ACTION_METADATA=%s", string(data)))
		}
	}
	return result
}
