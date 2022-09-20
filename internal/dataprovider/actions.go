// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	// ActionExecutorSelf is used as username for self action, for example a user/admin that updates itself
	ActionExecutorSelf = "__self__"
	// ActionExecutorSystem is used as username for actions with no explicit executor associated, for example
	// adding/updating a user/admin by loading initial data
	ActionExecutorSystem = "__system__"
)

const (
	actionObjectUser        = "user"
	actionObjectFolder      = "folder"
	actionObjectGroup       = "group"
	actionObjectAdmin       = "admin"
	actionObjectAPIKey      = "api_key"
	actionObjectShare       = "share"
	actionObjectEventAction = "event_action"
	actionObjectEventRule   = "event_rule"
)

var (
	actionsConcurrencyGuard = make(chan struct{}, 100)
	reservedUsers           = []string{ActionExecutorSelf, ActionExecutorSystem}
)

func executeAction(operation, executor, ip, objectType, objectName string, object plugin.Renderer) {
	if plugin.Handler.HasNotifiers() {
		plugin.Handler.NotifyProviderEvent(&notifier.ProviderEvent{
			Action:     operation,
			Username:   executor,
			ObjectType: objectType,
			ObjectName: objectName,
			IP:         ip,
			Timestamp:  time.Now().UnixNano(),
		}, object)
	}
	if fnHandleRuleForProviderEvent != nil {
		fnHandleRuleForProviderEvent(operation, executor, ip, objectType, objectName, object)
	}
	if config.Actions.Hook == "" {
		return
	}
	if !util.Contains(config.Actions.ExecuteOn, operation) ||
		!util.Contains(config.Actions.ExecuteFor, objectType) {
		return
	}

	go func() {
		actionsConcurrencyGuard <- struct{}{}
		defer func() {
			<-actionsConcurrencyGuard
		}()

		dataAsJSON, err := object.RenderAsJSON(operation != operationDelete)
		if err != nil {
			providerLog(logger.LevelError, "unable to serialize user as JSON for operation %#v: %v", operation, err)
			return
		}
		if strings.HasPrefix(config.Actions.Hook, "http") {
			var url *url.URL
			url, err := url.Parse(config.Actions.Hook)
			if err != nil {
				providerLog(logger.LevelError, "Invalid http_notification_url %#v for operation %#v: %v",
					config.Actions.Hook, operation, err)
				return
			}
			q := url.Query()
			q.Add("action", operation)
			q.Add("username", executor)
			q.Add("ip", ip)
			q.Add("object_type", objectType)
			q.Add("object_name", objectName)
			q.Add("timestamp", fmt.Sprintf("%d", time.Now().UnixNano()))
			url.RawQuery = q.Encode()
			startTime := time.Now()
			resp, err := httpclient.RetryablePost(url.String(), "application/json", bytes.NewBuffer(dataAsJSON))
			respCode := 0
			if err == nil {
				respCode = resp.StatusCode
				resp.Body.Close()
			}
			providerLog(logger.LevelDebug, "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v",
				operation, url.Redacted(), respCode, time.Since(startTime), err)
		} else {
			executeNotificationCommand(operation, executor, ip, objectType, objectName, dataAsJSON) //nolint:errcheck // the error is used in test cases only
		}
	}()
}

func executeNotificationCommand(operation, executor, ip, objectType, objectName string, objectAsJSON []byte) error {
	if !filepath.IsAbs(config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", config.Actions.Hook)
		logger.Warn(logSender, "", "unable to execute notification command: %v", err)
		return err
	}

	timeout, env, args := command.GetConfig(config.Actions.Hook, command.HookProviderActions)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.Actions.Hook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPGO_PROVIDER_ACTION=%vs", operation),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT_TYPE=%s", objectType),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT_NAME=%s", objectName),
		fmt.Sprintf("SFTPGO_PROVIDER_USERNAME=%s", executor),
		fmt.Sprintf("SFTPGO_PROVIDER_IP=%s", ip),
		fmt.Sprintf("SFTPGO_PROVIDER_TIMESTAMP=%d", util.GetTimeAsMsSinceEpoch(time.Now())),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT=%s", string(objectAsJSON)))

	startTime := time.Now()
	err := cmd.Run()
	providerLog(logger.LevelDebug, "executed command %#v, elapsed: %v, error: %v", config.Actions.Hook,
		time.Since(startTime), err)
	return err
}
