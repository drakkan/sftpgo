package dataprovider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
)

const (
	// ActionExecutorSelf is used as username for self action, for example a user/admin that updates itself
	ActionExecutorSelf = "__self__"
	// ActionExecutorSystem is used as username for actions with no explicit executor associated, for example
	// adding/updating a user/admin by loading initial data
	ActionExecutorSystem = "__system__"
)

const (
	actionObjectUser   = "user"
	actionObjectAdmin  = "admin"
	actionObjectAPIKey = "api_key"
	actionObjectShare  = "share"
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
	if config.Actions.Hook == "" {
		return
	}
	if !util.IsStringInSlice(operation, config.Actions.ExecuteOn) ||
		!util.IsStringInSlice(objectType, config.Actions.ExecuteFor) {
		return
	}

	go func() {
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
			q.Add("timestamp", fmt.Sprintf("%v", time.Now().UnixNano()))
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, config.Actions.Hook)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SFTPGO_PROVIDER_ACTION=%v", operation),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT_TYPE=%v", objectType),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT_NAME=%v", objectName),
		fmt.Sprintf("SFTPGO_PROVIDER_USERNAME=%v", executor),
		fmt.Sprintf("SFTPGO_PROVIDER_IP=%v", ip),
		fmt.Sprintf("SFTPGO_PROVIDER_TIMESTAMP=%v", util.GetTimeAsMsSinceEpoch(time.Now())),
		fmt.Sprintf("SFTPGO_PROVIDER_OBJECT=%v", string(objectAsJSON)))

	startTime := time.Now()
	err := cmd.Run()
	providerLog(logger.LevelDebug, "executed command %#v, elapsed: %v, error: %v", config.Actions.Hook,
		time.Since(startTime), err)
	return err
}
