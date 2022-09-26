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

package common

import (
	"crypto/rand"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func TestEventRuleMatch(t *testing.T) {
	conditions := dataprovider.EventConditions{
		ProviderEvents: []string{"add", "update"},
		Options: dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern:      "user1",
					InverseMatch: true,
				},
			},
		},
	}
	res := eventManager.checkProviderEventMatch(conditions, EventParams{
		Name:  "user1",
		Event: "add",
	})
	assert.False(t, res)
	res = eventManager.checkProviderEventMatch(conditions, EventParams{
		Name:  "user2",
		Event: "update",
	})
	assert.True(t, res)
	res = eventManager.checkProviderEventMatch(conditions, EventParams{
		Name:  "user2",
		Event: "delete",
	})
	assert.False(t, res)
	conditions.Options.ProviderObjects = []string{"api_key"}
	res = eventManager.checkProviderEventMatch(conditions, EventParams{
		Name:       "user2",
		Event:      "update",
		ObjectType: "share",
	})
	assert.False(t, res)
	res = eventManager.checkProviderEventMatch(conditions, EventParams{
		Name:       "user2",
		Event:      "update",
		ObjectType: "api_key",
	})
	assert.True(t, res)
	// now test fs events
	conditions = dataprovider.EventConditions{
		FsEvents: []string{operationUpload, operationDownload},
		Options: dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: "user*",
				},
				{
					Pattern: "tester*",
				},
			},
			FsPaths: []dataprovider.ConditionPattern{
				{
					Pattern: "*.txt",
				},
			},
			Protocols:   []string{ProtocolSFTP},
			MinFileSize: 10,
			MaxFileSize: 30,
		},
	}
	params := EventParams{
		Name:        "tester4",
		Event:       operationDelete,
		VirtualPath: "/path.txt",
		Protocol:    ProtocolSFTP,
		ObjectName:  "path.txt",
		FileSize:    20,
	}
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.Event = operationDownload
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.True(t, res)
	params.Name = "name"
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.Name = "user5"
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.True(t, res)
	params.VirtualPath = "/sub/f.jpg"
	params.ObjectName = path.Base(params.VirtualPath)
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.VirtualPath = "/sub/f.txt"
	params.ObjectName = path.Base(params.VirtualPath)
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.True(t, res)
	params.Protocol = ProtocolHTTP
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.Protocol = ProtocolSFTP
	params.FileSize = 5
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.FileSize = 50
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.FileSize = 25
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.True(t, res)
	// bad pattern
	conditions.Options.Names = []dataprovider.ConditionPattern{
		{
			Pattern: "[-]",
		},
	}
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	// check fs events with group name filters
	conditions = dataprovider.EventConditions{
		FsEvents: []string{operationUpload, operationDownload},
		Options: dataprovider.ConditionOptions{
			GroupNames: []dataprovider.ConditionPattern{
				{
					Pattern: "group*",
				},
				{
					Pattern: "testgroup*",
				},
			},
		},
	}
	params = EventParams{
		Name:  "user1",
		Event: operationUpload,
	}
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.Groups = []sdk.GroupMapping{
		{
			Name: "g1",
			Type: sdk.GroupTypePrimary,
		},
		{
			Name: "g2",
			Type: sdk.GroupTypeSecondary,
		},
	}
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.False(t, res)
	params.Groups = []sdk.GroupMapping{
		{
			Name: "testgroup2",
			Type: sdk.GroupTypePrimary,
		},
		{
			Name: "g2",
			Type: sdk.GroupTypeSecondary,
		},
	}
	res = eventManager.checkFsEventMatch(conditions, params)
	assert.True(t, res)
}

func TestEventManager(t *testing.T) {
	startEventScheduler()
	action := &dataprovider.BaseEventAction{
		Name: "test_action",
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint: "http://localhost",
				Timeout:  20,
				Method:   http.MethodGet,
			},
		},
	}
	err := dataprovider.AddEventAction(action, "", "")
	assert.NoError(t, err)
	rule := &dataprovider.EventRule{
		Name:    "rule",
		Trigger: dataprovider.EventTriggerFsEvent,
		Conditions: dataprovider.EventConditions{
			FsEvents: []string{operationUpload},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action.Name,
				},
				Order: 1,
			},
		},
	}

	err = dataprovider.AddEventRule(rule, "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 1)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	assert.Len(t, eventManager.schedulesMapping, 0)
	eventManager.RUnlock()

	rule.Trigger = dataprovider.EventTriggerProviderEvent
	rule.Conditions = dataprovider.EventConditions{
		ProviderEvents: []string{"add"},
	}
	err = dataprovider.UpdateEventRule(rule, "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 1)
	assert.Len(t, eventManager.Schedules, 0)
	assert.Len(t, eventManager.schedulesMapping, 0)
	eventManager.RUnlock()

	rule.Trigger = dataprovider.EventTriggerSchedule
	rule.Conditions = dataprovider.EventConditions{
		Schedules: []dataprovider.Schedule{
			{
				Hours:      "0",
				DayOfWeek:  "*",
				DayOfMonth: "*",
				Month:      "*",
			},
		},
	}
	rule.DeletedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-12 * time.Hour))
	eventManager.addUpdateRuleInternal(*rule)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	assert.Len(t, eventManager.schedulesMapping, 0)
	eventManager.RUnlock()

	assert.Eventually(t, func() bool {
		_, err = dataprovider.EventRuleExists(rule.Name)
		_, ok := err.(*util.RecordNotFoundError)
		return ok
	}, 2*time.Second, 100*time.Millisecond)

	rule.DeletedAt = 0
	err = dataprovider.AddEventRule(rule, "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 1)
	assert.Len(t, eventManager.schedulesMapping, 1)
	eventManager.RUnlock()

	err = dataprovider.DeleteEventRule(rule.Name, "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	assert.Len(t, eventManager.schedulesMapping, 0)
	eventManager.RUnlock()

	err = dataprovider.DeleteEventAction(action.Name, "", "")
	assert.NoError(t, err)
	stopEventScheduler()
}

func TestEventManagerErrors(t *testing.T) {
	startEventScheduler()
	providerConf := dataprovider.GetProviderConfig()
	err := dataprovider.Close()
	assert.NoError(t, err)

	params := EventParams{
		sender: "sender",
	}
	_, err = params.getUsers()
	assert.Error(t, err)
	_, err = params.getFolders()
	assert.Error(t, err)

	err = executeUsersQuotaResetRuleAction(dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeFoldersQuotaResetRuleAction(dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeTransferQuotaResetRuleAction(dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeMetadataCheckRuleAction(dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeDeleteFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeMkdirFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeRenameFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeExistFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)

	groupName := "agroup"
	err = executeQuotaResetForUser(dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeMetadataCheckForUser(dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeDataRetentionCheckForUser(dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	}, nil, &EventParams{}, "")
	assert.Error(t, err)
	err = executeDeleteFsActionForUser(nil, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeMkDirsFsActionForUser(nil, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeRenameFsActionForUser(nil, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeExistFsActionForUser(nil, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	_, err = getMailAttachments(dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		}}, []string{"/a", "/b"}, nil)
	assert.Error(t, err)

	_, _, err = getHTTPRuleActionBody(dataprovider.EventActionHTTPConfig{
		Method: http.MethodPost,
		Parts: []dataprovider.HTTPPart{
			{
				Name: "p1",
			},
		},
	}, nil, nil, dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
		},
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	}, &EventParams{})
	assert.Error(t, err)

	dataRetentionAction := dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeDataRetentionCheck,
		Options: dataprovider.BaseEventActionOptions{
			RetentionConfig: dataprovider.EventActionDataRetentionConfig{
				Folders: []dataprovider.FolderRetention{
					{
						Path:      "/",
						Retention: 24,
					},
				},
			},
		},
	}
	err = executeRuleAction(dataRetentionAction, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "username1",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to get users")
	}

	eventManager.loadRules()

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	eventManager.RUnlock()

	// rule with invalid trigger
	eventManager.addUpdateRuleInternal(dataprovider.EventRule{
		Name:    "test rule",
		Trigger: -1,
	})

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	eventManager.RUnlock()
	// rule with invalid cronspec
	eventManager.addUpdateRuleInternal(dataprovider.EventRule{
		Name:    "test rule",
		Trigger: dataprovider.EventTriggerSchedule,
		Conditions: dataprovider.EventConditions{
			Schedules: []dataprovider.Schedule{
				{
					Hours: "1000",
				},
			},
		},
	})
	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	eventManager.RUnlock()

	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	stopEventScheduler()
}

func TestEventRuleActions(t *testing.T) {
	actionName := "test rule action"
	action := dataprovider.BaseEventAction{
		Name: actionName,
		Type: dataprovider.ActionTypeBackup,
	}
	err := executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{})
	assert.NoError(t, err)
	action.Type = -1
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{})
	assert.Error(t, err)

	action = dataprovider.BaseEventAction{
		Name: actionName,
		Type: dataprovider.ActionTypeHTTP,
		Options: dataprovider.BaseEventActionOptions{
			HTTPConfig: dataprovider.EventActionHTTPConfig{
				Endpoint:      "http://foo\x7f.com/", // invalid URL
				SkipTLSVerify: true,
				Body:          "{{ObjectData}}",
				Method:        http.MethodPost,
				QueryParameters: []dataprovider.KeyValue{
					{
						Key:   "param",
						Value: "value",
					},
				},
				Timeout: 5,
				Headers: []dataprovider.KeyValue{
					{
						Key:   "Content-Type",
						Value: "application/json",
					},
				},
				Username: "httpuser",
			},
		},
	}
	action.Options.SetEmptySecretsIfNil()
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid endpoint")
	}
	action.Options.HTTPConfig.Endpoint = fmt.Sprintf("http://%v", httpAddr)
	params := &EventParams{
		Name: "a",
		Object: &dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username: "test user",
			},
		},
	}
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	assert.NoError(t, err)
	action.Options.HTTPConfig.Method = http.MethodGet
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	assert.NoError(t, err)
	action.Options.HTTPConfig.Endpoint = fmt.Sprintf("http://%v/404", httpAddr)
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unexpected status code: 404")
	}
	action.Options.HTTPConfig.Endpoint = "http://invalid:1234"
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	assert.Error(t, err)
	action.Options.HTTPConfig.QueryParameters = nil
	action.Options.HTTPConfig.Endpoint = "http://bar\x7f.com/"
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	assert.Error(t, err)
	action.Options.HTTPConfig.Password = kms.NewSecret(sdkkms.SecretStatusSecretBox, "payload", "key", "data")
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to decrypt HTTP password")
	}
	action.Options.HTTPConfig.Password = kms.NewEmptySecret()
	action.Options.HTTPConfig.Body = ""
	action.Options.HTTPConfig.Parts = []dataprovider.HTTPPart{
		{
			Name:     "p1",
			Filepath: "path",
		},
	}
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "error getting user")
	}
	action.Options.HTTPConfig.Parts = nil
	action.Options.HTTPConfig.Body = "{{ObjectData}}"
	// test disk and transfer quota reset
	username1 := "user1"
	username2 := "user2"
	user1 := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username1,
			HomeDir:  filepath.Join(os.TempDir(), username1),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	user2 := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username2,
			HomeDir:  filepath.Join(os.TempDir(), username2),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	err = dataprovider.AddUser(&user1, "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&user2, "", "")
	assert.NoError(t, err)

	action = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeUserQuotaReset,
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err) // no home dir
	// create the home dir
	err = os.MkdirAll(user1.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user1.GetHomeDir(), "file.txt"), []byte("user"), 0666)
	assert.NoError(t, err)
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)
	userGet, err := dataprovider.UserExists(username1)
	assert.NoError(t, err)
	assert.Equal(t, 1, userGet.UsedQuotaFiles)
	assert.Equal(t, int64(4), userGet.UsedQuotaSize)
	// simulate another quota scan in progress
	assert.True(t, QuotaScans.AddUserQuotaScan(username1))
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err)
	assert.True(t, QuotaScans.RemoveUserQuotaScan(username1))
	// non matching pattern
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "don't match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no user quota reset executed")
	}

	action = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeMetadataCheck,
	}

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "don't match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no metadata check executed")
	}

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)
	// simulate another metadata check in progress
	assert.True(t, ActiveMetadataChecks.Add(username1))
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err)
	assert.True(t, ActiveMetadataChecks.Remove(username1))

	dataRetentionAction := dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeDataRetentionCheck,
		Options: dataprovider.BaseEventActionOptions{
			RetentionConfig: dataprovider.EventActionDataRetentionConfig{
				Folders: []dataprovider.FolderRetention{
					{
						Path:      "",
						Retention: 24,
					},
				},
			},
		},
	}
	err = executeRuleAction(dataRetentionAction, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err) // invalid config, no folder path specified
	retentionDir := "testretention"
	dataRetentionAction = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeDataRetentionCheck,
		Options: dataprovider.BaseEventActionOptions{
			RetentionConfig: dataprovider.EventActionDataRetentionConfig{
				Folders: []dataprovider.FolderRetention{
					{
						Path:            path.Join("/", retentionDir),
						Retention:       24,
						DeleteEmptyDirs: true,
					},
				},
			},
		},
	}
	// create some test files
	file1 := filepath.Join(user1.GetHomeDir(), "file1.txt")
	file2 := filepath.Join(user1.GetHomeDir(), retentionDir, "file2.txt")
	file3 := filepath.Join(user1.GetHomeDir(), retentionDir, "file3.txt")
	file4 := filepath.Join(user1.GetHomeDir(), retentionDir, "sub", "file4.txt")

	err = os.MkdirAll(filepath.Dir(file4), os.ModePerm)
	assert.NoError(t, err)

	for _, f := range []string{file1, file2, file3, file4} {
		err = os.WriteFile(f, []byte(""), 0666)
		assert.NoError(t, err)
	}
	timeBeforeRetention := time.Now().Add(-48 * time.Hour)
	err = os.Chtimes(file1, timeBeforeRetention, timeBeforeRetention)
	assert.NoError(t, err)
	err = os.Chtimes(file2, timeBeforeRetention, timeBeforeRetention)
	assert.NoError(t, err)
	err = os.Chtimes(file4, timeBeforeRetention, timeBeforeRetention)
	assert.NoError(t, err)

	err = executeRuleAction(dataRetentionAction, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)
	assert.FileExists(t, file1)
	assert.NoFileExists(t, file2)
	assert.FileExists(t, file3)
	assert.NoDirExists(t, filepath.Dir(file4))
	// simulate another check in progress
	c := RetentionChecks.Add(RetentionCheck{}, &user1)
	assert.NotNil(t, c)
	err = executeRuleAction(dataRetentionAction, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err)
	RetentionChecks.remove(user1.Username)

	err = executeRuleAction(dataRetentionAction, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no retention check executed")
	}
	// test file exists action
	action = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type:  dataprovider.FilesystemActionExist,
				Exist: []string{"/file1.txt", path.Join("/", retentionDir, "file3.txt")},
			},
		},
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no existence check executed")
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)
	action.Options.FsConfig.Exist = []string{"/file1.txt", path.Join("/", retentionDir, "file2.txt")}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.Error(t, err)

	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.UpdateUserTransferQuota(&user1, 100, 100, true)
	assert.NoError(t, err)

	action.Type = dataprovider.ActionTypeTransferQuotaReset
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)
	userGet, err = dataprovider.UserExists(username1)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), userGet.UsedDownloadDataTransfer)
	assert.Equal(t, int64(0), userGet.UsedUploadDataTransfer)

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no transfer quota reset executed")
	}
	action.Type = dataprovider.ActionTypeFilesystem
	action.Options = dataprovider.BaseEventActionOptions{
		FsConfig: dataprovider.EventActionFilesystemConfig{
			Type: dataprovider.FilesystemActionRename,
			Renames: []dataprovider.KeyValue{
				{
					Key:   "/source",
					Value: "/target",
				},
			},
		},
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no rename executed")
	}
	action.Options = dataprovider.BaseEventActionOptions{
		FsConfig: dataprovider.EventActionFilesystemConfig{
			Type:    dataprovider.FilesystemActionDelete,
			Deletes: []string{"/dir1"},
		},
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no delete executed")
	}
	action.Options = dataprovider.BaseEventActionOptions{
		FsConfig: dataprovider.EventActionFilesystemConfig{
			Type:    dataprovider.FilesystemActionMkdirs,
			Deletes: []string{"/dir1"},
		},
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no mkdir executed")
	}

	err = dataprovider.DeleteUser(username1, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username2, "", "")
	assert.NoError(t, err)
	// test folder quota reset
	foldername1 := "f1"
	foldername2 := "f2"
	folder1 := vfs.BaseVirtualFolder{
		Name:       foldername1,
		MappedPath: filepath.Join(os.TempDir(), foldername1),
	}
	folder2 := vfs.BaseVirtualFolder{
		Name:       foldername2,
		MappedPath: filepath.Join(os.TempDir(), foldername2),
	}
	err = dataprovider.AddFolder(&folder1, "", "")
	assert.NoError(t, err)
	err = dataprovider.AddFolder(&folder2, "", "")
	assert.NoError(t, err)
	action = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeFolderQuotaReset,
	}
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: foldername1,
			},
		},
	})
	assert.Error(t, err) // no home dir
	err = os.MkdirAll(folder1.MappedPath, os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(folder1.MappedPath, "file.txt"), []byte("folder"), 0666)
	assert.NoError(t, err)
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: foldername1,
			},
		},
	})
	assert.NoError(t, err)
	folderGet, err := dataprovider.GetFolderByName(foldername1)
	assert.NoError(t, err)
	assert.Equal(t, 1, folderGet.UsedQuotaFiles)
	assert.Equal(t, int64(6), folderGet.UsedQuotaSize)
	// simulate another quota scan in progress
	assert.True(t, QuotaScans.AddVFolderQuotaScan(foldername1))
	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: foldername1,
			},
		},
	})
	assert.Error(t, err)
	assert.True(t, QuotaScans.RemoveVFolderQuotaScan(foldername1))

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "no folder match",
			},
		},
	})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no folder quota reset executed")
	}

	body, _, err := getHTTPRuleActionBody(dataprovider.EventActionHTTPConfig{
		Method: http.MethodPost,
	}, nil, nil, dataprovider.User{}, &EventParams{})
	assert.NoError(t, err)
	assert.Nil(t, body)

	err = os.RemoveAll(folder1.MappedPath)
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(foldername1, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(foldername2, "", "")
	assert.NoError(t, err)
}

func TestEventRuleActionsNoGroupMatching(t *testing.T) {
	username := "test_user_action_group_matching"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
			HomeDir: filepath.Join(os.TempDir(), username),
		},
	}
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	conditions := dataprovider.ConditionOptions{
		GroupNames: []dataprovider.ConditionPattern{
			{
				Pattern: "agroup",
			},
		},
	}
	err = executeDeleteFsRuleAction(nil, nil, conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no delete executed")
	}
	err = executeMkdirFsRuleAction(nil, nil, conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no mkdir executed")
	}
	err = executeRenameFsRuleAction(nil, nil, conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no rename executed")
	}
	err = executeExistFsRuleAction(nil, nil, conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no existence check executed")
	}
	err = executeUsersQuotaResetRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no user quota reset executed")
	}
	err = executeMetadataCheckRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no metadata check executed")
	}
	err = executeTransferQuotaResetRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no transfer quota reset executed")
	}
	err = executeDataRetentionCheckRuleAction(dataprovider.EventActionDataRetentionConfig{}, conditions, &EventParams{}, "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no retention check executed")
	}

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestGetFileContent(t *testing.T) {
	username := "test_user_get_file_content"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
			HomeDir: filepath.Join(os.TempDir(), username),
		},
	}
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	fileContent := []byte("test file content")
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file.txt"), fileContent, 0666)
	assert.NoError(t, err)
	replacer := strings.NewReplacer("old", "new")
	files, err := getMailAttachments(user, []string{"/file.txt"}, replacer)
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		assert.Equal(t, fileContent, files[0].Data)
	}
	// missing file
	_, err = getMailAttachments(user, []string{"/file1.txt"}, replacer)
	assert.Error(t, err)
	// directory
	_, err = getMailAttachments(user, []string{"/"}, replacer)
	assert.Error(t, err)
	// files too large
	content := make([]byte, maxAttachmentsSize/2+1)
	_, err = rand.Read(content)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file1.txt"), content, 0666)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file2.txt"), content, 0666)
	assert.NoError(t, err)
	files, err = getMailAttachments(user, []string{"/file1.txt"}, replacer)
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		assert.Equal(t, content, files[0].Data)
	}
	_, err = getMailAttachments(user, []string{"/file1.txt", "/file2.txt"}, replacer)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "size too large")
	}
	// change the filesystem provider
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("pwd")
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	// the file is not encrypted so reading the encryption header will fail
	_, err = getMailAttachments(user, []string{"/file.txt"}, replacer)
	assert.Error(t, err)

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestFilesystemActionErrors(t *testing.T) {
	err := executeFsRuleAction(dataprovider.EventActionFilesystemConfig{}, dataprovider.ConditionOptions{}, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported filesystem action")
	}
	username := "test_user_for_actions"
	testReplacer := strings.NewReplacer("old", "new")
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
			HomeDir: filepath.Join(os.TempDir(), username),
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.SFTPFilesystemProvider,
			SFTPConfig: vfs.SFTPFsConfig{
				BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
					Endpoint: "127.0.0.1:4022",
					Username: username,
				},
				Password: kms.NewPlainSecret("pwd"),
			},
		},
	}
	err = executeEmailRuleAction(dataprovider.EventActionEmailConfig{
		Recipients:  []string{"test@example.net"},
		Subject:     "subject",
		Body:        "body",
		Attachments: []string{"/file.txt"},
	}, &EventParams{
		sender: username,
	})
	assert.Error(t, err)
	conn := NewBaseConnection("", protocolEventAction, "", "", user)
	err = executeDeleteFileFsAction(conn, "", nil)
	assert.Error(t, err)
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	// check root fs fails
	err = executeDeleteFsActionForUser(nil, testReplacer, user)
	assert.Error(t, err)
	err = executeMkDirsFsActionForUser(nil, testReplacer, user)
	assert.Error(t, err)
	err = executeRenameFsActionForUser(nil, testReplacer, user)
	assert.Error(t, err)
	err = executeExistFsActionForUser(nil, testReplacer, user)
	assert.Error(t, err)
	err = executeEmailRuleAction(dataprovider.EventActionEmailConfig{
		Recipients:  []string{"test@example.net"},
		Subject:     "subject",
		Body:        "body",
		Attachments: []string{"/file1.txt"},
	}, &EventParams{
		sender: username,
	})
	assert.Error(t, err)
	_, err = getFileContent(NewBaseConnection("", protocolEventAction, "", "", user), "/f.txt", 1234)
	assert.Error(t, err)
	err = executeHTTPRuleAction(dataprovider.EventActionHTTPConfig{
		Endpoint: "http://127.0.0.1:9999/",
		Method:   http.MethodPost,
		Parts: []dataprovider.HTTPPart{
			{
				Name:     "p1",
				Filepath: "/filepath",
			},
		},
	}, &EventParams{
		sender: username,
	})
	assert.Error(t, err)
	user.FsConfig.Provider = sdk.LocalFilesystemProvider
	user.Permissions["/"] = []string{dataprovider.PermUpload}
	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	err = executeRenameFsActionForUser([]dataprovider.KeyValue{
		{
			Key:   "/p1",
			Value: "/p1",
		},
	}, testReplacer, user)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "the rename source and target cannot be the same")
	}
	err = executeRuleAction(dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeFilesystem,
		Options: dataprovider.BaseEventActionOptions{
			FsConfig: dataprovider.EventActionFilesystemConfig{
				Type: dataprovider.FilesystemActionRename,
				Renames: []dataprovider.KeyValue{
					{
						Key:   "/p2",
						Value: "/p2",
					},
				},
			},
		},
	}, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username,
			},
		},
	})
	assert.Error(t, err)

	if runtime.GOOS != osWindows {
		dirPath := filepath.Join(user.HomeDir, "adir", "sub")
		err := os.MkdirAll(dirPath, os.ModePerm)
		assert.NoError(t, err)
		filePath := filepath.Join(dirPath, "f.dat")
		err = os.WriteFile(filePath, nil, 0666)
		assert.NoError(t, err)
		err = os.Chmod(dirPath, 0001)
		assert.NoError(t, err)

		err = executeDeleteFsActionForUser([]string{"/adir/sub"}, testReplacer, user)
		assert.Error(t, err)
		err = executeDeleteFsActionForUser([]string{"/adir/sub/f.dat"}, testReplacer, user)
		assert.Error(t, err)
		err = os.Chmod(dirPath, 0555)
		assert.NoError(t, err)
		err = executeDeleteFsActionForUser([]string{"/adir/sub/f.dat"}, testReplacer, user)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "unable to remove file")
		}
		err = executeRuleAction(dataprovider.BaseEventAction{
			Type: dataprovider.ActionTypeFilesystem,
			Options: dataprovider.BaseEventActionOptions{
				FsConfig: dataprovider.EventActionFilesystemConfig{
					Type:    dataprovider.FilesystemActionDelete,
					Deletes: []string{"/adir/sub/f.dat"},
				},
			},
		}, &EventParams{}, dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: username,
				},
			},
		})
		assert.Error(t, err)

		err = executeMkDirsFsActionForUser([]string{"/adir/sub/sub"}, testReplacer, user)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "unable to create dir")
		}
		err = executeMkDirsFsActionForUser([]string{"/adir/sub/sub/sub"}, testReplacer, user)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "unable to check parent dirs")
		}

		err = executeRuleAction(dataprovider.BaseEventAction{
			Type: dataprovider.ActionTypeFilesystem,
			Options: dataprovider.BaseEventActionOptions{
				FsConfig: dataprovider.EventActionFilesystemConfig{
					Type:   dataprovider.FilesystemActionMkdirs,
					MkDirs: []string{"/adir/sub/sub1"},
				},
			},
		}, &EventParams{}, dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: username,
				},
			},
		})
		assert.Error(t, err)

		err = os.Chmod(dirPath, os.ModePerm)
		assert.NoError(t, err)
	}

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaActionsWithQuotaTrackDisabled(t *testing.T) {
	oldProviderConf := dataprovider.GetProviderConfig()
	providerConf := dataprovider.GetProviderConfig()
	providerConf.TrackQuota = 0
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	username := "u1"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.LocalFilesystemProvider,
		},
	}
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = executeRuleAction(dataprovider.BaseEventAction{Type: dataprovider.ActionTypeUserQuotaReset},
		&EventParams{}, dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: username,
				},
			},
		})
	assert.Error(t, err)

	err = executeRuleAction(dataprovider.BaseEventAction{Type: dataprovider.ActionTypeTransferQuotaReset},
		&EventParams{}, dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: username,
				},
			},
		})
	assert.Error(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)

	foldername := "f1"
	folder := vfs.BaseVirtualFolder{
		Name:       foldername,
		MappedPath: filepath.Join(os.TempDir(), foldername),
	}
	err = dataprovider.AddFolder(&folder, "", "")
	assert.NoError(t, err)
	err = os.MkdirAll(folder.MappedPath, os.ModePerm)
	assert.NoError(t, err)

	err = executeRuleAction(dataprovider.BaseEventAction{Type: dataprovider.ActionTypeFolderQuotaReset},
		&EventParams{}, dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: foldername,
				},
			},
		})
	assert.Error(t, err)

	err = os.RemoveAll(folder.MappedPath)
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(foldername, "", "")
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(oldProviderConf, configDir, true)
	assert.NoError(t, err)
}

func TestScheduledActions(t *testing.T) {
	startEventScheduler()
	backupsPath := filepath.Join(os.TempDir(), "backups")
	err := os.RemoveAll(backupsPath)
	assert.NoError(t, err)

	action := &dataprovider.BaseEventAction{
		Name: "action",
		Type: dataprovider.ActionTypeBackup,
	}
	err = dataprovider.AddEventAction(action, "", "")
	assert.NoError(t, err)
	rule := &dataprovider.EventRule{
		Name:    "rule",
		Trigger: dataprovider.EventTriggerSchedule,
		Conditions: dataprovider.EventConditions{
			Schedules: []dataprovider.Schedule{
				{
					Hours:      "11",
					DayOfWeek:  "*",
					DayOfMonth: "*",
					Month:      "*",
				},
			},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action.Name,
				},
				Order: 1,
			},
		},
	}

	job := eventCronJob{
		ruleName: rule.Name,
	}
	job.Run() // rule not found
	assert.NoDirExists(t, backupsPath)

	err = dataprovider.AddEventRule(rule, "", "")
	assert.NoError(t, err)

	job.Run()
	assert.DirExists(t, backupsPath)

	action.Type = dataprovider.ActionTypeEmail
	action.Options = dataprovider.BaseEventActionOptions{
		EmailConfig: dataprovider.EventActionEmailConfig{
			Recipients:  []string{"example@example.com"},
			Subject:     "test with attachments",
			Body:        "body",
			Attachments: []string{"/file1.txt"},
		},
	}
	err = dataprovider.UpdateEventAction(action, "", "")
	assert.NoError(t, err)
	job.Run() // action is not compatible with a scheduled rule

	err = dataprovider.DeleteEventRule(rule.Name, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(action.Name, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(backupsPath)
	assert.NoError(t, err)
	stopEventScheduler()
}

func TestEventParamsCopy(t *testing.T) {
	params := EventParams{
		Name:            "name",
		Event:           "event",
		Status:          1,
		errors:          []string{"error1"},
		retentionChecks: []executedRetentionCheck{},
	}
	paramsCopy := params.getACopy()
	assert.Equal(t, params, *paramsCopy)
	params.Name = "name mod"
	paramsCopy.Event = "event mod"
	paramsCopy.Status = 2
	params.errors = append(params.errors, "error2")
	paramsCopy.errors = append(paramsCopy.errors, "error3")
	assert.Equal(t, []string{"error1", "error3"}, paramsCopy.errors)
	assert.Equal(t, []string{"error1", "error2"}, params.errors)
	assert.Equal(t, "name mod", params.Name)
	assert.Equal(t, "name", paramsCopy.Name)
	assert.Equal(t, "event", params.Event)
	assert.Equal(t, "event mod", paramsCopy.Event)
	assert.Equal(t, 1, params.Status)
	assert.Equal(t, 2, paramsCopy.Status)
	params = EventParams{
		retentionChecks: []executedRetentionCheck{
			{
				Username:   "u",
				ActionName: "a",
				Results: []folderRetentionCheckResult{
					{
						Path:      "p",
						Retention: 1,
					},
				},
			},
		},
	}
	paramsCopy = params.getACopy()
	require.Len(t, paramsCopy.retentionChecks, 1)
	paramsCopy.retentionChecks[0].Username = "u_copy"
	paramsCopy.retentionChecks[0].ActionName = "a_copy"
	require.Len(t, paramsCopy.retentionChecks[0].Results, 1)
	paramsCopy.retentionChecks[0].Results[0].Path = "p_copy"
	paramsCopy.retentionChecks[0].Results[0].Retention = 2
	assert.Equal(t, "u", params.retentionChecks[0].Username)
	assert.Equal(t, "a", params.retentionChecks[0].ActionName)
	assert.Equal(t, "p", params.retentionChecks[0].Results[0].Path)
	assert.Equal(t, 1, params.retentionChecks[0].Results[0].Retention)
	assert.Equal(t, "u_copy", paramsCopy.retentionChecks[0].Username)
	assert.Equal(t, "a_copy", paramsCopy.retentionChecks[0].ActionName)
	assert.Equal(t, "p_copy", paramsCopy.retentionChecks[0].Results[0].Path)
	assert.Equal(t, 2, paramsCopy.retentionChecks[0].Results[0].Retention)
}

func TestEventParamsStatusFromError(t *testing.T) {
	params := EventParams{Status: 1}
	params.AddError(os.ErrNotExist)
	assert.Equal(t, 1, params.Status)

	params = EventParams{Status: 1, updateStatusFromError: true}
	params.AddError(os.ErrNotExist)
	assert.Equal(t, 2, params.Status)
}

type testWriter struct {
	errTest  error
	sentinel string
}

func (w *testWriter) Write(p []byte) (int, error) {
	if w.errTest != nil {
		return 0, w.errTest
	}
	if w.sentinel == string(p) {
		return 0, io.ErrUnexpectedEOF
	}
	return len(p), nil
}

func TestWriteHTTPPartsError(t *testing.T) {
	m := multipart.NewWriter(&testWriter{
		errTest: io.ErrShortWrite,
	})

	err := writeHTTPPart(m, dataprovider.HTTPPart{}, nil, nil, nil, &EventParams{})
	assert.ErrorIs(t, err, io.ErrShortWrite)

	body := "test body"
	m = multipart.NewWriter(&testWriter{sentinel: body})
	err = writeHTTPPart(m, dataprovider.HTTPPart{
		Body: body,
	}, nil, nil, nil, &EventParams{})
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
