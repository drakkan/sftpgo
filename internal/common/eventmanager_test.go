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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zip"
	"github.com/rs/xid"
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
	role := "role1"
	conditions := &dataprovider.EventConditions{
		ProviderEvents: []string{"add", "update"},
		Options: dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern:      "user1",
					InverseMatch: true,
				},
			},
			RoleNames: []dataprovider.ConditionPattern{
				{
					Pattern: role,
				},
			},
		},
	}
	res := eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:  "user1",
		Role:  role,
		Event: "add",
	})
	assert.False(t, res)
	res = eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:  "user2",
		Role:  role,
		Event: "update",
	})
	assert.True(t, res)
	res = eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:  "user2",
		Role:  role,
		Event: "delete",
	})
	assert.False(t, res)
	conditions.Options.ProviderObjects = []string{"api_key"}
	res = eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:       "user2",
		Event:      "update",
		Role:       role,
		ObjectType: "share",
	})
	assert.False(t, res)
	res = eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:       "user2",
		Event:      "update",
		Role:       role,
		ObjectType: "api_key",
	})
	assert.True(t, res)
	res = eventManager.checkProviderEventMatch(conditions, &EventParams{
		Name:       "user2",
		Event:      "update",
		Role:       role + "1",
		ObjectType: "api_key",
	})
	assert.False(t, res)
	// now test fs events
	conditions = &dataprovider.EventConditions{
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
			RoleNames: []dataprovider.ConditionPattern{
				{
					Pattern:      role,
					InverseMatch: true,
				},
			},
			FsPaths: []dataprovider.ConditionPattern{
				{
					Pattern: "/**/*.txt",
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
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.Event = operationDownload
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.True(t, res)
	params.Role = role
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.Role = ""
	params.Name = "name"
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.Name = "user5"
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.True(t, res)
	params.VirtualPath = "/sub/f.jpg"
	params.ObjectName = path.Base(params.VirtualPath)
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.VirtualPath = "/sub/f.txt"
	params.ObjectName = path.Base(params.VirtualPath)
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.True(t, res)
	params.Protocol = ProtocolHTTP
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.Protocol = ProtocolSFTP
	params.FileSize = 5
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.FileSize = 50
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	params.FileSize = 25
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.True(t, res)
	// bad pattern
	conditions.Options.Names = []dataprovider.ConditionPattern{
		{
			Pattern: "[-]",
		},
	}
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.False(t, res)
	// check fs events with group name filters
	conditions = &dataprovider.EventConditions{
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
	res = eventManager.checkFsEventMatch(conditions, &params)
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
	res = eventManager.checkFsEventMatch(conditions, &params)
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
	res = eventManager.checkFsEventMatch(conditions, &params)
	assert.True(t, res)
	// check user conditions
	user := dataprovider.User{}
	user.Username = "u1"
	res = checkUserConditionOptions(&user, &dataprovider.ConditionOptions{})
	assert.True(t, res)
	res = checkUserConditionOptions(&user, &dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "user",
			},
		},
	})
	assert.False(t, res)
	res = checkUserConditionOptions(&user, &dataprovider.ConditionOptions{
		RoleNames: []dataprovider.ConditionPattern{
			{
				Pattern: role,
			},
		},
	})
	assert.False(t, res)
	user.Role = role
	res = checkUserConditionOptions(&user, &dataprovider.ConditionOptions{
		RoleNames: []dataprovider.ConditionPattern{
			{
				Pattern: role,
			},
		},
	})
	assert.True(t, res)
	res = checkUserConditionOptions(&user, &dataprovider.ConditionOptions{
		GroupNames: []dataprovider.ConditionPattern{
			{
				Pattern: "group",
			},
		},
		RoleNames: []dataprovider.ConditionPattern{
			{
				Pattern: role,
			},
		},
	})
	assert.False(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 0,
	}, &EventParams{
		Event: IDPLoginAdmin,
	})
	assert.True(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 2,
	}, &EventParams{
		Event: IDPLoginAdmin,
	})
	assert.True(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 1,
	}, &EventParams{
		Event: IDPLoginAdmin,
	})
	assert.False(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 1,
	}, &EventParams{
		Event: IDPLoginUser,
	})
	assert.True(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 1,
	}, &EventParams{
		Name:  "user",
		Event: IDPLoginUser,
	})
	assert.True(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 1,
		Options: dataprovider.ConditionOptions{
			Names: []dataprovider.ConditionPattern{
				{
					Pattern: "abc",
				},
			},
		},
	}, &EventParams{
		Name:  "user",
		Event: IDPLoginUser,
	})
	assert.False(t, res)
	res = eventManager.checkIPDLoginEventMatch(&dataprovider.EventConditions{
		IDPLoginEvent: 2,
	}, &EventParams{
		Name:  "user",
		Event: IDPLoginUser,
	})
	assert.False(t, res)
}

func TestDoubleStarMatching(t *testing.T) {
	c := dataprovider.ConditionPattern{
		Pattern: "/mydir/**",
	}
	res := checkEventConditionPattern(c, "/mydir")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/mydirname")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub/dir")
	assert.True(t, res)

	c.Pattern = "/**/*"
	res = checkEventConditionPattern(c, "/mydir")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/mydirname")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub/dir/file.txt")
	assert.True(t, res)

	c.Pattern = "/**/*.filepart"
	res = checkEventConditionPattern(c, "/file.filepart")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub/file.filepart")
	assert.True(t, res)
	res = checkEventConditionPattern(c, "/file.txt")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydir/file.txt")
	assert.False(t, res)

	c.Pattern = "/mydir/**/*.txt"
	res = checkEventConditionPattern(c, "/mydir")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydirname/f.txt")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub/dir")
	assert.False(t, res)
	res = checkEventConditionPattern(c, "/mydir/sub/dir/a.txt")
	assert.True(t, res)

	c.InverseMatch = true
	assert.True(t, checkEventConditionPattern(c, "/mydir"))
	assert.True(t, checkEventConditionPattern(c, "/mydirname/f.txt"))
	assert.True(t, checkEventConditionPattern(c, "/mydir/sub"))
	assert.True(t, checkEventConditionPattern(c, "/mydir/sub/dir"))
	assert.False(t, checkEventConditionPattern(c, "/mydir/sub/dir/a.txt"))
}

func TestMutlipleDoubleStarMatching(t *testing.T) {
	patterns := []dataprovider.ConditionPattern{
		{
			Pattern:      "/**/*.txt",
			InverseMatch: false,
		},
		{
			Pattern:      "/**/*.tmp",
			InverseMatch: false,
		},
	}
	assert.False(t, checkEventConditionPatterns("/mydir", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/test.tmp", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/test.txt", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/test.csv", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/sub", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/sub/test.tmp", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/sub/test.txt", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/sub/test.csv", patterns))
}

func TestMultipleDoubleStarMatchingInverse(t *testing.T) {
	patterns := []dataprovider.ConditionPattern{
		{
			Pattern:      "/**/*.txt",
			InverseMatch: true,
		},
		{
			Pattern:      "/**/*.tmp",
			InverseMatch: true,
		},
	}
	assert.True(t, checkEventConditionPatterns("/mydir", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/test.tmp", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/test.txt", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/test.csv", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/sub", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/sub/test.tmp", patterns))
	assert.False(t, checkEventConditionPatterns("/mydir/sub/test.txt", patterns))
	assert.True(t, checkEventConditionPatterns("/mydir/sub/test.csv", patterns))
}

func TestGroupConditionPatterns(t *testing.T) {
	group1 := "group1"
	group2 := "group2"
	patterns := []dataprovider.ConditionPattern{
		{
			Pattern: group1,
		},
		{
			Pattern: group2,
		},
	}
	inversePatterns := []dataprovider.ConditionPattern{
		{
			Pattern:      group1,
			InverseMatch: true,
		},
		{
			Pattern:      group2,
			InverseMatch: true,
		},
	}
	groups := []sdk.GroupMapping{
		{
			Name: "group3",
			Type: sdk.GroupTypePrimary,
		},
	}
	assert.False(t, checkEventGroupConditionPatterns(groups, patterns))
	assert.True(t, checkEventGroupConditionPatterns(groups, inversePatterns))

	groups = []sdk.GroupMapping{
		{
			Name: group1,
			Type: sdk.GroupTypePrimary,
		},
		{
			Name: "group4",
			Type: sdk.GroupTypePrimary,
		},
	}
	assert.True(t, checkEventGroupConditionPatterns(groups, patterns))
	assert.False(t, checkEventGroupConditionPatterns(groups, inversePatterns))
	groups = []sdk.GroupMapping{
		{
			Name: group1,
			Type: sdk.GroupTypePrimary,
		},
	}
	assert.True(t, checkEventGroupConditionPatterns(groups, patterns))
	assert.False(t, checkEventGroupConditionPatterns(groups, inversePatterns))
	groups = []sdk.GroupMapping{
		{
			Name: "group11",
			Type: sdk.GroupTypePrimary,
		},
	}
	assert.False(t, checkEventGroupConditionPatterns(groups, patterns))
	assert.True(t, checkEventGroupConditionPatterns(groups, inversePatterns))
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
	err := dataprovider.AddEventAction(action, "", "", "")
	assert.NoError(t, err)
	rule := &dataprovider.EventRule{
		Name:    "rule",
		Status:  1,
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

	err = dataprovider.AddEventRule(rule, "", "", "")
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
	err = dataprovider.UpdateEventRule(rule, "", "", "")
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
		ok := errors.Is(err, util.ErrNotFound)
		return ok
	}, 2*time.Second, 100*time.Millisecond)

	rule.DeletedAt = 0
	err = dataprovider.AddEventRule(rule, "", "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 1)
	assert.Len(t, eventManager.schedulesMapping, 1)
	eventManager.RUnlock()

	err = dataprovider.DeleteEventRule(rule.Name, "", "", "")
	assert.NoError(t, err)

	eventManager.RLock()
	assert.Len(t, eventManager.FsEvents, 0)
	assert.Len(t, eventManager.ProviderEvents, 0)
	assert.Len(t, eventManager.Schedules, 0)
	assert.Len(t, eventManager.schedulesMapping, 0)
	eventManager.RUnlock()

	err = dataprovider.DeleteEventAction(action.Name, "", "", "")
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
	err = executeUserExpirationCheckRuleAction(dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{},
		dataprovider.ConditionOptions{}, &EventParams{}, time.Time{})
	assert.Error(t, err)
	err = executeDeleteFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeMkdirFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeRenameFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeExistFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeCopyFsRuleAction(nil, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executeCompressFsRuleAction(dataprovider.EventActionFsCompress{}, nil, dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	err = executePwdExpirationCheckRuleAction(dataprovider.EventActionPasswordExpiration{},
		dataprovider.ConditionOptions{}, &EventParams{})
	assert.Error(t, err)
	_, err = executeAdminCheckAction(&dataprovider.EventActionIDPAccountCheck{}, &EventParams{})
	assert.Error(t, err)
	_, err = executeUserCheckAction(&dataprovider.EventActionIDPAccountCheck{}, &EventParams{})
	assert.Error(t, err)

	groupName := "agroup"
	err = executeQuotaResetForUser(&dataprovider.User{
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
	err = executeCopyFsActionForUser(nil, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executeCompressFsActionForUser(dataprovider.EventActionFsCompress{}, nil, dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		},
	})
	assert.Error(t, err)
	err = executePwdExpirationCheckForUser(&dataprovider.User{
		Groups: []sdk.GroupMapping{
			{
				Name: groupName,
				Type: sdk.GroupTypePrimary,
			},
		}}, dataprovider.EventActionPasswordExpiration{})
	assert.Error(t, err)

	_, _, err = getHTTPRuleActionBody(&dataprovider.EventActionHTTPConfig{
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
	}, &EventParams{}, false)
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
		Status:  1,
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
		Status:  1,
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
				Body:          `"data": "{{ObjectDataString}}"`,
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
	action.Options.HTTPConfig.Endpoint = fmt.Sprintf("http://%v", httpAddr)
	action.Options.HTTPConfig.Password = kms.NewEmptySecret()
	action.Options.HTTPConfig.Body = ""
	action.Options.HTTPConfig.Parts = []dataprovider.HTTPPart{
		{
			Name:     "p1",
			Filepath: "path",
		},
	}
	err = executeRuleAction(action, params, dataprovider.ConditionOptions{})
	assert.Contains(t, getErrorString(err), "error getting user")

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
	user2.Filters.PasswordExpiration = 10
	err = dataprovider.AddUser(&user1, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&user2, "", "", "")
	assert.NoError(t, err)

	err = executePwdExpirationCheckRuleAction(dataprovider.EventActionPasswordExpiration{
		Threshold: 20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user2.Username,
			},
		},
	}, &EventParams{})
	// smtp not configured
	assert.Error(t, err)

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
	userGet, err := dataprovider.UserExists(username1, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, userGet.UsedQuotaFiles)
	assert.Equal(t, int64(4), userGet.UsedQuotaSize)
	// simulate another quota scan in progress
	assert.True(t, QuotaScans.AddUserQuotaScan(username1, ""))
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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no user quota reset executed")

	action = dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeUserExpirationCheck,
	}

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "don't match",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no user expiration check executed")

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username1,
			},
		},
	})
	assert.NoError(t, err)

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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no retention check executed")

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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no existence check executed")

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
	userGet, err = dataprovider.UserExists(username1, "")
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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no transfer quota reset executed")

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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no rename executed")

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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no delete executed")

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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no mkdir executed")

	action.Options = dataprovider.BaseEventActionOptions{
		FsConfig: dataprovider.EventActionFilesystemConfig{
			Type: dataprovider.FilesystemActionCompress,
			Compress: dataprovider.EventActionFsCompress{
				Name:  "test.zip",
				Paths: []string{"/{{VirtualPath}}"},
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
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no file/folder compressed")

	err = executeRuleAction(action, &EventParams{}, dataprovider.ConditionOptions{
		GroupNames: []dataprovider.ConditionPattern{
			{
				Pattern: "no match",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, getErrorString(err), "no file/folder compressed")

	err = dataprovider.DeleteUser(username1, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username2, "", "", "")
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
	err = dataprovider.AddFolder(&folder1, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.AddFolder(&folder2, "", "", "")
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

	body, _, err := getHTTPRuleActionBody(&dataprovider.EventActionHTTPConfig{
		Method: http.MethodPost,
	}, nil, nil, dataprovider.User{}, &EventParams{}, true)
	assert.NoError(t, err)
	assert.Nil(t, body)
	body, _, err = getHTTPRuleActionBody(&dataprovider.EventActionHTTPConfig{
		Method: http.MethodPost,
		Body:   "test body",
	}, nil, nil, dataprovider.User{}, &EventParams{}, false)
	assert.NoError(t, err)
	assert.NotNil(t, body)

	err = os.RemoveAll(folder1.MappedPath)
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(foldername1, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteFolder(foldername2, "", "", "")
	assert.NoError(t, err)
}

func TestIDPAccountCheckRule(t *testing.T) {
	_, _, err := executeIDPAccountCheckRule(dataprovider.EventRule{}, EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no action executed")
	}
	_, _, err = executeIDPAccountCheckRule(dataprovider.EventRule{
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: "n",
					Type: dataprovider.ActionTypeIDPAccountCheck,
				},
			},
		},
	}, EventParams{Event: "invalid"})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported IDP login event")
	}
	// invalid json
	_, err = executeAdminCheckAction(&dataprovider.EventActionIDPAccountCheck{TemplateAdmin: "{"}, &EventParams{Name: "missing admin"})
	assert.Error(t, err)
	_, err = executeUserCheckAction(&dataprovider.EventActionIDPAccountCheck{TemplateUser: "["}, &EventParams{Name: "missing user"})
	assert.Error(t, err)
	_, err = executeUserCheckAction(&dataprovider.EventActionIDPAccountCheck{TemplateUser: "{}"}, &EventParams{Name: "invalid user template"})
	assert.ErrorIs(t, err, util.ErrValidation)
	username := "u"
	c := &dataprovider.EventActionIDPAccountCheck{
		Mode:         1,
		TemplateUser: `{"username":"` + username + `","status":1,"home_dir":"` + util.JSONEscape(filepath.Join(os.TempDir())) + `","permissions":{"/":["*"]}}`,
	}
	params := &EventParams{
		Name:  username,
		Event: IDPLoginUser,
	}
	user, err := executeUserCheckAction(c, params)
	assert.NoError(t, err)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, 1, user.Status)
	user.Status = 0
	err = dataprovider.UpdateUser(user, "", "", "")
	assert.NoError(t, err)
	// the user is not changed
	user, err = executeUserCheckAction(c, params)
	assert.NoError(t, err)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, 0, user.Status)
	// change the mode, the user is now updated
	c.Mode = 0
	user, err = executeUserCheckAction(c, params)
	assert.NoError(t, err)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, 1, user.Status)

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
	// check rule consistency
	r := dataprovider.EventRule{
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Type: dataprovider.ActionTypeIDPAccountCheck,
				},
				Order: 1,
			},
		},
	}
	err = r.CheckActionsConsistency("")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "IDP account check action is only supported for IDP login trigger")
	}
	r.Trigger = dataprovider.EventTriggerIDPLogin
	err = r.CheckActionsConsistency("")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "IDP account check must be a sync action")
	}
	r.Actions[0].Options.ExecuteSync = true
	err = r.CheckActionsConsistency("")
	assert.NoError(t, err)
	r.Actions = append(r.Actions, dataprovider.EventAction{
		BaseEventAction: dataprovider.BaseEventAction{
			Type: dataprovider.ActionTypeCommand,
		},
		Options: dataprovider.EventActionOptions{
			ExecuteSync: true,
		},
		Order: 2,
	})
	err = r.CheckActionsConsistency("")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "IDP account check must be the only sync action")
	}
}

func TestUserExpirationCheck(t *testing.T) {
	username := "test_user_expiration_check"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
			HomeDir:        filepath.Join(os.TempDir(), username),
			ExpirationDate: util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour)),
		},
	}
	user.Filters.PasswordExpiration = 5
	err := dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)

	conditions := dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: username,
			},
		},
	}
	err = executeUserExpirationCheckRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "expired users")
	}
	// the check will be skipped, the user is expired
	err = executePwdExpirationCheckRuleAction(dataprovider.EventActionPasswordExpiration{Threshold: 10}, conditions, &EventParams{})
	assert.NoError(t, err)

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
	err := dataprovider.AddUser(&user, "", "", "")
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
	err = executeCopyFsRuleAction(nil, nil, conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no copy executed")
	}
	err = executeUsersQuotaResetRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no user quota reset executed")
	}
	err = executeTransferQuotaResetRuleAction(conditions, &EventParams{})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no transfer quota reset executed")
	}
	err = executeDataRetentionCheckRuleAction(dataprovider.EventActionDataRetentionConfig{}, conditions, &EventParams{}, "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no retention check executed")
	}

	err = dataprovider.DeleteUser(username, "", "", "")
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
	err := dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)
	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	fileContent := []byte("test file content")
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file.txt"), fileContent, 0666)
	assert.NoError(t, err)
	conn := NewBaseConnection(xid.New().String(), protocolEventAction, "", "", user)
	replacer := strings.NewReplacer("old", "new")
	files, err := getMailAttachments(conn, []string{"/file.txt"}, replacer)
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		var b bytes.Buffer
		_, err = files[0].Writer(&b)
		assert.NoError(t, err)
		assert.Equal(t, fileContent, b.Bytes())
	}
	// missing file
	_, err = getMailAttachments(conn, []string{"/file1.txt"}, replacer)
	assert.Error(t, err)
	// directory
	_, err = getMailAttachments(conn, []string{"/"}, replacer)
	assert.Error(t, err)
	// files too large
	content := make([]byte, maxAttachmentsSize/2+1)
	_, err = rand.Read(content)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file1.txt"), content, 0666)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(user.GetHomeDir(), "file2.txt"), content, 0666)
	assert.NoError(t, err)
	files, err = getMailAttachments(conn, []string{"/file1.txt"}, replacer)
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		var b bytes.Buffer
		_, err = files[0].Writer(&b)
		assert.NoError(t, err)
		assert.Equal(t, content, b.Bytes())
	}
	_, err = getMailAttachments(conn, []string{"/file1.txt", "/file2.txt"}, replacer)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "size too large")
	}
	// change the filesystem provider
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("pwd")
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)
	conn = NewBaseConnection(xid.New().String(), protocolEventAction, "", "", user)
	// the file is not encrypted so reading the encryption header will fail
	files, err = getMailAttachments(conn, []string{"/file.txt"}, replacer)
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		var b bytes.Buffer
		_, err = files[0].Writer(&b)
		assert.Error(t, err)
	}

	err = dataprovider.DeleteUser(username, "", "", "")
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
	err = dataprovider.AddUser(&user, "", "", "")
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
	err = executeCopyFsActionForUser(nil, testReplacer, user)
	assert.Error(t, err)
	err = executeCompressFsActionForUser(dataprovider.EventActionFsCompress{}, testReplacer, user)
	assert.Error(t, err)
	_, _, _, _, err = getFileWriter(conn, "/path.txt", -1) //nolint:dogsled
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
	fn := getFileContentFn(NewBaseConnection("", protocolEventAction, "", "", user), "/f.txt", 1234)
	var b bytes.Buffer
	_, err = fn(&b)
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
	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&user, "", "", "")
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
		err = os.WriteFile(filePath, []byte("test file content"), 0666)
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

		conn = NewBaseConnection("", protocolEventAction, "", "", user)
		wr := &zipWriterWrapper{
			Name:    "test.zip",
			Writer:  zip.NewWriter(bytes.NewBuffer(nil)),
			Entries: map[string]bool{},
		}
		err = addZipEntry(wr, conn, "/adir/sub/f.dat", "/adir/sub/sub", 0)
		assert.Error(t, err)
		assert.Contains(t, getErrorString(err), "is outside base dir")
	}

	wr := &zipWriterWrapper{
		Name:    xid.New().String() + ".zip",
		Writer:  zip.NewWriter(bytes.NewBuffer(nil)),
		Entries: map[string]bool{},
	}
	err = addZipEntry(wr, conn, "/p1", "/", 2000)
	assert.ErrorIs(t, err, util.ErrRecursionTooDeep)

	err = dataprovider.DeleteUser(username, "", "", "")
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
	err = dataprovider.AddUser(&user, "", "", "")
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
	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)

	foldername := "f1"
	folder := vfs.BaseVirtualFolder{
		Name:       foldername,
		MappedPath: filepath.Join(os.TempDir(), foldername),
	}
	err = dataprovider.AddFolder(&folder, "", "", "")
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
	err = dataprovider.DeleteFolder(foldername, "", "", "")
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
	err = dataprovider.AddEventAction(action, "", "", "")
	assert.NoError(t, err)
	rule := &dataprovider.EventRule{
		Name:    "rule",
		Status:  1,
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

	err = dataprovider.AddEventRule(rule, "", "", "")
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
	err = dataprovider.UpdateEventAction(action, "", "", "")
	assert.NoError(t, err)
	job.Run() // action is not compatible with a scheduled rule

	err = dataprovider.DeleteEventRule(rule.Name, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(action.Name, "", "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(backupsPath)
	assert.NoError(t, err)
	stopEventScheduler()
}

func TestEventParamsCopy(t *testing.T) {
	params := EventParams{
		Name:            "name",
		Event:           "event",
		Extension:       "ext",
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
	assert.Nil(t, params.IDPCustomFields)
	params.addIDPCustomFields(nil)
	assert.Nil(t, params.IDPCustomFields)
	params.IDPCustomFields = &map[string]string{
		"field1": "val1",
	}
	paramsCopy = params.getACopy()
	for k, v := range *paramsCopy.IDPCustomFields {
		assert.Equal(t, "field1", k)
		assert.Equal(t, "val1", v)
	}
	assert.Equal(t, params.IDPCustomFields, paramsCopy.IDPCustomFields)
	(*paramsCopy.IDPCustomFields)["field1"] = "val2"
	assert.NotEqual(t, params.IDPCustomFields, paramsCopy.IDPCustomFields)
	params.Metadata = map[string]string{"key": "value"}
	paramsCopy = params.getACopy()
	params.Metadata["key1"] = "value1"
	require.Equal(t, map[string]string{"key": "value"}, paramsCopy.Metadata)
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

	err := writeHTTPPart(m, dataprovider.HTTPPart{}, nil, nil, nil, &EventParams{}, false)
	assert.ErrorIs(t, err, io.ErrShortWrite)

	body := "test body"
	m = multipart.NewWriter(&testWriter{sentinel: body})
	err = writeHTTPPart(m, dataprovider.HTTPPart{
		Body: body,
	}, nil, nil, nil, &EventParams{}, false)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReplacePathsPlaceholders(t *testing.T) {
	replacer := strings.NewReplacer("{{VirtualPath}}", "/path1")
	paths := []string{"{{VirtualPath}}", "/path1"}
	paths = replacePathsPlaceholders(paths, replacer)
	assert.Equal(t, []string{"/path1"}, paths)
	paths = []string{"{{VirtualPath}}", "/path2"}
	paths = replacePathsPlaceholders(paths, replacer)
	assert.Equal(t, []string{"/path1", "/path2"}, paths)
}

func TestEstimateZipSizeErrors(t *testing.T) {
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
			HomeDir:  filepath.Join(os.TempDir(), "u"),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
			QuotaSize: 1000,
		},
	}
	err := dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	err = os.MkdirAll(u.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	conn := NewBaseConnection("", ProtocolFTP, "", "", u)
	_, _, _, _, err = getFileWriter(conn, "/missing/path/file.txt", -1) //nolint:dogsled
	assert.Error(t, err)
	_, err = getSizeForPath(conn, "/missing", vfs.NewFileInfo("missing", true, 0, time.Now(), false))
	assert.True(t, conn.IsNotExistError(err))
	if runtime.GOOS != osWindows {
		err = os.MkdirAll(filepath.Join(u.HomeDir, "d1", "d2", "sub"), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(filepath.Join(u.HomeDir, "d1", "d2", "sub", "file.txt"), []byte("data"), 0666)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(u.HomeDir, "d1", "d2"), 0001)
		assert.NoError(t, err)
		size, err := estimateZipSize(conn, "/archive.zip", []string{"/d1"})
		assert.Error(t, err, "size %d", size)
		err = os.Chmod(filepath.Join(u.HomeDir, "d1", "d2"), os.ModePerm)
		assert.NoError(t, err)
	}
	err = dataprovider.DeleteUser(u.Username, "", "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
}

func TestOnDemandRule(t *testing.T) {
	a := &dataprovider.BaseEventAction{
		Name:    "a",
		Type:    dataprovider.ActionTypeBackup,
		Options: dataprovider.BaseEventActionOptions{},
	}
	err := dataprovider.AddEventAction(a, "", "", "")
	assert.NoError(t, err)
	r := &dataprovider.EventRule{
		Name:    "test on demand rule",
		Status:  1,
		Trigger: dataprovider.EventTriggerOnDemand,
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: a.Name,
				},
			},
		},
	}
	err = dataprovider.AddEventRule(r, "", "", "")
	assert.NoError(t, err)

	err = RunOnDemandRule(r.Name)
	assert.NoError(t, err)

	r.Status = 0
	err = dataprovider.UpdateEventRule(r, "", "", "")
	assert.NoError(t, err)
	err = RunOnDemandRule(r.Name)
	assert.ErrorIs(t, err, util.ErrValidation)
	assert.Contains(t, err.Error(), "is inactive")

	r.Status = 1
	r.Trigger = dataprovider.EventTriggerCertificate
	err = dataprovider.UpdateEventRule(r, "", "", "")
	assert.NoError(t, err)
	err = RunOnDemandRule(r.Name)
	assert.ErrorIs(t, err, util.ErrValidation)
	assert.Contains(t, err.Error(), "is not defined as on-demand")

	a1 := &dataprovider.BaseEventAction{
		Name: "a1",
		Type: dataprovider.ActionTypeEmail,
		Options: dataprovider.BaseEventActionOptions{
			EmailConfig: dataprovider.EventActionEmailConfig{
				Recipients:  []string{"example@example.org"},
				Subject:     "subject",
				Body:        "body",
				Attachments: []string{"/{{VirtualPath}}"},
			},
		},
	}
	err = dataprovider.AddEventAction(a1, "", "", "")
	assert.NoError(t, err)

	r.Trigger = dataprovider.EventTriggerOnDemand
	r.Actions = []dataprovider.EventAction{
		{
			BaseEventAction: dataprovider.BaseEventAction{
				Name: a1.Name,
			},
		},
	}
	err = dataprovider.UpdateEventRule(r, "", "", "")
	assert.NoError(t, err)
	err = RunOnDemandRule(r.Name)
	assert.ErrorIs(t, err, util.ErrValidation)
	assert.Contains(t, err.Error(), "incosistent actions")

	err = dataprovider.DeleteEventRule(r.Name, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(a.Name, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(a1.Name, "", "", "")
	assert.NoError(t, err)

	err = RunOnDemandRule(r.Name)
	assert.ErrorIs(t, err, util.ErrNotFound)
}

func getErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestHTTPEndpointWithPlaceholders(t *testing.T) {
	c := dataprovider.EventActionHTTPConfig{
		Endpoint: "http://127.0.0.1:8080/base/url/{{Name}}/{{VirtualPath}}/upload",
		QueryParameters: []dataprovider.KeyValue{
			{
				Key:   "u",
				Value: "{{Name}}",
			},
			{
				Key:   "p",
				Value: "{{VirtualPath}}",
			},
		},
	}
	name := "uname"
	vPath := "/a dir/@ file.txt"
	replacer := strings.NewReplacer("{{Name}}", name, "{{VirtualPath}}", vPath)
	u, err := getHTTPRuleActionEndpoint(&c, replacer)
	assert.NoError(t, err)
	expected := "http://127.0.0.1:8080/base/url/" + url.PathEscape(name) + "/" + url.PathEscape(vPath) +
		"/upload?" + "p=" + url.QueryEscape(vPath) + "&u=" + url.QueryEscape(name)
	assert.Equal(t, expected, u)

	c.Endpoint = "http://127.0.0.1/upload"
	u, err = getHTTPRuleActionEndpoint(&c, replacer)
	assert.NoError(t, err)
	expected = c.Endpoint + "?p=" + url.QueryEscape(vPath) + "&u=" + url.QueryEscape(name)
	assert.Equal(t, expected, u)
}

func TestMetadataReplacement(t *testing.T) {
	params := &EventParams{
		Metadata: map[string]string{
			"key": "value",
		},
	}
	replacements := params.getStringReplacements(false, false)
	replacer := strings.NewReplacer(replacements...)
	reader, _, err := getHTTPRuleActionBody(&dataprovider.EventActionHTTPConfig{Body: "{{Metadata}} {{MetadataString}}"}, replacer, nil, dataprovider.User{}, params, false)
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, `{"key":"value"} {\"key\":\"value\"}`, string(data))
}

func TestUserInactivityCheck(t *testing.T) {
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
	days := user1.InactivityDays(time.Now().Add(10*24*time.Hour + 5*time.Second))
	assert.Equal(t, 0, days)

	user2.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	err := executeInactivityCheckForUser(&user2, dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
	}, time.Now().Add(12*24*time.Hour))
	assert.Error(t, err)
	user2.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	err = executeInactivityCheckForUser(&user2, dataprovider.EventActionUserInactivity{
		DeleteThreshold: 10,
	}, time.Now().Add(12*24*time.Hour))
	assert.Error(t, err)

	err = dataprovider.AddUser(&user1, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&user2, "", "", "")
	assert.NoError(t, err)
	user1, err = dataprovider.UserExists(username1, "")
	assert.NoError(t, err)
	assert.Equal(t, 1, user1.Status)
	days = user1.InactivityDays(time.Now().Add(10*24*time.Hour + 5*time.Second))
	assert.Equal(t, 10, days)
	days = user1.InactivityDays(time.Now().Add(-10*24*time.Hour + 5*time.Second))
	assert.Equal(t, -9, days)

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: "not matching",
			},
		},
	}, &EventParams{}, time.Now().Add(12*24*time.Hour))
	assert.NoError(t, err)

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now())
	assert.NoError(t, err) // no action

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(-12*24*time.Hour))
	assert.NoError(t, err) // no action

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
		DeleteThreshold:  20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(30*24*time.Hour))
	// both thresholds exceeded, the user will be disabled
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "executed inactivity check actions for users")
	}
	user1, err = dataprovider.UserExists(username1, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, user1.Status)

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(30*24*time.Hour))
	assert.NoError(t, err) // already disabled, no action

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
		DeleteThreshold:  20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(-30*24*time.Hour))
	assert.NoError(t, err)
	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
		DeleteThreshold:  20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now())
	assert.NoError(t, err)
	user1, err = dataprovider.UserExists(username1, "")
	assert.NoError(t, err)
	assert.Equal(t, 0, user1.Status)

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DisableThreshold: 10,
		DeleteThreshold:  20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user1.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(30*24*time.Hour)) // the user is disabled, will be now deleted
	assert.Error(t, err)
	_, err = dataprovider.UserExists(username1, "")
	assert.ErrorIs(t, err, util.ErrNotFound)

	err = executeUserInactivityCheckRuleAction(dataprovider.EventActionUserInactivity{
		DeleteThreshold: 20,
	}, dataprovider.ConditionOptions{
		Names: []dataprovider.ConditionPattern{
			{
				Pattern: user2.Username,
			},
		},
	}, &EventParams{}, time.Now().Add(30*24*time.Hour)) // no disable threshold, user deleted
	assert.Error(t, err)
	_, err = dataprovider.UserExists(username2, "")
	assert.ErrorIs(t, err, util.ErrNotFound)

	err = dataprovider.DeleteUser(username1, "", "", "")
	assert.Error(t, err)
	err = dataprovider.DeleteUser(username2, "", "", "")
	assert.Error(t, err)
}
