// Copyright (C) 2024 Nicola Murino
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

package httpd

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	webTaskMgr webTaskManager
)

func newWebTaskManager(isShared int) webTaskManager {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider task manager")
		return &dbTaskManager{}
	}
	logger.Info(logSender, "", "using memory task manager")
	return &memoryTaskManager{}
}

type webTaskManager interface {
	Add(data webTaskData) error
	Get(ID string) (webTaskData, error)
	Cleanup()
}

type webTaskData struct {
	ID        string `json:"id"`
	User      string `json:"user"`
	Path      string `json:"path"`
	Target    string `json:"target"`
	Timestamp int64  `json:"ts"`
	Status    int    `json:"status"` // 0 in progress or http status code (200 ok, 403 and so on)
}

type memoryTaskManager struct {
	tasks sync.Map
}

func (m *memoryTaskManager) Add(data webTaskData) error {
	m.tasks.Store(data.ID, &data)
	return nil
}

func (m *memoryTaskManager) Get(ID string) (webTaskData, error) {
	data, ok := m.tasks.Load(ID)
	if !ok {
		return webTaskData{}, util.NewRecordNotFoundError(fmt.Sprintf("task for ID %q not found", ID))
	}
	return *data.(*webTaskData), nil
}

func (m *memoryTaskManager) Cleanup() {
	m.tasks.Range(func(key, value any) bool {
		data := value.(*webTaskData)
		if data.Timestamp < util.GetTimeAsMsSinceEpoch(time.Now().Add(-5*time.Minute)) {
			m.tasks.Delete(key)
		}
		return true
	})
}

type dbTaskManager struct{}

func (m *dbTaskManager) Add(data webTaskData) error {
	session := dataprovider.Session{
		Key:       data.ID,
		Data:      data,
		Type:      dataprovider.SessionTypeWebTask,
		Timestamp: data.Timestamp,
	}
	return dataprovider.AddSharedSession(session)
}

func (m *dbTaskManager) Get(ID string) (webTaskData, error) {
	sess, err := dataprovider.GetSharedSession(ID, dataprovider.SessionTypeWebTask)
	if err != nil {
		return webTaskData{}, err
	}
	d := sess.Data.([]byte)
	var data webTaskData
	err = json.Unmarshal(d, &data)
	return data, err
}

func (m *dbTaskManager) Cleanup() {
	dataprovider.CleanupSharedSessions(dataprovider.SessionTypeWebTask, time.Now().Add(-5*time.Minute)) //nolint:errcheck
}
