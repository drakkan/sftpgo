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
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

func TestMemoryWebTaskManager(t *testing.T) {
	mgr := newWebTaskManager(0)
	m, ok := mgr.(*memoryTaskManager)
	require.True(t, ok)
	task := webTaskData{
		ID:        xid.New().String(),
		User:      defeaultUsername,
		Timestamp: time.Now().Add(-1 * time.Hour).UnixMilli(),
		Status:    0,
	}
	task1 := webTaskData{
		ID:        xid.New().String(),
		User:      defeaultUsername,
		Timestamp: time.Now().UnixMilli(),
		Status:    0,
	}
	err := m.Add(task)
	require.NoError(t, err)
	err = m.Add(task1)
	require.NoError(t, err)
	taskGet, err := m.Get(task.ID)
	require.NoError(t, err)
	require.Equal(t, task, taskGet)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.ErrorIs(t, err, util.ErrNotFound)
	taskGet, err = m.Get(task1.ID)
	require.NoError(t, err)
	require.Equal(t, task1, taskGet)
	task1.Timestamp = time.Now().Add(-1 * time.Hour).UnixMilli()
	err = m.Add(task1)
	require.NoError(t, err)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.ErrorIs(t, err, util.ErrNotFound)
	// test keep alive task
	oldMgr := webTaskMgr
	webTaskMgr = mgr

	done := make(chan bool)
	go keepAliveTask(task, done, 50*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	close(done)
	taskGet, err = m.Get(task.ID)
	require.NoError(t, err)
	assert.Greater(t, taskGet.Timestamp, task.Timestamp)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.NoError(t, err)
	err = m.Add(task)
	require.NoError(t, err)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.ErrorIs(t, err, util.ErrNotFound)

	webTaskMgr = oldMgr
}

func TestDbWebTaskManager(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	mgr := newWebTaskManager(1)
	m, ok := mgr.(*dbTaskManager)
	require.True(t, ok)

	task := webTaskData{
		ID:        xid.New().String(),
		User:      defeaultUsername,
		Timestamp: time.Now().Add(-1 * time.Hour).UnixMilli(),
		Status:    0,
	}
	err := m.Add(task)
	require.NoError(t, err)
	taskGet, err := m.Get(task.ID)
	require.NoError(t, err)
	require.Equal(t, task, taskGet)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.ErrorIs(t, err, util.ErrNotFound)
	err = m.Add(task)
	require.NoError(t, err)
	// test keep alive task
	oldMgr := webTaskMgr
	webTaskMgr = mgr

	done := make(chan bool)
	go keepAliveTask(task, done, 50*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	close(done)
	taskGet, err = m.Get(task.ID)
	require.NoError(t, err)
	assert.Greater(t, taskGet.Timestamp, task.Timestamp)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.NoError(t, err)
	err = m.Add(task)
	require.NoError(t, err)
	m.Cleanup()
	_, err = m.Get(task.ID)
	require.ErrorIs(t, err, util.ErrNotFound)

	webTaskMgr = oldMgr
}
