package common

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

func TestTransfersCheckerDiskQuota(t *testing.T) {
	username := "transfers_check_username"
	folderName := "test_transfers_folder"
	vdirPath := "/vdir"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:  username,
			Password:  "testpwd",
			HomeDir:   filepath.Join(os.TempDir(), username),
			Status:    1,
			QuotaSize: 120,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		VirtualFolders: []vfs.VirtualFolder{
			{
				BaseVirtualFolder: vfs.BaseVirtualFolder{
					Name:       folderName,
					MappedPath: filepath.Join(os.TempDir(), folderName),
				},
				VirtualPath: vdirPath,
				QuotaSize:   100,
			},
		},
	}

	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	user, err = dataprovider.UserExists(username)
	assert.NoError(t, err)

	connID1 := xid.New().String()
	fsUser, err := user.GetFilesystemForPath("/file1", connID1)
	assert.NoError(t, err)
	conn1 := NewBaseConnection(connID1, ProtocolSFTP, "", "", user)
	fakeConn1 := &fakeConnection{
		BaseConnection: conn1,
	}
	transfer1 := NewBaseTransfer(nil, conn1, nil, filepath.Join(user.HomeDir, "file1"), filepath.Join(user.HomeDir, "file1"),
		"/file1", TransferUpload, 0, 0, 120, 0, true, fsUser)
	transfer1.BytesReceived = 150
	Connections.Add(fakeConn1)
	// the transferschecker will do nothing if there is only one ongoing transfer
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)

	connID2 := xid.New().String()
	conn2 := NewBaseConnection(connID2, ProtocolSFTP, "", "", user)
	fakeConn2 := &fakeConnection{
		BaseConnection: conn2,
	}
	transfer2 := NewBaseTransfer(nil, conn2, nil, filepath.Join(user.HomeDir, "file2"), filepath.Join(user.HomeDir, "file2"),
		"/file2", TransferUpload, 0, 0, 120, 40, true, fsUser)
	transfer1.BytesReceived = 50
	transfer2.BytesReceived = 60
	Connections.Add(fakeConn2)

	connID3 := xid.New().String()
	conn3 := NewBaseConnection(connID3, ProtocolSFTP, "", "", user)
	fakeConn3 := &fakeConnection{
		BaseConnection: conn3,
	}
	transfer3 := NewBaseTransfer(nil, conn3, nil, filepath.Join(user.HomeDir, "file3"), filepath.Join(user.HomeDir, "file3"),
		"/file3", TransferDownload, 0, 0, 120, 0, true, fsUser)
	transfer3.BytesReceived = 60 // this value will be ignored, this is a download
	Connections.Add(fakeConn3)

	// the transfers are not overquota
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)

	transfer1.BytesReceived = 80 // truncated size will be subtracted, we are not overquota
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)
	transfer1.BytesReceived = 120
	// we are now overquota
	// if another check is in progress nothing is done
	atomic.StoreInt32(&Connections.transfersCheckStatus, 1)
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)
	atomic.StoreInt32(&Connections.transfersCheckStatus, 0)

	Connections.checkTransfers()
	assert.True(t, conn1.IsQuotaExceededError(transfer1.errAbort))
	assert.True(t, conn2.IsQuotaExceededError(transfer2.errAbort))
	assert.True(t, conn1.IsQuotaExceededError(transfer1.GetAbortError()))
	assert.Nil(t, transfer3.errAbort)
	assert.True(t, conn3.IsQuotaExceededError(transfer3.GetAbortError()))
	// update the user quota size
	user.QuotaSize = 1000
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	transfer1.errAbort = nil
	transfer2.errAbort = nil
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)

	user.QuotaSize = 0
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)
	// now check a public folder
	transfer1.BytesReceived = 0
	transfer2.BytesReceived = 0
	connID4 := xid.New().String()
	fsFolder, err := user.GetFilesystemForPath(path.Join(vdirPath, "/file1"), connID4)
	assert.NoError(t, err)
	conn4 := NewBaseConnection(connID4, ProtocolSFTP, "", "", user)
	fakeConn4 := &fakeConnection{
		BaseConnection: conn4,
	}
	transfer4 := NewBaseTransfer(nil, conn4, nil, filepath.Join(os.TempDir(), folderName, "file1"),
		filepath.Join(os.TempDir(), folderName, "file1"), path.Join(vdirPath, "/file1"), TransferUpload, 0, 0,
		100, 0, true, fsFolder)
	Connections.Add(fakeConn4)
	connID5 := xid.New().String()
	conn5 := NewBaseConnection(connID5, ProtocolSFTP, "", "", user)
	fakeConn5 := &fakeConnection{
		BaseConnection: conn5,
	}
	transfer5 := NewBaseTransfer(nil, conn5, nil, filepath.Join(os.TempDir(), folderName, "file2"),
		filepath.Join(os.TempDir(), folderName, "file2"), path.Join(vdirPath, "/file2"), TransferUpload, 0, 0,
		100, 0, true, fsFolder)

	Connections.Add(fakeConn5)
	transfer4.BytesReceived = 50
	transfer5.BytesReceived = 40
	Connections.checkTransfers()
	assert.Nil(t, transfer4.errAbort)
	assert.Nil(t, transfer5.errAbort)
	transfer5.BytesReceived = 60
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	assert.Nil(t, transfer3.errAbort)
	assert.True(t, conn1.IsQuotaExceededError(transfer4.errAbort))
	assert.True(t, conn2.IsQuotaExceededError(transfer5.errAbort))

	if dataprovider.GetProviderStatus().Driver != dataprovider.MemoryDataProviderName {
		providerConf := dataprovider.GetProviderConfig()
		err = dataprovider.Close()
		assert.NoError(t, err)

		transfer4.errAbort = nil
		transfer5.errAbort = nil
		Connections.checkTransfers()
		assert.Nil(t, transfer1.errAbort)
		assert.Nil(t, transfer2.errAbort)
		assert.Nil(t, transfer3.errAbort)
		assert.Nil(t, transfer4.errAbort)
		assert.Nil(t, transfer5.errAbort)

		err = dataprovider.Initialize(providerConf, configDir, true)
		assert.NoError(t, err)
	}

	Connections.Remove(fakeConn1.GetID())
	Connections.Remove(fakeConn2.GetID())
	Connections.Remove(fakeConn3.GetID())
	Connections.Remove(fakeConn4.GetID())
	Connections.Remove(fakeConn5.GetID())
	stats := Connections.GetStats()
	assert.Len(t, stats, 0)

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.DeleteFolder(folderName, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(os.TempDir(), folderName))
	assert.NoError(t, err)
}

func TestAggregateTransfers(t *testing.T) {
	checker := transfersCheckerMem{}
	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "1",
		Username:      "user",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 100,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	usersToFetch, aggregations := checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 1)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferDownload,
		ConnID:        "2",
		Username:      "user",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 0,
		CurrentDLSize: 100,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 2)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "3",
		Username:      "user",
		FolderName:    "folder",
		TruncatedSize: 0,
		CurrentULSize: 10,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 3)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "4",
		Username:      "user1",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 100,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 4)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "5",
		Username:      "user",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 100,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok := usersToFetch["user"]
	assert.True(t, ok)
	assert.False(t, val)
	assert.Len(t, aggregations, 4)
	aggregate, ok := aggregations["user0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 2)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "6",
		Username:      "user",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 100,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.False(t, val)
	assert.Len(t, aggregations, 4)
	aggregate, ok = aggregations["user0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 3)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "7",
		Username:      "user",
		FolderName:    "folder",
		TruncatedSize: 0,
		CurrentULSize: 10,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.True(t, val)
	assert.Len(t, aggregations, 4)
	aggregate, ok = aggregations["user0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 3)
	aggregate, ok = aggregations["userfolder0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 2)

	checker.AddTransfer(dataprovider.ActiveTransfer{
		ID:            1,
		Type:          TransferUpload,
		ConnID:        "8",
		Username:      "user",
		FolderName:    "",
		TruncatedSize: 0,
		CurrentULSize: 100,
		CurrentDLSize: 0,
		CreatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
		UpdatedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	usersToFetch, aggregations = checker.aggregateTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.True(t, val)
	assert.Len(t, aggregations, 4)
	aggregate, ok = aggregations["user0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 4)
	aggregate, ok = aggregations["userfolder0"]
	assert.True(t, ok)
	assert.Len(t, aggregate, 2)
}

func TestGetUsersForQuotaCheck(t *testing.T) {
	usersToFetch := make(map[string]bool)
	for i := 0; i < 50; i++ {
		usersToFetch[fmt.Sprintf("user%v", i)] = i%2 == 0
	}

	users, err := dataprovider.GetUsersForQuotaCheck(usersToFetch)
	assert.NoError(t, err)
	assert.Len(t, users, 0)

	for i := 0; i < 40; i++ {
		user := dataprovider.User{
			BaseUser: sdk.BaseUser{
				Username:  fmt.Sprintf("user%v", i),
				Password:  "pwd",
				HomeDir:   filepath.Join(os.TempDir(), fmt.Sprintf("user%v", i)),
				Status:    1,
				QuotaSize: 120,
				Permissions: map[string][]string{
					"/": {dataprovider.PermAny},
				},
			},
			VirtualFolders: []vfs.VirtualFolder{
				{
					BaseVirtualFolder: vfs.BaseVirtualFolder{
						Name:       fmt.Sprintf("f%v", i),
						MappedPath: filepath.Join(os.TempDir(), fmt.Sprintf("f%v", i)),
					},
					VirtualPath: "/vfolder",
					QuotaSize:   100,
				},
			},
		}
		err = dataprovider.AddUser(&user, "", "")
		assert.NoError(t, err)
		err = dataprovider.UpdateVirtualFolderQuota(&vfs.BaseVirtualFolder{Name: fmt.Sprintf("f%v", i)}, 1, 50, false)
		assert.NoError(t, err)
	}

	users, err = dataprovider.GetUsersForQuotaCheck(usersToFetch)
	assert.NoError(t, err)
	assert.Len(t, users, 40)

	for _, user := range users {
		userIdxStr := strings.Replace(user.Username, "user", "", 1)
		userIdx, err := strconv.Atoi(userIdxStr)
		assert.NoError(t, err)
		if userIdx%2 == 0 {
			if assert.Len(t, user.VirtualFolders, 1, user.Username) {
				assert.Equal(t, int64(100), user.VirtualFolders[0].QuotaSize)
				assert.Equal(t, int64(50), user.VirtualFolders[0].UsedQuotaSize)
			}
		} else {
			switch dataprovider.GetProviderStatus().Driver {
			case dataprovider.MySQLDataProviderName, dataprovider.PGSQLDataProviderName,
				dataprovider.CockroachDataProviderName, dataprovider.SQLiteDataProviderName:
				assert.Len(t, user.VirtualFolders, 0, user.Username)
			}
		}
	}

	for i := 0; i < 40; i++ {
		err = dataprovider.DeleteUser(fmt.Sprintf("user%v", i), "", "")
		assert.NoError(t, err)
		err = dataprovider.DeleteFolder(fmt.Sprintf("f%v", i), "", "")
		assert.NoError(t, err)
	}

	users, err = dataprovider.GetUsersForQuotaCheck(usersToFetch)
	assert.NoError(t, err)
	assert.Len(t, users, 0)
}
