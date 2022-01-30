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
		"/file1", TransferUpload, 0, 0, 120, 0, true, fsUser, dataprovider.TransferQuota{})
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
		"/file2", TransferUpload, 0, 0, 120, 40, true, fsUser, dataprovider.TransferQuota{})
	transfer1.BytesReceived = 50
	transfer2.BytesReceived = 60
	Connections.Add(fakeConn2)

	connID3 := xid.New().String()
	conn3 := NewBaseConnection(connID3, ProtocolSFTP, "", "", user)
	fakeConn3 := &fakeConnection{
		BaseConnection: conn3,
	}
	transfer3 := NewBaseTransfer(nil, conn3, nil, filepath.Join(user.HomeDir, "file3"), filepath.Join(user.HomeDir, "file3"),
		"/file3", TransferDownload, 0, 0, 120, 0, true, fsUser, dataprovider.TransferQuota{})
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
		100, 0, true, fsFolder, dataprovider.TransferQuota{})
	Connections.Add(fakeConn4)
	connID5 := xid.New().String()
	conn5 := NewBaseConnection(connID5, ProtocolSFTP, "", "", user)
	fakeConn5 := &fakeConnection{
		BaseConnection: conn5,
	}
	transfer5 := NewBaseTransfer(nil, conn5, nil, filepath.Join(os.TempDir(), folderName, "file2"),
		filepath.Join(os.TempDir(), folderName, "file2"), path.Join(vdirPath, "/file2"), TransferUpload, 0, 0,
		100, 0, true, fsFolder, dataprovider.TransferQuota{})

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

	err = transfer1.Close()
	assert.NoError(t, err)
	err = transfer2.Close()
	assert.NoError(t, err)
	err = transfer3.Close()
	assert.NoError(t, err)
	err = transfer4.Close()
	assert.NoError(t, err)
	err = transfer5.Close()
	assert.NoError(t, err)

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

func TestTransferCheckerTransferQuota(t *testing.T) {
	username := "transfers_check_username"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:          username,
			Password:          "test_pwd",
			HomeDir:           filepath.Join(os.TempDir(), username),
			Status:            1,
			TotalDataTransfer: 1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	connID1 := xid.New().String()
	fsUser, err := user.GetFilesystemForPath("/file1", connID1)
	assert.NoError(t, err)
	conn1 := NewBaseConnection(connID1, ProtocolSFTP, "", "192.168.1.1", user)
	fakeConn1 := &fakeConnection{
		BaseConnection: conn1,
	}
	transfer1 := NewBaseTransfer(nil, conn1, nil, filepath.Join(user.HomeDir, "file1"), filepath.Join(user.HomeDir, "file1"),
		"/file1", TransferUpload, 0, 0, 0, 0, true, fsUser, dataprovider.TransferQuota{AllowedTotalSize: 100})
	transfer1.BytesReceived = 150
	Connections.Add(fakeConn1)
	// the transferschecker will do nothing if there is only one ongoing transfer
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)

	connID2 := xid.New().String()
	conn2 := NewBaseConnection(connID2, ProtocolSFTP, "", "127.0.0.1", user)
	fakeConn2 := &fakeConnection{
		BaseConnection: conn2,
	}
	transfer2 := NewBaseTransfer(nil, conn2, nil, filepath.Join(user.HomeDir, "file2"), filepath.Join(user.HomeDir, "file2"),
		"/file2", TransferUpload, 0, 0, 0, 0, true, fsUser, dataprovider.TransferQuota{AllowedTotalSize: 100})
	transfer2.BytesReceived = 150
	Connections.Add(fakeConn2)
	Connections.checkTransfers()
	assert.Nil(t, transfer1.errAbort)
	assert.Nil(t, transfer2.errAbort)
	// now test overquota
	transfer1.BytesReceived = 1024*1024 + 1
	transfer2.BytesReceived = 0
	Connections.checkTransfers()
	assert.True(t, conn1.IsQuotaExceededError(transfer1.errAbort))
	assert.Nil(t, transfer2.errAbort)
	transfer1.errAbort = nil
	transfer1.BytesReceived = 1024*1024 + 1
	transfer2.BytesReceived = 1024
	Connections.checkTransfers()
	assert.True(t, conn1.IsQuotaExceededError(transfer1.errAbort))
	assert.True(t, conn2.IsQuotaExceededError(transfer2.errAbort))
	transfer1.BytesReceived = 0
	transfer2.BytesReceived = 0
	transfer1.errAbort = nil
	transfer2.errAbort = nil

	err = transfer1.Close()
	assert.NoError(t, err)
	err = transfer2.Close()
	assert.NoError(t, err)
	Connections.Remove(fakeConn1.GetID())
	Connections.Remove(fakeConn2.GetID())

	connID3 := xid.New().String()
	conn3 := NewBaseConnection(connID3, ProtocolSFTP, "", "", user)
	fakeConn3 := &fakeConnection{
		BaseConnection: conn3,
	}
	transfer3 := NewBaseTransfer(nil, conn3, nil, filepath.Join(user.HomeDir, "file1"), filepath.Join(user.HomeDir, "file1"),
		"/file1", TransferDownload, 0, 0, 0, 0, true, fsUser, dataprovider.TransferQuota{AllowedDLSize: 100})
	transfer3.BytesSent = 150
	Connections.Add(fakeConn3)

	connID4 := xid.New().String()
	conn4 := NewBaseConnection(connID4, ProtocolSFTP, "", "", user)
	fakeConn4 := &fakeConnection{
		BaseConnection: conn4,
	}
	transfer4 := NewBaseTransfer(nil, conn4, nil, filepath.Join(user.HomeDir, "file2"), filepath.Join(user.HomeDir, "file2"),
		"/file2", TransferDownload, 0, 0, 0, 0, true, fsUser, dataprovider.TransferQuota{AllowedDLSize: 100})
	transfer4.BytesSent = 150
	Connections.Add(fakeConn4)
	Connections.checkTransfers()
	assert.Nil(t, transfer3.errAbort)
	assert.Nil(t, transfer4.errAbort)

	transfer3.BytesSent = 512 * 1024
	transfer4.BytesSent = 512*1024 + 1
	Connections.checkTransfers()
	if assert.Error(t, transfer3.errAbort) {
		assert.Contains(t, transfer3.errAbort.Error(), ErrReadQuotaExceeded.Error())
	}
	if assert.Error(t, transfer4.errAbort) {
		assert.Contains(t, transfer4.errAbort.Error(), ErrReadQuotaExceeded.Error())
	}

	Connections.Remove(fakeConn3.GetID())
	Connections.Remove(fakeConn4.GetID())
	stats := Connections.GetStats()
	assert.Len(t, stats, 0)

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
	usersToFetch, aggregations := checker.aggregateUploadTransfers()
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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 1)

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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 2)

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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 0)
	assert.Len(t, aggregations, 3)

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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok := usersToFetch["user"]
	assert.True(t, ok)
	assert.False(t, val)
	assert.Len(t, aggregations, 3)
	aggregate, ok := aggregations[0]
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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.False(t, val)
	assert.Len(t, aggregations, 3)
	aggregate, ok = aggregations[0]
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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.True(t, val)
	assert.Len(t, aggregations, 3)
	aggregate, ok = aggregations[0]
	assert.True(t, ok)
	assert.Len(t, aggregate, 3)
	aggregate, ok = aggregations[1]
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

	usersToFetch, aggregations = checker.aggregateUploadTransfers()
	assert.Len(t, usersToFetch, 1)
	val, ok = usersToFetch["user"]
	assert.True(t, ok)
	assert.True(t, val)
	assert.Len(t, aggregations, 3)
	aggregate, ok = aggregations[0]
	assert.True(t, ok)
	assert.Len(t, aggregate, 4)
	aggregate, ok = aggregations[1]
	assert.True(t, ok)
	assert.Len(t, aggregate, 2)
}

func TestDataTransferExceeded(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			TotalDataTransfer: 1,
		},
	}
	transfer := dataprovider.ActiveTransfer{
		CurrentULSize: 0,
		CurrentDLSize: 0,
	}
	user.UsedDownloadDataTransfer = 1024 * 1024
	user.UsedUploadDataTransfer = 512 * 1024
	checker := transfersCheckerMem{}
	res := checker.isDataTransferExceeded(user, transfer, 100, 100)
	assert.False(t, res)
	transfer.CurrentULSize = 1
	res = checker.isDataTransferExceeded(user, transfer, 100, 100)
	assert.True(t, res)
	user.UsedDownloadDataTransfer = 512*1024 - 100
	user.UsedUploadDataTransfer = 512*1024 - 100
	res = checker.isDataTransferExceeded(user, transfer, 100, 100)
	assert.False(t, res)
	res = checker.isDataTransferExceeded(user, transfer, 101, 100)
	assert.True(t, res)

	user.TotalDataTransfer = 0
	user.DownloadDataTransfer = 1
	user.UsedDownloadDataTransfer = 512 * 1024
	transfer.CurrentULSize = 0
	transfer.CurrentDLSize = 100
	res = checker.isDataTransferExceeded(user, transfer, 0, 512*1024)
	assert.False(t, res)
	res = checker.isDataTransferExceeded(user, transfer, 0, 512*1024+1)
	assert.True(t, res)

	user.DownloadDataTransfer = 0
	user.UploadDataTransfer = 1
	user.UsedUploadDataTransfer = 512 * 1024
	transfer.CurrentULSize = 0
	transfer.CurrentDLSize = 0
	res = checker.isDataTransferExceeded(user, transfer, 512*1024+1, 0)
	assert.False(t, res)
	transfer.CurrentULSize = 1
	res = checker.isDataTransferExceeded(user, transfer, 512*1024+1, 0)
	assert.True(t, res)
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
			Filters: dataprovider.UserFilters{
				BaseUserFilters: sdk.BaseUserFilters{
					DataTransferLimits: []sdk.DataTransferLimit{
						{
							Sources:              []string{"172.16.0.0/16"},
							UploadDataTransfer:   50,
							DownloadDataTransfer: 80,
						},
					},
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
		ul, dl, total := user.GetDataTransferLimits("127.1.1.1")
		assert.Equal(t, int64(0), ul)
		assert.Equal(t, int64(0), dl)
		assert.Equal(t, int64(0), total)
		ul, dl, total = user.GetDataTransferLimits("172.16.2.3")
		assert.Equal(t, int64(50*1024*1024), ul)
		assert.Equal(t, int64(80*1024*1024), dl)
		assert.Equal(t, int64(0), total)
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

func TestDBTransferChecker(t *testing.T) {
	if !isDbTransferCheckerSupported() {
		t.Skip("this test is not supported with the current database provider")
	}
	providerConf := dataprovider.GetProviderConfig()
	err := dataprovider.Close()
	assert.NoError(t, err)
	providerConf.IsShared = 1
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	c := getTransfersChecker(1)
	checker, ok := c.(*transfersCheckerDB)
	assert.True(t, ok)
	assert.True(t, checker.lastCleanup.IsZero())
	transfer1 := dataprovider.ActiveTransfer{
		ID:         1,
		Type:       TransferDownload,
		ConnID:     xid.New().String(),
		Username:   "user1",
		FolderName: "folder1",
		IP:         "127.0.0.1",
	}
	checker.AddTransfer(transfer1)
	transfers, err := dataprovider.GetActiveTransfers(time.Now().Add(24 * time.Hour))
	assert.NoError(t, err)
	assert.Len(t, transfers, 0)
	transfers, err = dataprovider.GetActiveTransfers(time.Now().Add(-periodicTimeoutCheckInterval * 2))
	assert.NoError(t, err)
	var createdAt, updatedAt int64
	if assert.Len(t, transfers, 1) {
		transfer := transfers[0]
		assert.Equal(t, transfer1.ID, transfer.ID)
		assert.Equal(t, transfer1.Type, transfer.Type)
		assert.Equal(t, transfer1.ConnID, transfer.ConnID)
		assert.Equal(t, transfer1.Username, transfer.Username)
		assert.Equal(t, transfer1.IP, transfer.IP)
		assert.Equal(t, transfer1.FolderName, transfer.FolderName)
		assert.Greater(t, transfer.CreatedAt, int64(0))
		assert.Greater(t, transfer.UpdatedAt, int64(0))
		assert.Equal(t, int64(0), transfer.CurrentDLSize)
		assert.Equal(t, int64(0), transfer.CurrentULSize)
		createdAt = transfer.CreatedAt
		updatedAt = transfer.UpdatedAt
	}
	time.Sleep(100 * time.Millisecond)
	checker.UpdateTransferCurrentSizes(100, 150, transfer1.ID, transfer1.ConnID)
	transfers, err = dataprovider.GetActiveTransfers(time.Now().Add(-periodicTimeoutCheckInterval * 2))
	assert.NoError(t, err)
	if assert.Len(t, transfers, 1) {
		transfer := transfers[0]
		assert.Equal(t, int64(150), transfer.CurrentDLSize)
		assert.Equal(t, int64(100), transfer.CurrentULSize)
		assert.Equal(t, createdAt, transfer.CreatedAt)
		assert.Greater(t, transfer.UpdatedAt, updatedAt)
	}
	res := checker.GetOverquotaTransfers()
	assert.Len(t, res, 0)

	checker.RemoveTransfer(transfer1.ID, transfer1.ConnID)
	transfers, err = dataprovider.GetActiveTransfers(time.Now().Add(-periodicTimeoutCheckInterval * 2))
	assert.NoError(t, err)
	assert.Len(t, transfers, 0)

	err = dataprovider.Close()
	assert.NoError(t, err)
	res = checker.GetOverquotaTransfers()
	assert.Len(t, res, 0)
	providerConf.IsShared = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func isDbTransferCheckerSupported() bool {
	// SQLite shares the implementation with other SQL-based provider but it makes no sense
	// to use it outside test cases
	switch dataprovider.GetProviderStatus().Driver {
	case dataprovider.MySQLDataProviderName, dataprovider.PGSQLDataProviderName,
		dataprovider.CockroachDataProviderName, dataprovider.SQLiteDataProviderName:
		return true
	default:
		return false
	}
}
