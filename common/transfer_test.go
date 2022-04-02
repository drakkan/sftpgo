package common

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/vfs"
)

func TestTransferUpdateQuota(t *testing.T) {
	conn := NewBaseConnection("", ProtocolSFTP, "", "", dataprovider.User{})
	transfer := BaseTransfer{
		Connection:    conn,
		transferType:  TransferUpload,
		BytesReceived: 123,
		Fs:            vfs.NewOsFs("", os.TempDir(), ""),
	}
	errFake := errors.New("fake error")
	transfer.TransferError(errFake)
	assert.False(t, transfer.updateQuota(1, 0))
	err := transfer.Close()
	if assert.Error(t, err) {
		assert.EqualError(t, err, errFake.Error())
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	vdirPath := "/vdir"
	conn.User.VirtualFolders = append(conn.User.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	transfer.ErrTransfer = nil
	transfer.BytesReceived = 1
	transfer.requestPath = "/vdir/file"
	assert.True(t, transfer.updateQuota(1, 0))
	err = transfer.Close()
	assert.NoError(t, err)
}

func TestTransferThrottling(t *testing.T) {
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:          "test",
			UploadBandwidth:   50,
			DownloadBandwidth: 40,
		},
	}
	fs := vfs.NewOsFs("", os.TempDir(), "")
	testFileSize := int64(131072)
	wantedUploadElapsed := 1000 * (testFileSize / 1024) / u.UploadBandwidth
	wantedDownloadElapsed := 1000 * (testFileSize / 1024) / u.DownloadBandwidth
	// some tolerance
	wantedUploadElapsed -= wantedDownloadElapsed / 10
	wantedDownloadElapsed -= wantedDownloadElapsed / 10
	conn := NewBaseConnection("id", ProtocolSCP, "", "", u)
	transfer := NewBaseTransfer(nil, conn, nil, "", "", "", TransferUpload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	transfer.BytesReceived = testFileSize
	transfer.Connection.UpdateLastActivity()
	startTime := transfer.Connection.GetLastActivity()
	transfer.HandleThrottle()
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	assert.GreaterOrEqual(t, elapsed, wantedUploadElapsed, "upload bandwidth throttling not respected")
	err := transfer.Close()
	assert.NoError(t, err)

	transfer = NewBaseTransfer(nil, conn, nil, "", "", "", TransferDownload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	transfer.BytesSent = testFileSize
	transfer.Connection.UpdateLastActivity()
	startTime = transfer.Connection.GetLastActivity()

	transfer.HandleThrottle()
	elapsed = time.Since(startTime).Nanoseconds() / 1000000
	assert.GreaterOrEqual(t, elapsed, wantedDownloadElapsed, "download bandwidth throttling not respected")
	err = transfer.Close()
	assert.NoError(t, err)
}

func TestRealPath(t *testing.T) {
	testFile := filepath.Join(os.TempDir(), "afile.txt")
	fs := vfs.NewOsFs("123", os.TempDir(), "")
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  os.TempDir(),
		},
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	file, err := os.Create(testFile)
	require.NoError(t, err)
	conn := NewBaseConnection(fs.ConnectionID(), ProtocolSFTP, "", "", u)
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file",
		TransferUpload, 0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	rPath := transfer.GetRealFsPath(testFile)
	assert.Equal(t, testFile, rPath)
	rPath = conn.getRealFsPath(testFile)
	assert.Equal(t, testFile, rPath)
	err = transfer.Close()
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)
	transfer.File = nil
	rPath = transfer.GetRealFsPath(testFile)
	assert.Equal(t, testFile, rPath)
	rPath = transfer.GetRealFsPath("")
	assert.Empty(t, rPath)
	err = os.Remove(testFile)
	assert.NoError(t, err)
	assert.Len(t, conn.GetTransfers(), 0)
}

func TestTruncate(t *testing.T) {
	testFile := filepath.Join(os.TempDir(), "transfer_test_file")
	fs := vfs.NewOsFs("123", os.TempDir(), "")
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  os.TempDir(),
		},
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	file, err := os.Create(testFile)
	if !assert.NoError(t, err) {
		assert.FailNow(t, "unable to open test file")
	}
	_, err = file.Write([]byte("hello"))
	assert.NoError(t, err)
	conn := NewBaseConnection(fs.ConnectionID(), ProtocolSFTP, "", "", u)
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 5,
		100, 0, false, fs, dataprovider.TransferQuota{})

	err = conn.SetStat("/transfer_test_file", &StatAttributes{
		Size:  2,
		Flags: StatAttrSize,
	})
	assert.NoError(t, err)
	assert.Equal(t, int64(103), transfer.MaxWriteSize)
	err = transfer.Close()
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)
	fi, err := os.Stat(testFile)
	if assert.NoError(t, err) {
		assert.Equal(t, int64(2), fi.Size())
	}

	transfer = NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 0,
		100, 0, true, fs, dataprovider.TransferQuota{})
	// file.Stat will fail on a closed file
	err = conn.SetStat("/transfer_test_file", &StatAttributes{
		Size:  2,
		Flags: StatAttrSize,
	})
	assert.Error(t, err)
	err = transfer.Close()
	assert.NoError(t, err)

	transfer = NewBaseTransfer(nil, conn, nil, testFile, testFile, "", TransferUpload, 0, 0, 0, 0, true,
		fs, dataprovider.TransferQuota{})
	_, err = transfer.Truncate("mismatch", 0)
	assert.EqualError(t, err, errTransferMismatch.Error())
	_, err = transfer.Truncate(testFile, 0)
	assert.NoError(t, err)
	_, err = transfer.Truncate(testFile, 1)
	assert.EqualError(t, err, vfs.ErrVfsUnsupported.Error())

	err = transfer.Close()
	assert.NoError(t, err)

	err = os.Remove(testFile)
	assert.NoError(t, err)

	assert.Len(t, conn.GetTransfers(), 0)
}

func TestTransferErrors(t *testing.T) {
	isCancelled := false
	cancelFn := func() {
		isCancelled = true
	}
	testFile := filepath.Join(os.TempDir(), "transfer_test_file")
	fs := vfs.NewOsFs("id", os.TempDir(), "")
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test",
			HomeDir:  os.TempDir(),
		},
	}
	err := os.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	file, err := os.Open(testFile)
	if !assert.NoError(t, err) {
		assert.FailNow(t, "unable to open test file")
	}
	conn := NewBaseConnection("id", ProtocolSFTP, "", "", u)
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload,
		0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	assert.Nil(t, transfer.cancelFn)
	assert.Equal(t, testFile, transfer.GetFsPath())
	transfer.SetCancelFn(cancelFn)
	errFake := errors.New("err fake")
	transfer.BytesReceived = 9
	transfer.TransferError(ErrQuotaExceeded)
	assert.True(t, isCancelled)
	transfer.TransferError(errFake)
	assert.Error(t, transfer.ErrTransfer, ErrQuotaExceeded.Error())
	// the file is closed from the embedding struct before to call close
	err = file.Close()
	assert.NoError(t, err)
	err = transfer.Close()
	if assert.Error(t, err) {
		assert.Error(t, err, ErrQuotaExceeded.Error())
	}
	assert.NoFileExists(t, testFile)

	err = os.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	file, err = os.Open(testFile)
	if !assert.NoError(t, err) {
		assert.FailNow(t, "unable to open test file")
	}
	fsPath := filepath.Join(os.TempDir(), "test_file")
	transfer = NewBaseTransfer(file, conn, nil, fsPath, file.Name(), "/test_file", TransferUpload, 0, 0, 0, 0, true,
		fs, dataprovider.TransferQuota{})
	transfer.BytesReceived = 9
	transfer.TransferError(errFake)
	assert.Error(t, transfer.ErrTransfer, errFake.Error())
	// the file is closed from the embedding struct before to call close
	err = file.Close()
	assert.NoError(t, err)
	err = transfer.Close()
	if assert.Error(t, err) {
		assert.Error(t, err, errFake.Error())
	}
	assert.NoFileExists(t, testFile)

	err = os.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	file, err = os.Open(testFile)
	if !assert.NoError(t, err) {
		assert.FailNow(t, "unable to open test file")
	}
	transfer = NewBaseTransfer(file, conn, nil, fsPath, file.Name(), "/test_file", TransferUpload, 0, 0, 0, 0, true,
		fs, dataprovider.TransferQuota{})
	transfer.BytesReceived = 9
	// the file is closed from the embedding struct before to call close
	err = file.Close()
	assert.NoError(t, err)
	err = transfer.Close()
	assert.NoError(t, err)
	assert.NoFileExists(t, testFile)
	assert.FileExists(t, fsPath)
	err = os.Remove(fsPath)
	assert.NoError(t, err)

	assert.Len(t, conn.GetTransfers(), 0)
}

func TestRemovePartialCryptoFile(t *testing.T) {
	testFile := filepath.Join(os.TempDir(), "transfer_test_file")
	fs, err := vfs.NewCryptFs("id", os.TempDir(), "", vfs.CryptFsConfig{Passphrase: kms.NewPlainSecret("secret")})
	require.NoError(t, err)
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test",
			HomeDir:  os.TempDir(),
		},
	}
	conn := NewBaseConnection(fs.ConnectionID(), ProtocolSFTP, "", "", u)
	transfer := NewBaseTransfer(nil, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload,
		0, 0, 0, 0, true, fs, dataprovider.TransferQuota{})
	transfer.ErrTransfer = errors.New("test error")
	_, err = transfer.getUploadFileSize()
	assert.Error(t, err)
	err = os.WriteFile(testFile, []byte("test data"), os.ModePerm)
	assert.NoError(t, err)
	size, err := transfer.getUploadFileSize()
	assert.NoError(t, err)
	assert.Equal(t, int64(9), size)
	assert.NoFileExists(t, testFile)
}

func TestFTPMode(t *testing.T) {
	conn := NewBaseConnection("", ProtocolFTP, "", "", dataprovider.User{})
	transfer := BaseTransfer{
		Connection:    conn,
		transferType:  TransferUpload,
		BytesReceived: 123,
		Fs:            vfs.NewOsFs("", os.TempDir(), ""),
	}
	assert.Empty(t, transfer.ftpMode)
	transfer.SetFtpMode("active")
	assert.Equal(t, "active", transfer.ftpMode)
}

func TestTransferQuota(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			TotalDataTransfer:    -1,
			UploadDataTransfer:   -1,
			DownloadDataTransfer: -1,
		},
	}
	user.Filters.DataTransferLimits = []sdk.DataTransferLimit{
		{
			Sources:              []string{"127.0.0.1/32", "192.168.1.0/24"},
			TotalDataTransfer:    100,
			UploadDataTransfer:   0,
			DownloadDataTransfer: 0,
		},
		{
			Sources:              []string{"172.16.0.0/24"},
			TotalDataTransfer:    0,
			UploadDataTransfer:   120,
			DownloadDataTransfer: 150,
		},
	}
	ul, dl, total := user.GetDataTransferLimits("127.0.1.1")
	assert.Equal(t, int64(0), ul)
	assert.Equal(t, int64(0), dl)
	assert.Equal(t, int64(0), total)
	ul, dl, total = user.GetDataTransferLimits("127.0.0.1")
	assert.Equal(t, int64(0), ul)
	assert.Equal(t, int64(0), dl)
	assert.Equal(t, int64(100*1048576), total)
	ul, dl, total = user.GetDataTransferLimits("192.168.1.4")
	assert.Equal(t, int64(0), ul)
	assert.Equal(t, int64(0), dl)
	assert.Equal(t, int64(100*1048576), total)
	ul, dl, total = user.GetDataTransferLimits("172.16.0.2")
	assert.Equal(t, int64(120*1048576), ul)
	assert.Equal(t, int64(150*1048576), dl)
	assert.Equal(t, int64(0), total)
	transferQuota := dataprovider.TransferQuota{}
	assert.True(t, transferQuota.HasDownloadSpace())
	assert.True(t, transferQuota.HasUploadSpace())
	transferQuota.TotalSize = -1
	transferQuota.ULSize = -1
	transferQuota.DLSize = -1
	assert.True(t, transferQuota.HasDownloadSpace())
	assert.True(t, transferQuota.HasUploadSpace())
	transferQuota.TotalSize = 100
	transferQuota.AllowedTotalSize = 10
	assert.True(t, transferQuota.HasDownloadSpace())
	assert.True(t, transferQuota.HasUploadSpace())
	transferQuota.AllowedTotalSize = 0
	assert.False(t, transferQuota.HasDownloadSpace())
	assert.False(t, transferQuota.HasUploadSpace())
	transferQuota.TotalSize = 0
	transferQuota.DLSize = 100
	transferQuota.ULSize = 50
	transferQuota.AllowedTotalSize = 0
	assert.False(t, transferQuota.HasDownloadSpace())
	assert.False(t, transferQuota.HasUploadSpace())
	transferQuota.AllowedDLSize = 1
	transferQuota.AllowedULSize = 1
	assert.True(t, transferQuota.HasDownloadSpace())
	assert.True(t, transferQuota.HasUploadSpace())
	transferQuota.AllowedDLSize = -10
	transferQuota.AllowedULSize = -1
	assert.False(t, transferQuota.HasDownloadSpace())
	assert.False(t, transferQuota.HasUploadSpace())

	conn := NewBaseConnection("", ProtocolSFTP, "", "", user)
	transfer := NewBaseTransfer(nil, conn, nil, "file.txt", "file.txt", "/transfer_test_file", TransferUpload,
		0, 0, 0, 0, true, vfs.NewOsFs("", os.TempDir(), ""), dataprovider.TransferQuota{})
	err := transfer.CheckRead()
	assert.NoError(t, err)
	err = transfer.CheckWrite()
	assert.NoError(t, err)

	transfer.transferQuota = dataprovider.TransferQuota{
		AllowedTotalSize: 10,
	}
	transfer.BytesReceived = 5
	transfer.BytesSent = 4
	err = transfer.CheckRead()
	assert.NoError(t, err)
	err = transfer.CheckWrite()
	assert.NoError(t, err)

	transfer.BytesSent = 6
	err = transfer.CheckRead()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), ErrReadQuotaExceeded.Error())
	}
	err = transfer.CheckWrite()
	assert.True(t, conn.IsQuotaExceededError(err))

	transferQuota = dataprovider.TransferQuota{
		AllowedTotalSize: 0,
		AllowedULSize:    10,
		AllowedDLSize:    5,
	}
	transfer.transferQuota = transferQuota
	assert.Equal(t, transferQuota, transfer.GetTransferQuota())
	err = transfer.CheckRead()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), ErrReadQuotaExceeded.Error())
	}
	err = transfer.CheckWrite()
	assert.NoError(t, err)

	transfer.BytesReceived = 11
	err = transfer.CheckRead()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), ErrReadQuotaExceeded.Error())
	}
	err = transfer.CheckWrite()
	assert.True(t, conn.IsQuotaExceededError(err))
}

func TestUploadOutsideHomeRenameError(t *testing.T) {
	oldTempPath := Config.TempPath

	conn := NewBaseConnection("", ProtocolSFTP, "", "", dataprovider.User{})
	transfer := BaseTransfer{
		Connection:    conn,
		transferType:  TransferUpload,
		BytesReceived: 123,
		Fs:            vfs.NewOsFs("", filepath.Join(os.TempDir(), "home"), ""),
	}

	fileName := filepath.Join(os.TempDir(), "_temp")
	err := os.WriteFile(fileName, []byte(`data`), 0644)
	assert.NoError(t, err)

	transfer.effectiveFsPath = fileName
	res := transfer.checkUploadOutsideHomeDir(os.ErrPermission)
	assert.Equal(t, 0, res)

	Config.TempPath = filepath.Clean(os.TempDir())
	res = transfer.checkUploadOutsideHomeDir(nil)
	assert.Equal(t, 0, res)
	assert.Greater(t, transfer.BytesReceived, int64(0))
	res = transfer.checkUploadOutsideHomeDir(os.ErrPermission)
	assert.Equal(t, 1, res)
	assert.Equal(t, int64(0), transfer.BytesReceived)
	assert.NoFileExists(t, fileName)

	Config.TempPath = oldTempPath
}
