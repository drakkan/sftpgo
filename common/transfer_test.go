package common

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/sdk"
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
	transfer := NewBaseTransfer(nil, conn, nil, "", "", "", TransferUpload, 0, 0, 0, true, fs)
	transfer.BytesReceived = testFileSize
	transfer.Connection.UpdateLastActivity()
	startTime := transfer.Connection.GetLastActivity()
	transfer.HandleThrottle()
	elapsed := time.Since(startTime).Nanoseconds() / 1000000
	assert.GreaterOrEqual(t, elapsed, wantedUploadElapsed, "upload bandwidth throttling not respected")
	err := transfer.Close()
	assert.NoError(t, err)

	transfer = NewBaseTransfer(nil, conn, nil, "", "", "", TransferDownload, 0, 0, 0, true, fs)
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
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 0, 0, true, fs)
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
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 5, 100, false, fs)

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

	transfer = NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 0, 100, true, fs)
	// file.Stat will fail on a closed file
	err = conn.SetStat("/transfer_test_file", &StatAttributes{
		Size:  2,
		Flags: StatAttrSize,
	})
	assert.Error(t, err)
	err = transfer.Close()
	assert.NoError(t, err)

	transfer = NewBaseTransfer(nil, conn, nil, testFile, testFile, "", TransferUpload, 0, 0, 0, true, fs)
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
	transfer := NewBaseTransfer(file, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 0, 0, true, fs)
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
	transfer = NewBaseTransfer(file, conn, nil, fsPath, file.Name(), "/test_file", TransferUpload, 0, 0, 0, true, fs)
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
	transfer = NewBaseTransfer(file, conn, nil, fsPath, file.Name(), "/test_file", TransferUpload, 0, 0, 0, true, fs)
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
	fs, err := vfs.NewCryptFs("id", os.TempDir(), "", vfs.CryptFsConfig{CryptFsConfig: sdk.CryptFsConfig{Passphrase: kms.NewPlainSecret("secret")}})
	require.NoError(t, err)
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test",
			HomeDir:  os.TempDir(),
		},
	}
	conn := NewBaseConnection(fs.ConnectionID(), ProtocolSFTP, "", "", u)
	transfer := NewBaseTransfer(nil, conn, nil, testFile, testFile, "/transfer_test_file", TransferUpload, 0, 0, 0, true, fs)
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
