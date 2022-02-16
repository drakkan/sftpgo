package sftpd_test

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpdtest"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	testPassphrase = "test passphrase"
)

func TestBasicSFTPCryptoHandling(t *testing.T) {
	usePubKey := false
	u := getTestUserWithCryptFs(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		encryptedFileSize, err := getEncryptedFileSize(testFileSize)
		assert.NoError(t, err)
		expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client)
		assert.Error(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		initialHash, err := computeHashForFile(sha256.New(), testFilePath)
		assert.NoError(t, err)
		downloadedFileHash, err := computeHashForFile(sha256.New(), localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, initialHash, downloadedFileHash)
		info, err := os.Stat(filepath.Join(user.HomeDir, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, encryptedFileSize, info.Size())
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		result, err := client.ReadDir(".")
		assert.NoError(t, err)
		if assert.Len(t, result, 1) {
			assert.Equal(t, testFileSize, result[0].Size())
		}
		info, err = client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, info.Size())
		}
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-encryptedFileSize, user.UsedQuotaSize)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOpenReadWriteCryptoFs(t *testing.T) {
	// read and write is not supported on crypto fs
	usePubKey := false
	u := getTestUserWithCryptFs(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("sample test data")
			n, err := sftpFile.Write(testData)
			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			buffer := make([]byte, 128)
			_, err = sftpFile.ReadAt(buffer, 1)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
			}
			err = sftpFile.Close()
			assert.NoError(t, err)
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestEmptyFile(t *testing.T) {
	usePubKey := true
	u := getTestUserWithCryptFs(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("")
			n, err := sftpFile.Write(testData)
			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			err = sftpFile.Close()
			assert.NoError(t, err)
		}
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			assert.Equal(t, int64(0), info.Size())
		}
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, 0, client)
		assert.NoError(t, err)
		encryptedFileSize, err := getEncryptedFileSize(0)
		assert.NoError(t, err)
		info, err = os.Stat(filepath.Join(user.HomeDir, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, encryptedFileSize, info.Size())
		}
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadResumeCryptFs(t *testing.T) {
	// resuming uploads is not supported
	usePubKey := true
	u := getTestUserWithCryptFs(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		appendDataSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = appendToTestFile(testFilePath, appendDataSize)
		assert.NoError(t, err)
		err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize, false, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaFileReplaceCryptFs(t *testing.T) {
	usePubKey := false
	u := getTestUserWithCryptFs(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	encryptedFileSize, err := getEncryptedFileSize(testFileSize)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) { //nolint:dupl
		defer conn.Close()
		defer client.Close()
		expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// now replace the same file, the quota must not change
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		// now create a symlink, replace it with a file and check the quota
		// replacing a symlink is like uploading a new file
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		expectedQuotaFiles = expectedQuotaFiles + 1
		expectedQuotaSize = expectedQuotaSize + encryptedFileSize
		err = sftpUploadFile(testFilePath, testFileName+".link", testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	}
	// now set a quota size restriction and upload the same file, upload should fail for space limit exceeded
	user.QuotaSize = encryptedFileSize*2 - 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err, "quota size exceeded, file upload must fail")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaScanCryptFs(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUserWithCryptFs(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	encryptedFileSize, err := getEncryptedFileSize(testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// create user with the same home dir, so there is at least an untracked file
	user, _, err = httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		scans, _, err := httpdtest.GetQuotaScans(http.StatusOK)
		if err == nil {
			return len(scans) == 0
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestGetMimeTypeCryptFs(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUserWithCryptFs(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("some UTF-8 text so we should get a text/plain mime type")
			n, err := sftpFile.Write(testData)
			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			err = sftpFile.Close()
			assert.NoError(t, err)
		}
	}

	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(testPassphrase)
	fs, err := user.GetFilesystem("connID")
	if assert.NoError(t, err) {
		assert.True(t, vfs.IsCryptOsFs(fs))
		mime, err := fs.GetMimeType(filepath.Join(user.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		assert.Equal(t, "text/plain; charset=utf-8", mime)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestTruncate(t *testing.T) {
	// truncate is not supported
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUserWithCryptFs(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		f, err := client.OpenFile(testFileName, os.O_WRONLY|os.O_CREATE)
		if assert.NoError(t, err) {
			err = f.Truncate(0)
			assert.NoError(t, err)
			err = f.Truncate(1)
			assert.Error(t, err)
		}
		err = f.Close()
		assert.NoError(t, err)
		err = client.Truncate(testFileName, 0)
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPBasicHandlingCryptoFs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUserWithCryptFs(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(131074)
	encryptedFileSize, err := getEncryptedFileSize(testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	// test to download a missing file
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "downloading a missing file via scp must fail")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.NoError(t, err)
	fi, err := os.Stat(localPath)
	if assert.NoError(t, err) {
		assert.Equal(t, testFileSize, fi.Size())
	}
	fi, err = os.Stat(filepath.Join(user.GetHomeDir(), testFileName))
	if assert.NoError(t, err) {
		assert.Equal(t, encryptedFileSize, fi.Size())
	}
	err = os.Remove(localPath)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	// now overwrite the existing file
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestSCPRecursiveCryptFs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUserWithCryptFs(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testBaseDirName := "atestdir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testBaseDirDownName := "test_dir_down" //nolint:goconst
	testBaseDirDownPath := filepath.Join(homeBasePath, testBaseDirDownName)
	testFilePath := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testBaseDirName, testFileName)
	testFileSize := int64(131074)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize)
	assert.NoError(t, err)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testBaseDirName))
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.NoError(t, err)
	// overwrite existing dir
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
	assert.NoError(t, err)
	// test download without passing -r
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, false)
	assert.Error(t, err, "recursive download without -r must fail")

	fi, err := os.Stat(filepath.Join(testBaseDirDownPath, testFileName))
	if assert.NoError(t, err) {
		assert.Equal(t, testFileSize, fi.Size())
	}
	fi, err = os.Stat(filepath.Join(testBaseDirDownPath, testBaseDirName, testFileName))
	if assert.NoError(t, err) {
		assert.Equal(t, testFileSize, fi.Size())
	}
	// upload to a non existent dir
	remoteUpPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/non_existent_dir")
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.Error(t, err, "uploading via scp to a non existent dir must fail")

	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirDownPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func getEncryptedFileSize(size int64) (int64, error) {
	encSize, err := sio.EncryptedSize(uint64(size))
	return int64(encSize) + 33, err
}

func getTestUserWithCryptFs(usePubKey bool) dataprovider.User {
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = sdk.CryptedFilesystemProvider
	u.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(testPassphrase)
	return u
}
