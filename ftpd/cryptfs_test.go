package ftpd_test

import (
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
)

func TestBasicFTPHandlingCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		assert.Len(t, common.Connections.GetStats(), 1)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		encryptedFileSize, err := getEncryptedFileSize(testFileSize)
		assert.NoError(t, err)
		expectedQuotaSize := encryptedFileSize
		expectedQuotaFiles := 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		// overwrite an existing file
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		info, err := os.Stat(localDownloadPath)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, info.Size())
		}
		list, err := client.List(".")
		if assert.NoError(t, err) {
			assert.Len(t, list, 1)
			assert.Equal(t, testFileSize, int64(list[0].Size))
		}
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Rename(testFileName, testFileName+"1")
		assert.NoError(t, err)
		err = client.Delete(testFileName)
		assert.Error(t, err)
		err = client.Delete(testFileName + "1")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-encryptedFileSize, user.UsedQuotaSize)
		curDir, err := client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, "/", curDir)
		}
		testDir := "testDir"
		err = client.MakeDir(testDir)
		assert.NoError(t, err)
		err = client.ChangeDir(testDir)
		assert.NoError(t, err)
		curDir, err = client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, path.Join("/", testDir), curDir)
		}
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		size, err := client.FileSize(path.Join("/", testDir, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, size)
		err = client.ChangeDirToParent()
		assert.NoError(t, err)
		curDir, err = client.CurrentDir()
		if assert.NoError(t, err) {
			assert.Equal(t, "/", curDir)
		}
		err = client.Delete(path.Join("/", testDir, testFileName))
		assert.NoError(t, err)
		err = client.Delete(testDir)
		assert.Error(t, err)
		err = client.RemoveDir(testDir)
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
}

func TestZeroBytesTransfersCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFileName := "testfilename"
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, "emptydownload")
		err = ioutil.WriteFile(localDownloadPath, []byte(""), os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(localDownloadPath, testFileName, 0, client, 0)
		assert.NoError(t, err)
		size, err := client.FileSize(testFileName)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), size)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		assert.NoFileExists(t, localDownloadPath)
		err = ftpDownloadFile(testFileName, localDownloadPath, 0, client, 0)
		assert.NoError(t, err)
		info, err := os.Stat(localDownloadPath)
		if assert.NoError(t, err) {
			assert.Equal(t, int64(0), info.Size())
		}
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestResumeCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		data := []byte("test data")
		err = ioutil.WriteFile(testFilePath, data, os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		// upload resume is not supported
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)+5), client, 5)
		assert.Error(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(4), client, 5)
		assert.NoError(t, err)
		readed, err := ioutil.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, data[5:], readed)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(8), client, 1)
		assert.NoError(t, err)
		readed, err = ioutil.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, data[1:], readed)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(0), client, 9)
		assert.NoError(t, err)
		err = client.Delete(testFileName)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		// now append to a file
		srcFile, err := os.Open(testFilePath)
		if assert.NoError(t, err) {
			err = client.Append(testFileName, srcFile)
			assert.Error(t, err)
			err = srcFile.Close()
			assert.NoError(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, int64(len(data)), size)
			err = ftpDownloadFile(testFileName, localDownloadPath, int64(len(data)), client, 0)
			assert.NoError(t, err)
			readed, err = ioutil.ReadFile(localDownloadPath)
			assert.NoError(t, err)
			assert.Equal(t, data, readed)
		}
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func getTestUserWithCryptFs() dataprovider.User {
	user := getTestUser()
	user.FsConfig.Provider = dataprovider.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("testPassphrase")
	return user
}

func getEncryptedFileSize(size int64) (int64, error) {
	encSize, err := sio.EncryptedSize(uint64(size))
	return int64(encSize) + 33, err
}
