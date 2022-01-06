package ftpd_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpdtest"
	"github.com/drakkan/sftpgo/v2/kms"
)

func TestBasicFTPHandlingCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
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
			assert.Len(t, list, 2)
			assert.Equal(t, ".", list[0].Name)
			assert.Equal(t, testFileSize, int64(list[1].Size))
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Rename(testFileName, testFileName+"1")
		assert.NoError(t, err)
		err = client.Delete(testFileName)
		assert.Error(t, err)
		err = client.Delete(testFileName + "1")
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
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
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return common.Connections.GetClientConnections() == 0 }, 1000*time.Millisecond,
		50*time.Millisecond)
}

func TestZeroBytesTransfersCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		testFileName := "testfilename"
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, "emptydownload")
		err = os.WriteFile(localDownloadPath, []byte(""), os.ModePerm)
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
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestResumeCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		data := []byte("test data")
		err = os.WriteFile(testFilePath, data, os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		// resuming uploads is not supported
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)+5), client, 5)
		assert.Error(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(4), client, 5)
		assert.NoError(t, err)
		readed, err := os.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, data[5:], readed)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(8), client, 1)
		assert.NoError(t, err)
		readed, err = os.ReadFile(localDownloadPath)
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
			readed, err = os.ReadFile(localDownloadPath)
			assert.NoError(t, err)
			assert.Equal(t, data, readed)
		}
		// now test a download resume using a bigger file
		testFileSize := int64(655352)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		initialHash, err := computeHashForFile(sha256.New(), testFilePath)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		downloadHash, err := computeHashForFile(sha256.New(), localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, initialHash, downloadHash)
		err = os.Truncate(localDownloadPath, 32767)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath+"_partial", testFileSize-32767, client, 32767)
		assert.NoError(t, err)
		file, err := os.OpenFile(localDownloadPath, os.O_APPEND|os.O_WRONLY, os.ModePerm)
		assert.NoError(t, err)
		file1, err := os.Open(localDownloadPath + "_partial")
		assert.NoError(t, err)
		_, err = io.Copy(file, file1)
		assert.NoError(t, err)
		err = file.Close()
		assert.NoError(t, err)
		err = file1.Close()
		assert.NoError(t, err)
		downloadHash, err = computeHashForFile(sha256.New(), localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, initialHash, downloadHash)

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath + "_partial")
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func getTestUserWithCryptFs() dataprovider.User {
	user := getTestUser()
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("testPassphrase")
	return user
}

func getEncryptedFileSize(size int64) (int64, error) {
	encSize, err := sio.EncryptedSize(uint64(size))
	return int64(encSize) + 33, err
}

func computeHashForFile(hasher hash.Hash, path string) (string, error) {
	hash := ""
	f, err := os.Open(path)
	if err != nil {
		return hash, err
	}
	defer f.Close()
	_, err = io.Copy(hasher, f)
	if err == nil {
		hash = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	return hash, err
}
