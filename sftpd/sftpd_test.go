package sftpd_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/pkg/sftp"
)

// To run test cases you need to manually start sftpgo using port 2022 for sftp and 8080 for http API

const (
	sftpServerAddr  = "127.0.0.1:2022"
	defaultUsername = "test_user"
	defaultPassword = "test_password"
	testPubKey      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	testPrivateKey  = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtN449A/nY5O6cSH/9Doa8a3ISU0WZJaHydTaCLuO+dkqtNpnV5mq
zFbKidXAI1eSwVctw9ReVOl1uK6aZF3lbXdOD8W9PXobR9KUUT2qBx5QC4ibfAqDKWymDA
PG9ylzz64hsYBqJr7VNk9kTFEUsDmWzLabLoH42Elnp8mF/lTkWIcpVp0ly/etS08gttXo
XenekJ1vRuxOYWDCEzGPU7kGc920TmM14k7IDdPoOh5+3sRUKedKeOUrVDH1f0n7QjHQsZ
cbshp8tgqzf734zu8cTqNrr+6taptdEOOij1iUL/qYGfzny/hA48tO5+UFUih5W8ftp0+E
NBIDkkGgk2MJ92I7QAXyMVsIABXco+mJT7pQi9tqlODGIQ3AOj0gcA3X/Ib8QX77Ih3TPi
XEh77/P1XiYZOgpp2cRmNH8QbqaL9u898hDvJwIPJPuj2lIltTElH7hjBf5LQfCzrLV7BD
10rM7sl4jr+A2q8jl1Ikp+25kainBBZSbrDummT9AAAFgDU/VLk1P1S5AAAAB3NzaC1yc2
EAAAGBALTeOPQP52OTunEh//Q6GvGtyElNFmSWh8nU2gi7jvnZKrTaZ1eZqsxWyonVwCNX
ksFXLcPUXlTpdbiummRd5W13Tg/FvT16G0fSlFE9qgceUAuIm3wKgylspgwDxvcpc8+uIb
GAaia+1TZPZExRFLA5lsy2my6B+NhJZ6fJhf5U5FiHKVadJcv3rUtPILbV6F3p3pCdb0bs
TmFgwhMxj1O5BnPdtE5jNeJOyA3T6Doeft7EVCnnSnjlK1Qx9X9J+0Ix0LGXG7IafLYKs3
+9+M7vHE6ja6/urWqbXRDjoo9YlC/6mBn858v4QOPLTuflBVIoeVvH7adPhDQSA5JBoJNj
CfdiO0AF8jFbCAAV3KPpiU+6UIvbapTgxiENwDo9IHAN1/yG/EF++yId0z4lxIe+/z9V4m
GToKadnEZjR/EG6mi/bvPfIQ7ycCDyT7o9pSJbUxJR+4YwX+S0Hws6y1ewQ9dKzO7JeI6/
gNqvI5dSJKftuZGopwQWUm6w7ppk/QAAAAMBAAEAAAGAHKnC+Nq0XtGAkIFE4N18e6SAwy
0WSWaZqmCzFQM0S2AhJnweOIG/0ZZHjsRzKKauOTmppQk40dgVsejpytIek9R+aH172gxJ
2n4Cx0UwduRU5x8FFQlNc/kl722B0JWfJuB/snOZXv6LJ4o5aObIkozt2w9tVFeAqjYn2S
1UsNOfRHBXGsTYwpRDwFWP56nKo2d2wBBTHDhCy6fb2dLW1fvSi/YspueOGIlHpvlYKi2/
CWqvs9xVrwcScMtiDoQYq0khhO0efLCxvg/o+W9CLMVM2ms4G1zoSUQKN0oYWWQJyW4+VI
YneWO8UpN0J3ElXKi7bhgAat7dBaM1g9IrAzk153DiEFZNsPxGOgL/+YdQN7zUBx/z7EkI
jyv80RV7fpUXvcq2p+qNl6UVig3VSzRrnsaJkUWu/A0u59ha7ocv6NxDIXjxpIDJme16GF
quiGVBQNnYJymS/vFEbGf6bgf7iRmMCRUMG4nqLA6fPYP9uAtch+CmDfVLZC/fIdC5AAAA
wQCDissV4zH6bfqgxJSuYNk8Vbb+19cF3b7gH1rVlB3zxpCAgcRgMHC+dP1z2NRx7UW9MR
nye6kjpkzZZ0OigLqo7TtEq8uTglD9o6W7mRXqhy5A/ySOmqPL3ernHHQhGuoNODYAHkOU
u2Rh8HXi+VLwKZcLInPOYJvcuLG4DxN8WfeVvlMHwhAOaTNNOtL4XZDHQeIPc4qHmJymmv
sV7GuyQ6yW5C10uoGdxRPd90Bh4z4h2bKfZFjvEBbSBVkqrlAAAADBAN/zNtNayd/dX7Cr
Nb4sZuzCh+CW4BH8GOePZWNCATwBbNXBVb5cR+dmuTqYm+Ekz0VxVQRA1TvKncluJOQpoa
Xj8r0xdIgqkehnfDPMKtYVor06B9Fl1jrXtXU0Vrr6QcBWruSVyK1ZxqcmcNK/+KolVepe
A6vcl/iKaG4U7su166nxLST06M2EgcSVsFJHpKn5+WAXC+X0Gx8kNjWIIb3GpiChdc0xZD
mq02xZthVJrTCVw/e7gfDoB2QRsNV8HwAAAMEAzsCghZVp+0YsYg9oOrw4tEqcbEXEMhwY
0jW8JNL8Spr1Ibp5Dw6bRSk5azARjmJtnMJhJ3oeHfF0eoISqcNuQXGndGQbVM9YzzAzc1
NbbCNsVroqKlChT5wyPNGS+phi2bPARBno7WSDvshTZ7dAVEP2c9MJW0XwoSevwKlhgSdt
RLFFQ/5nclJSdzPBOmQouC0OBcMFSrYtMeknJ4VvueVvve5HcHFaEsaMc7ABAGaLYaBQOm
iixITGvaNZh/tjAAAACW5pY29sYUBwMQE=
-----END OPENSSH PRIVATE KEY-----`
)

var (
	allPerms     = []string{dataprovider.PermAny}
	homeBasePath string
)

func init() {
	if runtime.GOOS == "windows" {
		homeBasePath = "C:\\"
	} else {
		homeBasePath = "/tmp"
	}
}

func getSftpClient(user dataprovider.User, usePubKey bool) (*sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: defaultUsername,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if usePubKey {
		key, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
		if err != nil {
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	return sftpClient, err
}

func createTestFile(path string, size int64) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, content, 0666)
}

func getTestUser(usePubKey bool) dataprovider.User {
	user := dataprovider.User{
		Username:    defaultUsername,
		Password:    defaultPassword,
		HomeDir:     filepath.Join(homeBasePath, defaultUsername),
		Permissions: allPerms,
	}
	if usePubKey {
		user.PublicKey = testPubKey
		user.Password = ""
	}
	return user
}

func sftpUploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *sftp.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	destFile, err := client.Create(remoteDestPath)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, srcFile)
	if expectedSize > 0 {
		fi, err := client.Lstat(remoteDestPath)
		if err != nil {
			return err
		}
		if fi.Size() != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", fi.Size(), expectedSize)
		}
	}
	return err
}

func sftpDownloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *sftp.Client) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()
	sftpSrcFile, err := client.Open(remoteSourcePath)
	if err != nil {
		return err
	}
	defer sftpSrcFile.Close()
	_, err = io.Copy(downloadDest, sftpSrcFile)
	if err != nil {
		return err
	}
	err = downloadDest.Sync()
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		fi, err := downloadDest.Stat()
		if err != nil {
			return err
		}
		if fi.Size() != expectedSize {
			return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", fi.Size(), expectedSize)
		}
	}
	return err
}

func TestBasicSFTPHandling(t *testing.T) {
	usePubKey := false
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		_, err = client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := user.UsedQuotaSize + testFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if err != nil {
			t.Errorf("error creating symlink: %v", err)
		}
		err = client.Remove(testFileName + ".link")
		if err != nil {
			t.Errorf("error removing symlink: %v", err)
		}
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if err != nil {
			t.Errorf("file download error: %v", err)
		}
		user, err = api.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if expectedQuotaFiles != user.UsedQuotaFiles {
			t.Errorf("quota files does not match, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
		}
		if expectedQuotaSize != user.UsedQuotaSize {
			t.Errorf("quota size does not match, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
		_, err = client.Lstat(testFileName)
		if err == nil {
			t.Errorf("stat for deleted file must not succeed")
		}
		user, err = api.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if (expectedQuotaFiles - 1) != user.UsedQuotaFiles {
			t.Errorf("quota files does not match after delete, expected: %v, actual: %v", expectedQuotaFiles-1, user.UsedQuotaFiles)
		}
		if (expectedQuotaSize - testFileSize) != user.UsedQuotaSize {
			t.Errorf("quota size does not match, expected: %v, actual: %v", expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		}
		err = client.Mkdir("test")
		if err != nil {
			t.Errorf("error mkdir: %v", err)
		}
		err = client.Rename("test", "test1")
		if err != nil {
			t.Errorf("error rename: %v", err)
		}
		err = client.Remove("test1")
		if err != nil {
			t.Errorf("error rmdir: %v", err)
		}
		err = client.MkdirAll("/test/test")
		if err != nil {
			t.Errorf("error mkdir all: %v", err)
		}
		err = client.Remove("/test")
		if err != nil {
			t.Errorf("error rmdir all: %v", err)
		}
		_, err = client.Lstat("/test")
		if err == nil {
			t.Errorf("stat for deleted dir must not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

// basic tests to verify virtual chroot, should be improved to cover more cases ...
func TestEscapeHomeDir(t *testing.T) {
	usePubKey := true
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		testDir := "testDir"
		linkPath := filepath.Join(homeBasePath, defaultUsername, testDir)
		err = os.Symlink(homeBasePath, linkPath)
		if err != nil {
			t.Errorf("error making local symlink: %v", err)
		}
		_, err = client.ReadDir(testDir)
		if err == nil {
			t.Errorf("reading a symbolic link outside home dir should not suceeded")
		}
		os.Remove(linkPath)
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		remoteDestPath := filepath.Join("..", "..", testFileName)
		err = sftpUploadFile(testFilePath, remoteDestPath, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		_, err = client.Lstat(testFileName)
		if err != nil {
			t.Errorf("file stat error: %v the file was created outside the user dir!", err)
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestHomeSpecialChars(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir = filepath.Join(homeBasePath, "abc açà#&%lk")
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		files, err := client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
		if len(files) < 1 {
			t.Errorf("expected at least 1 file in this dir")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLoginPubKey(t *testing.T) {
	usePubKey := true
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		_, err = client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLoginAfterUserUpdateEmptyPwd(t *testing.T) {
	usePubKey := false
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKey = ""
	// password and public key should remain unchanged
	_, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		_, err = client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLoginAfterUserUpdateEmptyPubKey(t *testing.T) {
	usePubKey := true
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKey = ""
	// password and public key should remain unchanged
	_, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		_, err = client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestMaxSessions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.MaxSessions = 1
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
		_, err = client.ReadDir(".")
		if err != nil {
			t.Errorf("unable to read remote dir: %v", err)
		}
		_, err = getSftpClient(user, usePubKey)
		if err == nil {
			t.Errorf("max sessions exceeded, new login should not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestQuotaScan(t *testing.T) {
	usePubKey := false
	user, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileSize := int64(65535)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	// create user with the same home dir, so there is at least an untracked file
	user, err = api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	err = api.StartQuotaScan(user, http.StatusCreated)
	if err != nil {
		t.Errorf("error starting quota scan: %v", err)
	}
	scans, err := api.GetQuotaScans(http.StatusOK)
	if err != nil {
		t.Errorf("error getting active quota scans: %v", err)
	}
	for len(scans) > 0 {
		scans, err = api.GetQuotaScans(http.StatusOK)
		if err != nil {
			t.Errorf("error getting active quota scans: %v", err)
			break
		}
	}
	user, err = api.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("error getting user: %v", err)
	}
	if expectedQuotaFiles != user.UsedQuotaFiles {
		t.Errorf("quota files does not match after scan, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
	}
	if expectedQuotaSize != user.UsedQuotaSize {
		t.Errorf("quota size does not match after scan, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermList(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err = client.ReadDir(".")
		if err == nil {
			t.Errorf("read remote dir without permission should not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermDownload(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if err == nil {
			t.Errorf("file download without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermUpload(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err == nil {
			t.Errorf("file upload without permission should not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermDelete(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Remove(testFileName)
		if err == nil {
			t.Errorf("delete without permission should not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermRename(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Rename(testFileName, testFileName+".rename")
		if err == nil {
			t.Errorf("rename without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermCreateDirs(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateSymlinks}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		err = client.Mkdir("testdir")
		if err == nil {
			t.Errorf("mkdir without permission should not succeed")
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermSymlink(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs}
	user, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Symlink(testFilePath, testFilePath+".symlink")
		if err == nil {
			t.Errorf("symlink without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}
