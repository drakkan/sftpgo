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
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
)

const (
	logSender       = "sftpdTesting"
	sftpServerAddr  = "127.0.0.1:2022"
	defaultUsername = "test_user_sftp"
	defaultPassword = "test_password"
	testPubKey      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	testPubKey1     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCd60+/j+y8f0tLftihWV1YN9RSahMI9btQMDIMqts/jeNbD8jgoogM3nhF7KxfcaMKURuD47KC4Ey6iAJUJ0sWkSNNxOcIYuvA+5MlspfZDsa8Ag76Fe1vyz72WeHMHMeh/hwFo2TeIeIXg480T1VI6mzfDrVp2GzUx0SS0dMsQBjftXkuVR8YOiOwMCAH2a//M1OrvV7d/NBk6kBN0WnuIBb2jKm15PAA7+jQQG7tzwk2HedNH3jeL5GH31xkSRwlBczRK0xsCQXehAlx6cT/e/s44iJcJTHfpPKoSk6UAhPJYe7Z1QnuoawY9P9jQaxpyeImBZxxUEowhjpj2avBxKdRGBVK8R7EL8tSOeLbhdyWe5Mwc1+foEbq9Zz5j5Kd+hn3Wm1UnsGCrXUUUoZp1jnlNl0NakCto+5KmqnT9cHxaY+ix2RLUWAZyVFlRq71OYux1UHJnEJPiEI1/tr4jFBSL46qhQZv/TfpkfVW8FLz0lErfqu0gQEZnNHr3Fc= nicola@p1"
	testPrivateKey  = `-----BEGIN OPENSSH PRIVATE KEY-----
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
iixITGvaNZh/tjAAAACW5pY29sYUBwMQE=
-----END OPENSSH PRIVATE KEY-----`
	configDir = ".."
	confName  = "sftpgo.conf"
)

var (
	allPerms       = []string{dataprovider.PermAny}
	homeBasePath   string
	configFilePath = filepath.Join(configDir, confName)
)

func TestMain(m *testing.M) {
	logfilePath := filepath.Join(configDir, "sftpgo_sftpd_test.log")
	logger.InitLogger(logfilePath, 5, 1, 28, false, zerolog.DebugLevel)
	config.LoadConfig(configFilePath)
	providerConf := config.GetProviderConf()

	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.Warn(logSender, "error initializing data provider: %v", err)
		os.Exit(1)
	}
	dataProvider := dataprovider.GetProvider()
	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()
	router := api.GetHTTPRouter()
	// we run the test cases with UploadMode atomic. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	sftpdConf.UploadMode = 1
	if runtime.GOOS == "windows" {
		homeBasePath = "C:\\"
	} else {
		homeBasePath = "/tmp"
		sftpdConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete"}
		sftpdConf.Actions.Command = "/bin/true"
		sftpdConf.Actions.HTTPNotificationURL = "http://127.0.0.1:8080/"
	}

	sftpd.SetDataProvider(dataProvider)
	api.SetDataProvider(dataProvider)

	go func() {
		logger.Debug(logSender, "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "could not start SFTP server: %v", err)
		}
	}()

	go func() {
		logger.Debug(logSender, "initializing HTTP server with config %+v", httpdConf)
		s := &http.Server{
			Addr:           fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort),
			Handler:        router,
			ReadTimeout:    300 * time.Second,
			WriteTimeout:   300 * time.Second,
			MaxHeaderBytes: 1 << 20, // 1MB
		}
		if err := s.ListenAndServe(); err != nil {
			logger.Error(logSender, "could not start HTTP server: %v", err)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))

	exitCode := m.Run()
	os.Remove(logfilePath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	config.LoadConfig(configFilePath)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Umask = "invalid umask"
	err := sftpdConf.Initialize(configDir)
	if err == nil {
		t.Errorf("Inizialize must fail, a SFTP server should be already running")
	}
}

func TestBasicSFTPHandling(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := api.AddUser(u, http.StatusOK)
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
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if err != nil {
			t.Errorf("file download error: %v", err)
		}
		user, _, err = api.GetUserByID(user.ID, http.StatusOK)
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
		user, _, err = api.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if (expectedQuotaFiles - 1) != user.UsedQuotaFiles {
			t.Errorf("quota files does not match after delete, expected: %v, actual: %v", expectedQuotaFiles-1, user.UsedQuotaFiles)
		}
		if (expectedQuotaSize - testFileSize) != user.UsedQuotaSize {
			t.Errorf("quota size does not match, expected: %v, actual: %v", expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestDirCommands(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	// remove the home dir to test auto creation
	_, err = os.Stat(user.HomeDir)
	if err == nil {
		os.RemoveAll(user.HomeDir)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
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
		err = client.Mkdir("/test/test1")
		if err != nil {
			t.Errorf("error mkdir all: %v", err)
		}
		testFileName := "/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, filepath.Join("/test", testFileName), testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		// internally client.Remove will call RemoveDirectory on failure
		// the first remove will fail since test directory is not empty
		// the RemoveDirectory called internally by client.Remove will succeed
		err = client.Remove("/test")
		if err != nil {
			t.Errorf("error rmdir all: %v", err)
		}
		_, err = client.Lstat("/test")
		if err == nil {
			t.Errorf("stat for deleted dir must not succeed")
		}
		err = client.Remove("/test")
		if err == nil {
			t.Errorf("remove missing path must fail")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSymlink(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
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
		err = client.Symlink(testFileName, testFileName+".link")
		if err != nil {
			t.Errorf("error creating symlink: %v", err)
		}
		err = client.Remove(testFileName + ".link")
		if err != nil {
			t.Errorf("error removing symlink: %v", err)
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestStat(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
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
		fi, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		err = client.Chown(testFileName, 1000, 1000)
		if err != nil {
			t.Errorf("chown error: %v", err)
		}
		err = client.Chmod(testFileName, 0600)
		if err != nil {
			t.Errorf("chmod error: %v", err)
		}
		newFi, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		if fi.Mode().Perm() != newFi.Mode().Perm() {
			t.Errorf("stat must remain unchanged")
		}
		_, err = client.ReadLink(testFileName)
		if err == nil {
			t.Errorf("readlink is not supported and must fail")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

// basic tests to verify virtual chroot, should be improved to cover more cases ...
func TestEscapeHomeDir(t *testing.T) {
	usePubKey := true
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
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
			t.Errorf("reading a symbolic link outside home dir should not succeeded")
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
		linkPath = filepath.Join(homeBasePath, defaultUsername, testFileName)
		err = os.Symlink(homeBasePath, linkPath)
		if err != nil {
			t.Errorf("error making local symlink: %v", err)
		}
		err = sftpDownloadFile(testFileName, testFilePath, 0, client)
		if err == nil {
			t.Errorf("download file outside home dir must fail")
		}
		err = sftpUploadFile(testFilePath, remoteDestPath, testFileSize, client)
		if err == nil {
			t.Errorf("overwrite a file outside home dir must fail")
		}
		err = client.Chmod(remoteDestPath, 0644)
		if err == nil {
			t.Errorf("setstat on a file outside home dir must fail")
		}
		os.Remove(linkPath)
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestHomeSpecialChars(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir = filepath.Join(homeBasePath, "abc açà#&%lk")
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLogin(t *testing.T) {
	u := getTestUser(false)
	u.PublicKey = []string{testPubKey}
	user, _, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, false)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("sftp client with valid password must work")
		}
	}
	client, err = getSftpClient(user, true)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("sftp client with valid public key must work")
		}
	}
	user.Password = "invalid password"
	client, err = getSftpClient(user, false)
	if err == nil {
		t.Errorf("login with invalid password must fail")
		defer client.Close()
	}
	// testPubKey1 is not authorized
	user.PublicKey = []string{testPubKey1}
	user.Password = ""
	_, _, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, true)
	if err == nil {
		t.Errorf("login with invalid public key must fail")
		defer client.Close()
	}
	// login a user with multiple public keys, only the second one is valid
	user.PublicKey = []string{testPubKey1, testPubKey}
	user.Password = ""
	_, _, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, true)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("sftp client with multiple public key must work if at least one public key is valid")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLoginAfterUserUpdateEmptyPwd(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKey = []string{}
	// password and public key should remain unchanged
	_, _, err = api.UpdateUser(user, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestLoginAfterUserUpdateEmptyPubKey(t *testing.T) {
	usePubKey := true
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKey = []string{}
	// password and public key should remain unchanged
	_, _, err = api.UpdateUser(user, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestMaxSessions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.MaxSessions = 1
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestQuotaFileReplace(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileSize := int64(65535)
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
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
		user, _, err = api.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		// now replace the same file, the quota must not change
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		user, _, err = api.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if expectedQuotaFiles != user.UsedQuotaFiles {
			t.Errorf("quota files does not match, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
		}
		if expectedQuotaSize != user.UsedQuotaSize {
			t.Errorf("quota size does not match, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
		}
	}
	// now set a quota size restriction and upload the same fail, upload should fail for space limit exceeded
	user.QuotaSize = testFileSize - 1
	user, _, err = api.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("error updating user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err == nil {
			t.Errorf("quota size exceeded, file upload must fail")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestQuotaScan(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
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
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	// create user with the same home dir, so there is at least an untracked file
	user, _, err = api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	_, err = api.StartQuotaScan(user, http.StatusCreated)
	if err != nil {
		t.Errorf("error starting quota scan: %v", err)
	}
	scans, _, err := api.GetQuotaScans(http.StatusOK)
	if err != nil {
		t.Errorf("error getting active quota scans: %v", err)
	}
	for len(scans) > 0 {
		scans, _, err = api.GetQuotaScans(http.StatusOK)
		if err != nil {
			t.Errorf("error getting active quota scans: %v", err)
			break
		}
	}
	user, _, err = api.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("error getting user: %v", err)
	}
	if expectedQuotaFiles != user.UsedQuotaFiles {
		t.Errorf("quota files does not match after scan, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
	}
	if expectedQuotaSize != user.UsedQuotaSize {
		t.Errorf("quota size does not match after scan, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestMultipleQuotaScans(t *testing.T) {
	if !sftpd.AddQuotaScan(defaultUsername) {
		t.Errorf("add quota failed")
	}
	if sftpd.AddQuotaScan(defaultUsername) {
		t.Errorf("add quota must fail if another scan is already active")
	}
	sftpd.RemoveQuotaScan(defaultPassword)
}

func TestQuotaSize(t *testing.T) {
	usePubKey := false
	testFileSize := int64(65535)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize - 1
	user, _, err := api.AddUser(u, http.StatusOK)
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
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
		if err == nil {
			t.Errorf("user is over quota file upload must fail")
		}
		err = client.Remove(testFileName + ".quota")
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestBandwidthAndConnections(t *testing.T) {
	usePubKey := false
	testFileSize := int64(131072)
	u := getTestUser(usePubKey)
	u.UploadBandwidth = 30
	u.DownloadBandwidth = 25
	wantedUploadElapsed := 1000 * (testFileSize / 1000) / u.UploadBandwidth
	wantedDownloadElapsed := 1000 * (testFileSize / 1000) / u.DownloadBandwidth
	// 100 ms tolerance
	wantedUploadElapsed -= 100
	wantedDownloadElapsed -= 100
	user, _, err := api.AddUser(u, http.StatusOK)
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
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		startTime := time.Now()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		elapsed := time.Since(startTime).Nanoseconds() / 1000000
		if elapsed < (wantedUploadElapsed) {
			t.Errorf("upload bandwidth throttling not respected, elapsed: %v, wanted: %v", elapsed, wantedUploadElapsed)
		}
		startTime = time.Now()
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		c := sftpDownloadNonBlocking(testFileName, localDownloadPath, testFileSize, client)
		waitForActiveTransfer()
		// wait some additional arbitrary time to wait for transfer activity to happen
		// it is need to reach all the code in CheckIdleConnections
		time.Sleep(100 * time.Millisecond)
		sftpd.CheckIdleConnections()
		err = <-c
		if err != nil {
			t.Errorf("file download error: %v", err)
		}
		elapsed = time.Since(startTime).Nanoseconds() / 1000000
		if elapsed < (wantedDownloadElapsed) {
			t.Errorf("download bandwidth throttling not respected, elapsed: %v, wanted: %v", elapsed, wantedDownloadElapsed)
		}
		// test disconnection
		c = sftpUploadNonBlocking(testFilePath, testFileName+"_partial", testFileSize, client)
		waitForActiveTransfer()
		time.Sleep(100 * time.Millisecond)
		sftpd.CheckIdleConnections()
		stats := sftpd.GetConnectionsStats()
		for _, stat := range stats {
			sftpd.CloseActiveConnection(stat.ConnectionID)
		}
		err = <-c
		if err == nil {
			t.Errorf("connection closed upload must fail")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestMissingFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile("missing_file", localDownloadPath, 0, client)
		if err == nil {
			t.Errorf("download missing file must fail")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestOverwriteDirWithFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := api.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileSize := int64(65535)
		testFileName := "test_file.dat"
		testDirName := "test_dir"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = client.Mkdir(testDirName)
		if err != nil {
			t.Errorf("mkdir error: %v", err)
		}
		err = sftpUploadFile(testFilePath, testDirName, testFileSize, client)
		if err == nil {
			t.Errorf("copying a file over an existing dir must fail")
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Rename(testFileName, testDirName)
		if err == nil {
			t.Errorf("rename a file over an existing dir must fail")
		}
		err = client.RemoveDirectory(testDirName)
		if err != nil {
			t.Errorf("dir remove error: %v", err)
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermList(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
		_, err = client.Stat("test_file")
		if err == nil {
			t.Errorf("stat remote file without permission should not succeed")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermDownload(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermUpload(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermDelete(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermRename(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermCreateDirs(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateSymlinks}
	user, _, err := api.AddUser(u, http.StatusOK)
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, "/dir/subdir/test_file.dat", testFileSize, client)
		if err == nil {
			t.Errorf("mkdir without permission should not succeed")
		}
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestPermSymlink(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs}
	user, _, err := api.AddUser(u, http.StatusOK)
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
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSSHConnection(t *testing.T) {
	usePubKey := false
	user, _, err := api.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	err = doSSH(user, usePubKey)
	if err == nil {
		t.Errorf("ssh connection must fail: %v", err)
	}
	_, err = api.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func waitTCPListening(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			logger.WarnToConsole("tcp server %v not listening: %v\n", address, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logger.InfoToConsole("tcp server %v now listening\n", address)
		defer conn.Close()
		break
	}
}

func getTestUser(usePubKey bool) dataprovider.User {
	user := dataprovider.User{
		Username:    defaultUsername,
		Password:    defaultPassword,
		HomeDir:     filepath.Join(homeBasePath, defaultUsername),
		Permissions: allPerms,
	}
	if usePubKey {
		user.PublicKey = []string{testPubKey}
		user.Password = ""
	}
	return user
}

func doSSH(user dataprovider.User, usePubKey bool) error {
	var sshSession *ssh.Session
	config := &ssh.ClientConfig{
		User: defaultUsername,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if usePubKey {
		key, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
		if err != nil {
			return err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	sshSession, err = conn.NewSession()
	if err != nil {
		return err
	}
	_, err = sshSession.CombinedOutput("ls")
	return err
}

func getSftpClient(user dataprovider.User, usePubKey bool) (*sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
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
		if len(user.Password) > 0 {
			config.Auth = []ssh.AuthMethod{ssh.Password(user.Password)}
		} else {
			config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
		}
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
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		destFile.Close()
		return err
	}
	// we need to close the file to trigger the close method on server
	// we cannot defer closing or Lstat will fail for upload atomic mode
	destFile.Close()
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

func sftpUploadNonBlocking(localSourcePath string, remoteDestPath string, expectedSize int64, client *sftp.Client) <-chan error {
	c := make(chan error)
	go func() {
		c <- sftpUploadFile(localSourcePath, remoteDestPath, expectedSize, client)
	}()
	return c
}

func sftpDownloadNonBlocking(remoteSourcePath string, localDestPath string, expectedSize int64, client *sftp.Client) <-chan error {
	c := make(chan error)
	go func() {
		c <- sftpDownloadFile(remoteSourcePath, localDestPath, expectedSize, client)
	}()
	return c
}

func waitForActiveTransfer() {
	stats := sftpd.GetConnectionsStats()
	for len(stats) < 1 {
		stats = sftpd.GetConnectionsStats()
	}
	activeTransferFound := false
	for !activeTransferFound {
		stats = sftpd.GetConnectionsStats()
		if len(stats) == 0 {
			break
		}
		for _, stat := range stats {
			if len(stat.Transfers) > 0 {
				activeTransferFound = true
			}
		}
	}
}
