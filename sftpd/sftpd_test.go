package sftpd_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
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
	configDir = ".."
)

var (
	allPerms       = []string{dataprovider.PermAny}
	homeBasePath   string
	scpPath        string
	pubKeyPath     string
	privateKeyPath string
)

func TestMain(m *testing.M) {
	logfilePath := filepath.Join(configDir, "sftpgo_sftpd_test.log")
	loginBannerFileName := "login_banner"
	loginBannerFile := filepath.Join(configDir, loginBannerFileName)
	ioutil.WriteFile(loginBannerFile, []byte("simple login banner\n"), 0777)
	logger.InitLogger(logfilePath, 5, 1, 28, false, zerolog.DebugLevel)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()

	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.Warn(logSender, "", "error initializing data provider: %v", err)
		os.Exit(1)
	}
	dataProvider := dataprovider.GetProvider()
	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()
	sftpdConf.BindPort = 2022
	sftpdConf.KexAlgorithms = []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384"}
	sftpdConf.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
		"aes256-ctr"}
	sftpdConf.MACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"}
	sftpdConf.LoginBannerFile = loginBannerFileName
	// we need to test SCP support
	sftpdConf.IsSCPEnabled = true
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	sftpdConf.UploadMode = 2
	if runtime.GOOS == "windows" {
		homeBasePath = "C:\\"
	} else {
		homeBasePath = "/tmp"
		sftpdConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete"}
		sftpdConf.Actions.Command = "/usr/bin/true"
		sftpdConf.Actions.HTTPNotificationURL = "http://127.0.0.1:8080/"
	}
	pubKeyPath = filepath.Join(homeBasePath, "ssh_key.pub")
	privateKeyPath = filepath.Join(homeBasePath, "ssh_key")
	err = ioutil.WriteFile(pubKeyPath, []byte(testPubKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save public key to file: %v", err)
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(testPrivateKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save private key to file: %v", err)
	}

	sftpd.SetDataProvider(dataProvider)
	httpd.SetDataProvider(dataProvider)

	scpPath, err = exec.LookPath("scp")
	if err != nil {
		logger.Warn(logSender, "", "unable to get scp command. SCP tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get scp command. SCP tests will be skipped, err: %v", err)
		scpPath = ""
	}

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "", "could not start HTTP server: %v", err)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))

	exitCode := m.Run()
	os.Remove(logfilePath)
	os.Remove(loginBannerFile)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	config.LoadConfig(configDir, "")
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Umask = "invalid umask"
	sftpdConf.BindPort = 2022
	sftpdConf.LoginBannerFile = "invalid_file"
	err := sftpdConf.Initialize(configDir)
	if err == nil {
		t.Errorf("Inizialize must fail, a SFTP server should be already running")
	}
}

func TestBasicSFTPHandling(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
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
		createTestFile(testFilePath, testFileSize)
		err = sftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client)
		if err == nil {
			t.Errorf("upload a file to a missing dir must fail")
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestUploadResume(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		appendDataSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = appendToTestFile(testFilePath, appendDataSize)
		if err != nil {
			t.Errorf("unable to append to test file: %v", err)
		}
		err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize+appendDataSize, false, client)
		if err != nil {
			t.Errorf("file upload resume error: %v", err)
		}
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize+appendDataSize, client)
		if err != nil {
			t.Errorf("file download error: %v", err)
		}
		initialHash, err := computeFileHash(localDownloadPath)
		if err != nil {
			t.Errorf("error computing file hash: %v", err)
		}
		donwloadedFileHash, err := computeFileHash(localDownloadPath)
		if err != nil {
			t.Errorf("error computing downloaded file hash: %v", err)
		}
		if donwloadedFileHash != initialHash {
			t.Errorf("resume failed: file hash does not match")
		}
		err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize+appendDataSize, true, client)
		if err == nil {
			t.Errorf("file upload resume with invalid offset must fail")
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestDirCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	// remove the home dir to test auto creation
	os.RemoveAll(user.HomeDir)
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
		if err == nil {
			t.Errorf("recursive mkdir must fail")
		}
		client.Mkdir("/test")
		err = client.Mkdir("/test/test1")
		if err != nil {
			t.Errorf("mkdir dir error: %v", err)
		}
		_, err = client.ReadDir("/this/dir/does/not/exist")
		if err == nil {
			t.Errorf("reading a missing dir must fail")
		}
		err = client.RemoveDirectory("/test/test1")
		if err != nil {
			t.Errorf("remove dir error: %v", err)
		}
		err = client.RemoveDirectory("/test")
		if err != nil {
			t.Errorf("remove dir error: %v", err)
		}
		_, err = client.Lstat("/test")
		if err == nil {
			t.Errorf("stat for deleted dir must not succeed")
		}
		err = client.RemoveDirectory("/test")
		if err == nil {
			t.Errorf("remove missing path must fail")
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestRemove(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
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
		err = client.Mkdir("/test/test1")
		if err != nil {
			t.Errorf("error mkdir subdir: %v", err)
		}
		testFileName := "/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, path.Join("/test", testFileName), testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Remove("/test")
		if err == nil {
			t.Errorf("remove non empty dir must fail")
		}
		err = client.RemoveDirectory(path.Join("/test", testFileName))
		if err == nil {
			t.Errorf("remove directory as file must fail")
		}
		err = client.Remove(path.Join("/test", testFileName))
		if err != nil {
			t.Errorf("remove file error: %v", err)
		}
		err = client.Remove(path.Join("/test", testFileName))
		if err == nil {
			t.Errorf("remove missing file must fail")
		}
		err = client.Remove("/test/test1")
		if err != nil {
			t.Errorf("remove dir error: %v", err)
		}
		err = client.Remove("/test")
		if err != nil {
			t.Errorf("remove dir error: %v", err)
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLink(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
		_, err = client.ReadLink(testFileName + ".link")
		if err == nil {
			t.Errorf("readlink is currently not implemented so must fail")
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if err == nil {
			t.Errorf("creating a symlink to an existing one must fail")
		}
		err = client.Link(testFileName, testFileName+".hlink")
		if err == nil {
			t.Errorf("hard link is not supported and must fail")
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestStat(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

// basic tests to verify virtual chroot, should be improved to cover more cases ...
func TestEscapeHomeDir(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
		remoteDestPath := path.Join("..", "..", testFileName)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestHomeSpecialChars(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir = filepath.Join(homeBasePath, "abc açà#&%lk")
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLogin(t *testing.T) {
	u := getTestUser(false)
	u.PublicKeys = []string{testPubKey}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	user.PublicKeys = []string{testPubKey1}
	user.Password = ""
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, true)
	if err == nil {
		t.Errorf("login with invalid public key must fail")
		defer client.Close()
	}
	// login a user with multiple public keys, only the second one is valid
	user.PublicKeys = []string{testPubKey1, testPubKey}
	user.Password = ""
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLoginAfterUserUpdateEmptyPwd(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLoginAfterUserUpdateEmptyPubKey(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestMaxSessions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.MaxSessions = 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestQuotaFileReplace(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		// now replace the same file, the quota must not change
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestQuotaScan(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	// create user with the same home dir, so there is at least an untracked file
	user, _, err = httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	_, err = httpd.StartQuotaScan(user, http.StatusCreated)
	if err != nil {
		t.Errorf("error starting quota scan: %v", err)
	}
	scans, _, err := httpd.GetQuotaScans(http.StatusOK)
	if err != nil {
		t.Errorf("error getting active quota scans: %v", err)
	}
	for len(scans) > 0 {
		scans, _, err = httpd.GetQuotaScans(http.StatusOK)
		if err != nil {
			t.Errorf("error getting active quota scans: %v", err)
			break
		}
	}
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("error getting user: %v", err)
	}
	if expectedQuotaFiles != user.UsedQuotaFiles {
		t.Errorf("quota files does not match after scan, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
	}
	if expectedQuotaSize != user.UsedQuotaSize {
		t.Errorf("quota size does not match after scan, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestMissingFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestOverwriteDirWithFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPasswordsHashPbkdf2Sha1(t *testing.T) {
	pbkdf2Pwd := "$pbkdf2-sha1$150000$DveVjgYUD05R$X6ydQZdyMeOvpgND2nqGR/0GGic="
	pbkdf2ClearPwd := "password"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = pbkdf2Pwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = pbkdf2ClearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with pkkdf2 sha1 password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with pkkdf2 sha1 password: %v", err)
		}
	}
	user.Password = pbkdf2Pwd
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login with wrong password must fail")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPasswordsHashPbkdf2Sha256(t *testing.T) {
	pbkdf2Pwd := "$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo="
	pbkdf2ClearPwd := "password"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = pbkdf2Pwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = pbkdf2ClearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with pkkdf2 sha1 password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with pkkdf2 sha1 password: %v", err)
		}
	}
	user.Password = pbkdf2Pwd
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login with wrong password must fail")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPasswordsHashPbkdf2Sha512(t *testing.T) {
	pbkdf2Pwd := "$pbkdf2-sha512$150000$dsu7T5R3IaVQ$1hFXPO1ntRBcoWkSLKw+s4sAP09Xtu4Ya7CyxFq64jM9zdUg8eRJVr3NcR2vQgb0W9HHvZaILHsL4Q/Vr6arCg=="
	pbkdf2ClearPwd := "password"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = pbkdf2Pwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = pbkdf2ClearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with pkkdf2 sha1 password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with pkkdf2 sha1 password: %v", err)
		}
	}
	user.Password = pbkdf2Pwd
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login with wrong password must fail")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPasswordsHashBcrypt(t *testing.T) {
	bcryptPwd := "$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK"
	bcryptClearPwd := "secret"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = bcryptPwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = bcryptClearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with bcrypt password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with bcrypt password: %v", err)
		}
	}
	user.Password = bcryptPwd
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login with wrong password must fail")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPasswordsHashSHA512Crypt(t *testing.T) {
	sha512CryptPwd := "$6$459ead56b72e44bc$uog86fUxscjt28BZxqFBE2pp2QD8P/1e98MNF75Z9xJfQvOckZnQ/1YJqiq1XeytPuDieHZvDAMoP7352ELkO1"
	clearPwd := "secret"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = sha512CryptPwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = clearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with sha512 crypt password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with sha512 crypt password: %v", err)
		}
	}
	user.Password = sha512CryptPwd
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login with wrong password must fail")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermList(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermDownload(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermUpload(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermOverwrite(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
			t.Errorf("error uploading file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err == nil {
			t.Errorf("file overwrite without permission should not succeed")
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermDelete(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermRename(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermCreateDirs(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermSymlink(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestSSHConnection(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	err = doSSH(user, usePubKey)
	if err == nil {
		t.Errorf("ssh connection must fail: %v", err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

// Start SCP tests
func TestSCPBasicHandling(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(131074)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	// test to download a missing file
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err == nil {
		t.Errorf("downloading a missing file via scp must fail")
	}
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err != nil {
		t.Errorf("error uploading file via scp: %v", err)
	}
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err != nil {
		t.Errorf("error downloading file via scp: %v", err)
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		t.Errorf("stat for the downloaded file must succeed")
	} else {
		if fi.Size() != testFileSize {
			t.Errorf("size of the file downloaded via SCP does not match the expected one")
		}
	}
	os.Remove(localPath)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("error getting user: %v", err)
	}
	if expectedQuotaFiles != user.UsedQuotaFiles {
		t.Errorf("quota files does not match, expected: %v, actual: %v", expectedQuotaFiles, user.UsedQuotaFiles)
	}
	if expectedQuotaSize != user.UsedQuotaSize {
		t.Errorf("quota size does not match, expected: %v, actual: %v", expectedQuotaSize, user.UsedQuotaSize)
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPUploadFileOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(32760)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading file via scp: %v", err)
	}
	// test a new upload that must overwrite the existing file
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading existing file via scp: %v", err)
	}
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("error getting user: %v", err)
	}
	if user.UsedQuotaSize != testFileSize || user.UsedQuotaFiles != 1 {
		t.Errorf("update quota error on file overwrite, actual size: %v, expected: %v actual files: %v, expected: 1",
			user.UsedQuotaSize, testFileSize, user.UsedQuotaFiles)
	}
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err != nil {
		t.Errorf("error downloading file via scp: %v", err)
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		t.Errorf("stat for the downloaded file must succeed")
	} else {
		if fi.Size() != testFileSize {
			t.Errorf("size of the file downloaded via SCP does not match the expected one")
		}
	}
	os.Remove(localPath)
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPRecursive(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testBaseDirDownName := "test_dir_down"
	testBaseDirDownPath := filepath.Join(homeBasePath, testBaseDirDownName)
	testFilePath := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testBaseDirName, testFileName)
	testFileSize := int64(131074)
	createTestFile(testFilePath, testFileSize)
	createTestFile(testFilePath1, testFileSize)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testBaseDirName))
	// test to download a missing dir
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
	if err == nil {
		t.Errorf("downloading a missing dir via scp must fail")
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading dir via scp: %v", err)
	}
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
	if err != nil {
		t.Errorf("error downloading dir via scp: %v", err)
	}
	// test download without passing -r
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, false)
	if err == nil {
		t.Errorf("recursive download without -r must fail")
	}
	fi, err := os.Stat(filepath.Join(testBaseDirDownPath, testFileName))
	if err != nil {
		t.Errorf("error downloading file using scp recursive: %v", err)
	} else {
		if fi.Size() != testFileSize {
			t.Errorf("size for file downloaded using recursive scp does not match, actual: %v, expected: %v", fi.Size(), testFileSize)
		}
	}
	fi, err = os.Stat(filepath.Join(testBaseDirDownPath, testBaseDirName, testFileName))
	if err != nil {
		t.Errorf("error downloading file using scp recursive: %v", err)
	} else {
		if fi.Size() != testFileSize {
			t.Errorf("size for file downloaded using recursive scp does not match, actual: %v, expected: %v", fi.Size(), testFileSize)
		}
	}
	// upload to a non existent dir
	remoteUpPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/non_existent_dir")
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	if err == nil {
		t.Errorf("uploading via scp to a non existent dir must fail")
	}
	os.RemoveAll(testBaseDirPath)
	os.RemoveAll(testBaseDirDownPath)
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPPermCreateDirs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(32760)
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	err = createTestFile(testFilePath1, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp/")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err == nil {
		t.Errorf("scp upload must fail, the user cannot create new dirs")
	}
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	if err == nil {
		t.Errorf("scp upload must fail, the user cannot create new dirs")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	os.RemoveAll(testBaseDirPath)
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPPermUpload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermDownload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65536)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err == nil {
		t.Errorf("scp upload must fail, the user cannot upload")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPPermOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65536)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("scp upload error: %v", err)
	}
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err == nil {
		t.Errorf("scp upload must fail, the user cannot ovewrite existing files")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPPermDownload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65537)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "tmp")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading existing file via scp: %v", err)
	}
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/tmp", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err == nil {
		t.Errorf("scp download must fail, the user cannot download")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPQuotaSize(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	testFileSize := int64(65535)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize - 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading existing file via scp: %v", err)
	}
	err = scpUpload(testFilePath, remoteUpPath+".quota", true, false)
	if err == nil {
		t.Errorf("user is over quota scp upload must fail")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPEscapeHomeDir(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	os.MkdirAll(user.GetHomeDir(), 0777)
	testDir := "testDir"
	linkPath := filepath.Join(homeBasePath, defaultUsername, testDir)
	err = os.Symlink(homeBasePath, linkPath)
	if err != nil {
		t.Errorf("error making local symlink: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDir, testDir))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err == nil {
		t.Errorf("uploading to a dir with a symlink outside home dir must fail")
	}
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testDir, testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err == nil {
		t.Errorf("scp download must fail, the requested file has a symlink outside user home")
	}
	remoteDownPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testDir))
	err = scpDownload(homeBasePath, remoteDownPath, false, true)
	if err == nil {
		t.Errorf("scp download must fail, the requested dir is a symlink outside user home")
	}
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPUploadPaths(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirName := "testDir"
	testDirPath := filepath.Join(user.GetHomeDir(), testDirName)
	os.MkdirAll(testDirPath, 0777)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, testDirName)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDirName, testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err != nil {
		t.Errorf("scp upload error: %v", err)
	}
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err != nil {
		t.Errorf("scp download error: %v", err)
	}
	// upload a file to a missing dir
	remoteUpPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDirName, testDirName, testFileName))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err == nil {
		t.Errorf("scp upload to a missing dir must fail")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPOverwriteDirWithFile(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirPath := filepath.Join(user.GetHomeDir(), testFileName)
	os.MkdirAll(testDirPath, 0777)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err == nil {
		t.Errorf("copying a file over an existing dir must fail")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSCPRemoteToRemote(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.HomeDir += "1"
	user1, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	remote1UpPath := fmt.Sprintf("%v@127.0.0.1:%v", user1.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err != nil {
		t.Errorf("scp upload error: %v", err)
	}
	err = scpUpload(remoteUpPath, remote1UpPath, false, true)
	if err != nil {
		t.Errorf("scp upload remote to remote error: %v", err)
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	err = os.RemoveAll(user1.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files for user1")
	}
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user1: %v", err)
	}
}

func TestSCPErrors(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	u := getTestUser(true)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	testFileSize := int64(524288)
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	if err != nil {
		t.Errorf("error uploading file via scp: %v", err)
	}
	user.UploadBandwidth = 512
	user.DownloadBandwidth = 512
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	cmd := getScpDownloadCommand(localPath, remoteDownPath, false, false)
	go func() {
		if cmd.Run() == nil {
			t.Errorf("SCP download must fail")
		}
	}()
	waitForActiveTransfer()
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	cmd.Process.Kill()
	waitForNoActiveTransfer()
	cmd = getScpUploadCommand(testFilePath, remoteUpPath, false, false)
	go func() {
		if cmd.Run() == nil {
			t.Errorf("SCP upload must fail")
		}
	}()
	waitForActiveTransfer()
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	cmd.Process.Kill()
	waitForNoActiveTransfer()
	err = os.Remove(testFilePath)
	if err != nil {
		t.Errorf("error removing test file")
	}
	err = os.RemoveAll(user.GetHomeDir())
	if err != nil {
		t.Errorf("error removing uploaded files")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

// End SCP tests

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
		user.PublicKeys = []string{testPubKey}
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
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		os.MkdirAll(baseDir, 0777)
	}
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, content, 0666)
}

func appendToTestFile(path string, size int64) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	written, err := io.Copy(f, bytes.NewReader(content))
	if err != nil {
		return err
	}
	if int64(written) != size {
		return fmt.Errorf("write error, written: %v/%v", written, size)
	}
	return nil
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

func sftpUploadResumeFile(localSourcePath string, remoteDestPath string, expectedSize int64, invalidOffset bool,
	client *sftp.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	fi, err := client.Lstat(remoteDestPath)
	if err != nil {
		return err
	}
	if !invalidOffset {
		_, err = srcFile.Seek(fi.Size(), 0)
		if err != nil {
			return err
		}
	}
	destFile, err := client.OpenFile(remoteDestPath, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	if !invalidOffset {
		_, err = destFile.Seek(fi.Size(), 0)
		if err != nil {
			return err
		}
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

func scpUpload(localPath, remotePath string, preserveTime, remoteToRemote bool) error {
	cmd := getScpUploadCommand(localPath, remotePath, preserveTime, remoteToRemote)
	return cmd.Run()
}

func scpDownload(localPath, remotePath string, preserveTime, recursive bool) error {
	cmd := getScpDownloadCommand(localPath, remotePath, preserveTime, recursive)
	return cmd.Run()
}

func getScpDownloadCommand(localPath, remotePath string, preserveTime, recursive bool) *exec.Cmd {
	var args []string
	if preserveTime {
		args = append(args, "-p")
	}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, "-P")
	args = append(args, "2022")
	args = append(args, "-o")
	args = append(args, "StrictHostKeyChecking=no")
	args = append(args, "-i")
	args = append(args, privateKeyPath)
	args = append(args, remotePath)
	args = append(args, localPath)
	return exec.Command(scpPath, args...)
}

func getScpUploadCommand(localPath, remotePath string, preserveTime, remoteToRemote bool) *exec.Cmd {
	var args []string
	if remoteToRemote {
		args = append(args, "-3")
	}
	if preserveTime {
		args = append(args, "-p")
	}
	fi, err := os.Stat(localPath)
	if err == nil {
		if fi.IsDir() {
			args = append(args, "-r")
		}
	}
	args = append(args, "-P")
	args = append(args, "2022")
	args = append(args, "-o")
	args = append(args, "StrictHostKeyChecking=no")
	args = append(args, "-i")
	args = append(args, privateKeyPath)
	args = append(args, localPath)
	args = append(args, remotePath)
	return exec.Command(scpPath, args...)
}

func computeFileHash(path string) (string, error) {
	hash := ""
	f, err := os.Open(path)
	if err != nil {
		return hash, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return hash, err
	}
	hash = fmt.Sprintf("%x", h.Sum(nil))
	return hash, err
}

func waitForNoActiveTransfer() {
	for len(sftpd.GetConnectionsStats()) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
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
