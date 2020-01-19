package sftpd_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
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
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
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
	gitPath        string
	sshPath        string
	pubKeyPath     string
	privateKeyPath string
	gitWrapPath    string
	extAuthPath    string
	logFilePath    string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_sftpd_test.log")
	loginBannerFileName := "login_banner"
	loginBannerFile := filepath.Join(configDir, loginBannerFileName)
	ioutil.WriteFile(loginBannerFile, []byte("simple login banner\n"), 0777)
	logger.InitLogger(logFilePath, 5, 1, 28, false, zerolog.DebugLevel)
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
	// we need to test all supported ssh commands
	sftpdConf.EnabledSSHCommands = []string{"*"}
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	sftpdConf.UploadMode = 2
	homeBasePath = os.TempDir()
	var scriptArgs string
	if runtime.GOOS == "windows" {
		scriptArgs = "%*"
	} else {
		sftpdConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete", "ssh_cmd"}
		sftpdConf.Actions.Command = "/usr/bin/true"
		sftpdConf.Actions.HTTPNotificationURL = "http://127.0.0.1:8080/"
		scriptArgs = "$@"
	}

	scpPath, err = exec.LookPath("scp")
	if err != nil {
		logger.Warn(logSender, "", "unable to get scp command. SCP tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get scp command. SCP tests will be skipped, err: %v", err)
		scpPath = ""
	}

	gitPath, err = exec.LookPath("git")
	if err != nil {
		logger.Warn(logSender, "", "unable to get git command. GIT tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get git command. GIT tests will be skipped, err: %v", err)
		gitPath = ""
	}

	sshPath, err = exec.LookPath("ssh")
	if err != nil {
		logger.Warn(logSender, "", "unable to get ssh command. GIT tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get ssh command. GIT tests will be skipped, err: %v", err)
		gitPath = ""
	}

	pubKeyPath = filepath.Join(homeBasePath, "ssh_key.pub")
	privateKeyPath = filepath.Join(homeBasePath, "ssh_key")
	gitWrapPath = filepath.Join(homeBasePath, "gitwrap.sh")
	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	err = ioutil.WriteFile(pubKeyPath, []byte(testPubKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save public key to file: %v", err)
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(testPrivateKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save private key to file: %v", err)
	}
	err = ioutil.WriteFile(gitWrapPath, []byte(fmt.Sprintf("%v -i %v -oStrictHostKeyChecking=no %v\n",
		sshPath, privateKeyPath, scriptArgs)), 0755)
	if err != nil {
		logger.WarnToConsole("unable to save gitwrap shell script: %v", err)
	}
	sftpd.SetDataProvider(dataProvider)
	httpd.SetDataProvider(dataProvider)

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
	os.Remove(logFilePath)
	os.Remove(loginBannerFile)
	os.Remove(pubKeyPath)
	os.Remove(privateKeyPath)
	os.Remove(gitWrapPath)
	os.Remove(extAuthPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	config.LoadConfig(configDir, "")
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Umask = "invalid umask"
	sftpdConf.BindPort = 2022
	sftpdConf.LoginBannerFile = "invalid_file"
	sftpdConf.IsSCPEnabled = true
	sftpdConf.EnabledSSHCommands = append(sftpdConf.EnabledSSHCommands, "ls")
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
		os.Remove(testFilePath)
		os.Remove(localDownloadPath)
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
		initialHash, err := computeHashForFile(sha256.New(), testFilePath)
		if err != nil {
			t.Errorf("error computing file hash: %v", err)
		}
		donwloadedFileHash, err := computeHashForFile(sha256.New(), localDownloadPath)
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
		os.Remove(testFilePath)
		os.Remove(localDownloadPath)
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
		err = client.Mkdir("test1")
		if err != nil {
			t.Errorf("error mkdir: %v", err)
		}
		err = client.Rename("test1", "test")
		if err != nil {
			t.Errorf("error rename: %v", err)
		}
		_, err = client.Lstat("/test1")
		if err == nil {
			t.Errorf("stat for renamed dir must not succeed")
		}
		err = client.PosixRename("test", "test1")
		if err != nil {
			t.Errorf("error posix rename: %v", err)
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
	httpd.RemoveUser(user, http.StatusOK)
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
			t.Errorf("remove a file with rmdir must fail")
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
		os.Remove(testFilePath)
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
		os.Remove(testFilePath)
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
		createTestFile(testFilePath, testFileSize)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		_, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		// mode 0666 and 0444 works on Windows too
		newPerm := os.FileMode(0666)
		err = client.Chmod(testFileName, newPerm)
		if err != nil {
			t.Errorf("chmod error: %v", err)
		}
		newFi, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		if newPerm != newFi.Mode().Perm() {
			t.Errorf("chmod failed expected: %v, actual: %v", newPerm, newFi.Mode().Perm())
		}
		newPerm = os.FileMode(0444)
		err = client.Chmod(testFileName, newPerm)
		if err != nil {
			t.Errorf("chmod error: %v", err)
		}
		newFi, err = client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		if newPerm != newFi.Mode().Perm() {
			t.Errorf("chmod failed expected: %v, actual: %v", newPerm, newFi.Mode().Perm())
		}
		_, err = client.ReadLink(testFileName)
		if err == nil {
			t.Errorf("readlink is not supported and must fail")
		}
		err = client.Truncate(testFileName, 0)
		if err != nil {
			t.Errorf("truncate must be silently ignored: %v", err)
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestStatChownChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown is not supported on Windows, chmod is partially supported")
	}
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		createTestFile(testFilePath, testFileSize)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Chown(testFileName, os.Getuid(), os.Getgid())
		if err != nil {
			t.Errorf("chown error: %v", err)
		}
		newPerm := os.FileMode(0600)
		err = client.Chmod(testFileName, newPerm)
		if err != nil {
			t.Errorf("chmod error: %v", err)
		}
		newFi, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("stat error: %v", err)
		}
		if newPerm != newFi.Mode().Perm() {
			t.Errorf("chown failed expected: %v, actual: %v", newPerm, newFi.Mode().Perm())
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
		// l'errore viene riconvertito da sftp.ErrSSHFxNoSuchFile in os.ErrNotExist
		err = client.Chmod(testFileName, newPerm)
		if err != os.ErrNotExist {
			t.Errorf("unexpected chmod error: %v expected: %v", err, os.ErrNotExist)
		}
		err = client.Chown(testFileName, os.Getuid(), os.Getgid())
		if err != os.ErrNotExist {
			t.Errorf("unexpected chown error: %v expected: %v", err, os.ErrNotExist)
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestChtimes(t *testing.T) {
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
		testDir := "test"
		createTestFile(testFilePath, testFileSize)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		acmodTime := time.Now()
		err = client.Chtimes(testFileName, acmodTime, acmodTime)
		if err != nil {
			t.Errorf("error changing file times")
		}
		newFi, err := client.Lstat(testFileName)
		if err != nil {
			t.Errorf("file stat error: %v", err)
		}
		diff := math.Abs(newFi.ModTime().Sub(acmodTime).Seconds())
		if diff > 1 {
			t.Errorf("diff between wanted and real modification time too big: %v", diff)
		}
		err = client.Chtimes("invalidFile", acmodTime, acmodTime)
		if !os.IsNotExist(err) {
			t.Errorf("unexpected error: %v", err)
		}
		err = client.Mkdir(testDir)
		if err != nil {
			t.Errorf("unable to create dir: %v", err)
		}
		err = client.Chtimes(testDir, acmodTime, acmodTime)
		if err != nil {
			t.Errorf("error changing dir times")
		}
		newFi, err = client.Lstat(testDir)
		if err != nil {
			t.Errorf("dir stat error: %v", err)
		}
		diff = math.Abs(newFi.ModTime().Sub(acmodTime).Seconds())
		if diff > 1 {
			t.Errorf("diff between wanted and real modification time too big: %v", diff)
		}
		os.Remove(testFilePath)
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
		os.Remove(testFilePath)
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
		os.Remove(testFilePath)
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if user.LastLogin <= 0 {
			t.Errorf("last login must be updated after a successful login: %v", user.LastLogin)
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

func TestLoginUserStatus(t *testing.T) {
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
			t.Errorf("sftp client with valid credentials must work")
		}
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if user.LastLogin <= 0 {
			t.Errorf("last login must be updated after a successful login: %v", user.LastLogin)
		}
	}
	user.Status = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login for a disabled user must fail")
		defer client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLoginUserExpiration(t *testing.T) {
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
			t.Errorf("sftp client with valid credentials must work")
		}
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if user.LastLogin <= 0 {
			t.Errorf("last login must be updated after a successful login: %v", user.LastLogin)
		}
	}
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now()) - 120000
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login for an expired user must fail")
		defer client.Close()
	}
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now()) + 120000
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("login for a non expired user must succeed: %v", err)
	} else {
		defer client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLoginInvalidFs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	if providerConf.Driver != dataprovider.SQLiteDataProviderName {
		t.Skip("this test require sqlite provider")
	}
	dbPath := providerConf.Name
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(configDir, dbPath)
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	// we update the database using sqlite3 CLI since we cannot add an user with an invalid config
	time.Sleep(150 * time.Millisecond)
	updateUserQuery := fmt.Sprintf("UPDATE users SET filesystem='{\"provider\":1}' WHERE id=%v", user.ID)
	cmd := exec.Command("sqlite3", dbPath, updateUserQuery)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("unexpected error: %v, cmd out: %v", err, string(out))
	}
	time.Sleep(200 * time.Millisecond)
	_, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Error("login must fail, the user has an invalid filesystem config")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestLoginWithIPFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{}
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
			t.Errorf("sftp client with valid credentials must work")
		}
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		if err != nil {
			t.Errorf("error getting user: %v", err)
		}
		if user.LastLogin <= 0 {
			t.Errorf("last login must be updated after a successful login: %v", user.LastLogin)
		}
	}
	user.Filters.AllowedIP = []string{"127.0.0.0/8"}
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("login from an allowed IP must succeed: %v", err)
	} else {
		defer client.Close()
	}
	user.Filters.AllowedIP = []string{"172.19.0.0/16"}
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	client, err = getSftpClient(user, usePubKey)
	if err == nil {
		t.Errorf("login from an not allowed IP must fail")
		client.Close()
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

func TestLoginExternalAuthPwdAndPubKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, 0, false), 0755)
	providerConf.ExternalAuthProgram = extAuthPath
	providerConf.ExternalAuthScope = 0
	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	client, err := getSftpClient(u, usePubKey)
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
		os.Remove(testFilePath)
	}
	u.Username = defaultUsername + "1"
	client, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("external auth login with invalid user must fail")
	}
	usePubKey = false
	u = getTestUser(usePubKey)
	u.PublicKeys = []string{}
	ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, 0, false), 0755)
	client, err = getSftpClient(u, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
	}
	users, out, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v, out: %v", err, string(out))
	}
	if len(users) != 1 {
		t.Errorf("number of users mismatch, expected: 1, actual: %v", len(users))
	}
	user := users[0]
	if len(user.PublicKeys) != 0 {
		t.Errorf("number of public keys mismatch, expected: 0, actual: %v", len(user.PublicKeys))
	}
	if user.UsedQuotaSize == 0 {
		t.Error("quota size must be > 0")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())

	dataProvider = dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	os.Remove(extAuthPath)
}

func TestLoginExternalAuthPwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, 0, false), 0755)
	providerConf.ExternalAuthProgram = extAuthPath
	providerConf.ExternalAuthScope = 1
	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	client, err := getSftpClient(u, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
	}
	u.Username = defaultUsername + "1"
	client, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("external auth login with invalid user must fail")
	}
	usePubKey = true
	u = getTestUser(usePubKey)
	client, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("external auth login with valid user but invalid auth scope must fail")
	}
	users, out, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v, out: %v", err, string(out))
	}
	if len(users) != 1 {
		t.Errorf("number of users mismatch, expected: 1, actual: %v", len(users))
	}
	user := users[0]
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())

	dataProvider = dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	os.Remove(extAuthPath)
}

func TestLoginExternalAuthPubKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, 0, false), 0755)
	providerConf.ExternalAuthProgram = extAuthPath
	providerConf.ExternalAuthScope = 2
	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	client, err := getSftpClient(u, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		_, err := client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir: %v", err)
		}
	}
	u.Username = defaultUsername + "1"
	client, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("external auth login with invalid user must fail")
	}
	usePubKey = false
	u = getTestUser(usePubKey)
	client, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("external auth login with valid user but invalid auth scope must fail")
	}
	users, out, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v, out: %v", err, string(out))
	}
	if len(users) != 1 {
		t.Errorf("number of users mismatch, expected: 1, actual: %v", len(users))
	}
	user := users[0]
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())

	dataProvider = dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	os.Remove(extAuthPath)
}

func TestLoginExternalAuthErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, 0, true), 0755)
	providerConf.ExternalAuthProgram = extAuthPath
	providerConf.ExternalAuthScope = 0
	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	_, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("login must fail, external auth returns a non json response")
	}
	usePubKey = false
	u = getTestUser(usePubKey)
	_, err = getSftpClient(u, usePubKey)
	if err == nil {
		t.Error("login must fail, external auth returns a non json response")
	}
	users, out, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get users: %v, out: %v", err, string(out))
	}
	if len(users) != 0 {
		t.Errorf("number of users mismatch, expected: 0, actual: %v", len(users))
	}

	dataProvider = dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	os.Remove(extAuthPath)
}

func TestQuotaDisabledError(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 10
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
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())

	dataProvider = dataprovider.GetProvider()
	dataprovider.Close(dataProvider)
	config.LoadConfig(configDir, "")
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		t.Errorf("error initializing data provider")
	}
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
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
	// now set a quota size restriction and upload the same file, upload should fail for space limit exceeded
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
	os.Remove(testFilePath)
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
		os.Remove(testFilePath)
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
	err = waitQuotaScans()
	if err != nil {
		t.Errorf("error waiting for active quota scans: %v", err)
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
	sftpd.RemoveQuotaScan(defaultUsername)
	activeScans := sftpd.GetQuotaScans()
	if len(activeScans) > 0 {
		t.Errorf("no quota scan must be active: %v", len(activeScans))
	}
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
		os.Remove(testFilePath)
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
		os.Remove(testFilePath)
		os.Remove(localDownloadPath)
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
		os.Remove(localDownloadPath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestOpenError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
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
		os.Chmod(user.GetHomeDir(), 0001)
		_, err = client.ReadDir(".")
		if err == nil {
			t.Errorf("read dir must fail if we have no filesystem read permissions")
		}
		os.Chmod(user.GetHomeDir(), 0755)
		testFileSize := int64(65535)
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		_, err = client.Stat(testFileName)
		if err != nil {
			t.Errorf("file stat error: %v", err)
		}
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if err != nil {
			t.Errorf("file download error: %v", err)
		}
		os.Chmod(testFilePath, 0001)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if err == nil {
			t.Errorf("file download must fail if we have no filesystem read permissions")
		}
		err = sftpUploadFile(localDownloadPath, testFileName, testFileSize, client)
		if err == nil {
			t.Errorf("upload must fail if we have no filesystem write permissions")
		}
		err = client.Mkdir("test")
		if err != nil {
			t.Errorf("error making dir: %v", err)
		}
		os.Chmod(user.GetHomeDir(), 0000)
		_, err = client.Lstat(testFileName)
		if err == nil {
			t.Errorf("file stat must fail if we have no filesystem read permissions")
		}
		os.Chmod(user.GetHomeDir(), 0755)
		os.Chmod(filepath.Join(user.GetHomeDir(), "test"), 0000)
		err = client.Rename(testFileName, path.Join("test", testFileName))
		if err == nil || !strings.Contains(err.Error(), sftp.ErrSSHFxPermissionDenied.Error()) {
			t.Errorf("unexpected error: %v expected: %v", err, sftp.ErrSSHFxPermissionDenied)
		}
		os.Chmod(filepath.Join(user.GetHomeDir(), "test"), 0755)
		os.Remove(testFilePath)
		os.Remove(localDownloadPath)
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
		os.Remove(testFilePath)
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

func TestPasswordsHashMD5Crypt(t *testing.T) {
	md5CryptPwd := "$1$b5caebda$VODr/nyhGWgZaY8sJ4x05."
	clearPwd := "password"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = md5CryptPwd
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	user.Password = clearPwd
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to login with md5 crypt password: %v", err)
	} else {
		defer client.Close()
		_, err = client.Getwd()
		if err != nil {
			t.Errorf("unable to get working dir with md5 crypt password: %v", err)
		}
	}
	user.Password = md5CryptPwd
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
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
		os.Remove(localDownloadPath)
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermOverwrite, dataprovider.PermChmod, dataprovider.PermChown,
		dataprovider.PermChtimes}
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
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermChmod(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChown, dataprovider.PermChtimes}
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
		err = client.Chmod(testFileName, 0666)
		if err == nil {
			t.Errorf("chmod without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermChown(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChmod, dataprovider.PermChtimes}
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
		err = client.Chown(testFileName, os.Getuid(), os.Getgid())
		if err == nil {
			t.Errorf("chown without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestPermChtimes(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChmod, dataprovider.PermChown}
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
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		if err == nil {
			t.Errorf("chtimes without permission should not succeed")
		}
		err = client.Remove(testFileName)
		if err != nil {
			t.Errorf("error removing uploaded file: %v", err)
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestSubDirsUploads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChtimes, dataprovider.PermDownload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		err = client.Mkdir("subdir")
		if err != nil {
			t.Errorf("unexpected mkdir error: %v", err)
		}
		testFileName := "test_file.dat"
		testFileNameSub := "/subdir/test_file_dat"
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
		err = sftpUploadFile(testFilePath, testFileNameSub, testFileSize, client)
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected upload error: %v", err)
		}
		err = client.Symlink(testFileName, testFileNameSub+".link")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected upload error: %v", err)
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if err != nil {
			t.Errorf("symlink error: %v", err)
		}
		err = client.Rename(testFileName, testFileNameSub+".rename")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected rename error: %v", err)
		}
		err = client.Rename(testFileName, testFileName+".rename")
		if err != nil {
			t.Errorf("rename error: %v", err)
		}
		err = client.Remove(testFileNameSub)
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected upload error: %v", err)
		}
		err = client.Remove(testFileName + ".rename")
		if err != nil {
			t.Errorf("remove error: %v", err)
		}
		os.Remove(testFilePath)
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestSubDirsOverwrite(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermOverwrite, dataprovider.PermListItems}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		testFileName := "/subdir/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
		testFileSFTPPath := filepath.Join(u.GetHomeDir(), "subdir", "test_file.dat")
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = createTestFile(testFileSFTPPath, 16384)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName+".new", testFileSize, client)
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected upload error: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("unexpected overwrite error: %v", err)
		}
		os.Remove(testFilePath)
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestSubDirsDownloads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChmod, dataprovider.PermUpload, dataprovider.PermListItems}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		err = client.Mkdir("subdir")
		if err != nil {
			t.Errorf("unexpected mkdir error: %v", err)
		}
		testFileName := "/subdir/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
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
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected upload error: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected overwrite error: %v", err)
		}
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected chtimes error: %v", err)
		}
		err = client.Rename(testFileName, testFileName+".rename")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected rename error: %v", err)
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected symlink error: %v", err)
		}
		err = client.Remove(testFileName)
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected remove error: %v", err)
		}
		os.Remove(localDownloadPath)
		os.Remove(testFilePath)
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestPermsSubDirsSetstat(t *testing.T) {
	// for setstat we check the parent dir permission if the requested path is a dir
	// otherwise the path permission
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermCreateDirs}
	u.Permissions["/subdir"] = []string{dataprovider.PermAny}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		err = client.Mkdir("subdir")
		if err != nil {
			t.Errorf("unexpected mkdir error: %v", err)
		}
		testFileName := "/subdir/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		if err != nil {
			t.Errorf("unable to create test file: %v", err)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if err != nil {
			t.Errorf("file upload error: %v", err)
		}
		err = client.Chtimes("/subdir/", time.Now(), time.Now())
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected chtimes error: %v", err)
		}
		err = client.Chtimes("subdir/", time.Now(), time.Now())
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected chtimes error: %v", err)
		}
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		if err != nil {
			t.Errorf("unexpected chtimes error: %v", err)
		}
		os.Remove(testFilePath)
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestPermsSubDirsCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		client.Mkdir("subdir")
		acmodTime := time.Now()
		err = client.Chtimes("/subdir", acmodTime, acmodTime)
		if err != nil {
			t.Errorf("unexpected chtimes error: %v", err)
		}
		_, err = client.Stat("/subdir")
		if err != nil {
			t.Errorf("unexpected stat error: %v", err)
		}
		_, err = client.ReadDir("/")
		if err != nil {
			t.Errorf("unexpected readdir error: %v", err)
		}
		_, err = client.ReadDir("/subdir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error: %v", err)
		}
		err = client.RemoveDirectory("/subdir/dir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error: %v", err)
		}
		err = client.Mkdir("/subdir/dir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error: %v", err)
		}
		client.Mkdir("/otherdir")
		err = client.Rename("/otherdir", "/subdir/otherdir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error: %v", err)
		}
		err = client.Symlink("/otherdir", "/subdir/otherdir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error: %v", err)
		}
		err = client.Symlink("/otherdir", "/otherdir_link")
		if err != nil {
			t.Errorf("unexpected rename dir error: %v", err)
		}
		err = client.Rename("/otherdir", "/otherdir1")
		if err != nil {
			t.Errorf("unexpected rename dir error: %v", err)
		}
		err = client.RemoveDirectory("/subdir")
		if err != nil {
			t.Errorf("unexpected remove dir error: %v", err)
		}
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestRootDirCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	client, err := getSftpClient(user, usePubKey)
	if err != nil {
		t.Errorf("unable to create sftp client: %v", err)
	} else {
		defer client.Close()
		err = client.Rename("/", "rootdir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error renaming root dir: %v", err)
		}
		err = client.Symlink("/", "rootdir")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error symlinking root dir: %v", err)
		}
		err = client.RemoveDirectory("/")
		if !strings.Contains(err.Error(), "Permission Denied") {
			t.Errorf("unexpected error removing root dir: %v", err)
		}
	}
	httpd.RemoveUser(user, http.StatusOK)
	os.RemoveAll(user.GetHomeDir())
}

func TestRelativePaths(t *testing.T) {
	user := getTestUser(true)
	path := filepath.Join(user.HomeDir, "/")
	fs := vfs.NewOsFs("")
	rel := fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "//")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "../..")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "../../../../../")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "/..")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "/../../../..")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, ".")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "somedir")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/somedir" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
	path = filepath.Join(user.HomeDir, "/somedir/subdir")
	rel = fs.GetRelativePath(path, user.GetHomeDir())
	if rel != "/somedir/subdir" {
		t.Errorf("Unexpected relative path: %v", rel)
	}
}

func TestUserPerms(t *testing.T) {
	user := getTestUser(true)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermListItems}
	user.Permissions["/p"] = []string{dataprovider.PermDelete}
	user.Permissions["/p/1"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user.Permissions["/p/2"] = []string{dataprovider.PermCreateDirs}
	user.Permissions["/p/3"] = []string{dataprovider.PermChmod}
	user.Permissions["/p/3/4"] = []string{dataprovider.PermChtimes}
	user.Permissions["/tmp"] = []string{dataprovider.PermRename}
	if !user.HasPerm(dataprovider.PermListItems, "/") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermListItems, ".") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermListItems, "") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermListItems, "../") {
		t.Error("expected permission not found")
	}
	// path p and /p are the same
	if !user.HasPerm(dataprovider.PermDelete, "/p") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermDownload, "/p/1") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermCreateDirs, "p/2") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermChmod, "/p/3") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermChtimes, "p/3/4/") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermChtimes, "p/3/4/../4") {
		t.Error("expected permission not found")
	}
	// undefined paths have permissions of the nearest path
	if !user.HasPerm(dataprovider.PermListItems, "/p34") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermListItems, "/p34/p1/file.dat") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermChtimes, "/p/3/4/5/6") {
		t.Error("expected permission not found")
	}
	if !user.HasPerm(dataprovider.PermDownload, "/p/1/test/file.dat") {
		t.Error("expected permission not found")
	}
}

func TestUserFiltersIPMaskConditions(t *testing.T) {
	user := getTestUser(true)
	// with no filter login must be allowed even if the remoteIP is invalid
	if !user.IsLoginAllowed("192.168.1.5") {
		t.Error("unexpected login denied")
	}
	if !user.IsLoginAllowed("invalid") {
		t.Error("unexpected login denied")
	}
	user.Filters.DeniedIP = append(user.Filters.DeniedIP, "192.168.1.0/24")
	if user.IsLoginAllowed("192.168.1.5") {
		t.Error("unexpected login allowed")
	}
	if !user.IsLoginAllowed("192.168.2.6") {
		t.Error("unexpected login denied")
	}
	user.Filters.AllowedIP = append(user.Filters.AllowedIP, "192.168.1.5/32")
	// if the same ip/mask is both denied and allowed then login must be denied
	if user.IsLoginAllowed("192.168.1.5") {
		t.Error("unexpected login allowed")
	}
	if user.IsLoginAllowed("192.168.3.6") {
		t.Error("unexpected login allowed")
	}
	user.Filters.DeniedIP = []string{}
	if !user.IsLoginAllowed("192.168.1.5") {
		t.Error("unexpected login denied")
	}
	if user.IsLoginAllowed("192.168.1.6") {
		t.Error("unexpected login allowed")
	}
	user.Filters.DeniedIP = []string{"192.168.0.0/16", "172.16.0.0/16"}
	user.Filters.AllowedIP = []string{}
	if user.IsLoginAllowed("192.168.5.255") {
		t.Error("unexpected login allowed")
	}
	if user.IsLoginAllowed("172.16.1.2") {
		t.Error("unexpected login allowed")
	}
	if !user.IsLoginAllowed("172.18.2.1") {
		t.Error("unexpected login denied")
	}
	user.Filters.AllowedIP = []string{"10.4.4.0/24"}
	if user.IsLoginAllowed("10.5.4.2") {
		t.Error("unexpected login allowed")
	}
	if !user.IsLoginAllowed("10.4.4.2") {
		t.Error("unexpected login denied")
	}
	if !user.IsLoginAllowed("invalid") {
		t.Error("unexpected login denied")
	}
}

func TestSSHCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	_, err = runSSHCommand("ls", user, usePubKey)
	if err == nil {
		t.Errorf("unsupported ssh command must fail")
	}
	_, err = runSSHCommand("cd", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error for ssh cd command: %v", err)
	}
	out, err := runSSHCommand("pwd", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.Fail()
	}
	if string(out) != "/\n" {
		t.Errorf("invalid response for ssh pwd command: %v", string(out))
	}
	out, err = runSSHCommand("md5sum", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.Fail()
	}
	// echo -n '' | md5sum
	if !strings.Contains(string(out), "d41d8cd98f00b204e9800998ecf8427e") {
		t.Errorf("invalid md5sum: %v", string(out))
	}
	out, err = runSSHCommand("sha1sum", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.Fail()
	}
	if !strings.Contains(string(out), "da39a3ee5e6b4b0d3255bfef95601890afd80709") {
		t.Errorf("invalid sha1sum: %v", string(out))
	}
	out, err = runSSHCommand("sha256sum", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.Fail()
	}
	if !strings.Contains(string(out), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Errorf("invalid sha256sum: %v", string(out))
	}
	out, err = runSSHCommand("sha384sum", user, usePubKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		t.Fail()
	}
	if !strings.Contains(string(out), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b") {
		t.Errorf("invalid sha384sum: %v", string(out))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
}

func TestSSHFileHash(t *testing.T) {
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
		user.Permissions = make(map[string][]string)
		user.Permissions["/"] = []string{dataprovider.PermUpload}
		_, _, err = httpd.UpdateUser(user, http.StatusOK)
		if err != nil {
			t.Errorf("unable to update user: %v", err)
		}
		_, err = runSSHCommand("sha512sum "+testFileName, user, usePubKey)
		if err == nil {
			t.Errorf("hash command with no list permission must fail")
		}
		user.Permissions["/"] = []string{dataprovider.PermAny}
		_, _, err = httpd.UpdateUser(user, http.StatusOK)
		if err != nil {
			t.Errorf("unable to update user: %v", err)
		}
		initialHash, err := computeHashForFile(sha512.New(), testFilePath)
		if err != nil {
			t.Errorf("error computing file hash: %v", err)
		}
		out, err := runSSHCommand("sha512sum "+testFileName, user, usePubKey)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			t.Fail()
		}
		if !strings.Contains(string(out), initialHash) {
			t.Errorf("invalid sha512sum: %v", string(out))
		}
		_, err = runSSHCommand("sha512sum invalid_path", user, usePubKey)
		if err == nil {
			t.Errorf("hash for an invalid path must fail")
		}
		os.Remove(testFilePath)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
}

func TestBasicGitCommands(t *testing.T) {
	if len(gitPath) == 0 || len(sshPath) == 0 {
		t.Skip("git and/or ssh command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	repoName := "testrepo"
	clonePath := filepath.Join(homeBasePath, repoName)
	os.RemoveAll(user.GetHomeDir())
	os.RemoveAll(filepath.Join(homeBasePath, repoName))
	out, err := initGitRepo(filepath.Join(user.HomeDir, repoName))
	if err != nil {
		t.Errorf("unexpected error: %v out: %v", err, string(out))
	}
	out, err = cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	if err != nil {
		t.Errorf("unexpected error: %v out: %v", err, string(out))
	}
	out, err = addFileToGitRepo(clonePath, 128)
	if err != nil {
		t.Errorf("unexpected error: %v out: %v", err, string(out))
	}
	user.QuotaFiles = 100000
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	out, err = pushToGitRepo(clonePath)
	if err != nil {
		t.Errorf("unexpected error: %v out: %v", err, string(out))
		printLatestLogs(10)
	}
	err = waitQuotaScans()
	if err != nil {
		t.Errorf("error waiting for active quota scans: %v", err)
	}
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	if err != nil {
		t.Errorf("unable to get user: %v", err)
	}
	user.QuotaSize = user.UsedQuotaSize - 1
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to update user: %v", err)
	}
	out, err = pushToGitRepo(clonePath)
	if err == nil {
		t.Errorf("git push must fail if quota is exceeded, out: %v", string(out))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
	os.RemoveAll(clonePath)
}

func TestGitErrors(t *testing.T) {
	if len(gitPath) == 0 || len(sshPath) == 0 {
		t.Skip("git and/or ssh command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	repoName := "testrepo"
	clonePath := filepath.Join(homeBasePath, repoName)
	os.RemoveAll(user.GetHomeDir())
	os.RemoveAll(filepath.Join(homeBasePath, repoName))
	out, err := cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	if err == nil {
		t.Errorf("cloning a missing repo must fail, out: %v", string(out))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	if err != nil {
		t.Errorf("unable to remove user: %v", err)
	}
	os.RemoveAll(user.GetHomeDir())
	os.RemoveAll(clonePath)
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
	os.Remove(testFilePath)
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
	os.Remove(testFilePath)
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

func TestSCPPermsSubDirs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/somedir"] = []string{dataprovider.PermListItems, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	if err != nil {
		t.Errorf("unable to add user: %v", err)
	}
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	subPath := filepath.Join(user.GetHomeDir(), "somedir")
	testFileSize := int64(65535)
	os.MkdirAll(subPath, 0777)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/somedir")
	err = scpDownload(localPath, remoteDownPath, false, true)
	if err == nil {
		t.Error("download a dir with no permissions must fail")
	}
	os.Remove(subPath)
	err = createTestFile(subPath, testFileSize)
	if err != nil {
		t.Errorf("unable to create test file: %v", err)
	}
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err != nil {
		t.Errorf("unexpected download error: %v", err)
	}
	os.Chmod(subPath, 0001)
	err = scpDownload(localPath, remoteDownPath, false, false)
	if err == nil {
		t.Error("download a file with no system permissions must fail")
	}
	os.Chmod(subPath, 0755)
	os.Remove(localPath)
	os.RemoveAll(user.GetHomeDir())
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
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
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
		t.Errorf("scp upload must fail, the user cannot create files in a missing dir")
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
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermCreateDirs}
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
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
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
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
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
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	if err != nil {
		t.Errorf("error uploading existing file via scp: %v", err)
	}
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
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
	os.Remove(localPath)
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
		Username:       defaultUsername,
		Password:       defaultPassword,
		HomeDir:        filepath.Join(homeBasePath, defaultUsername),
		Status:         1,
		ExpirationDate: 0,
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = allPerms
	if usePubKey {
		user.PublicKeys = []string{testPubKey}
		user.Password = ""
	}
	return user
}

func runSSHCommand(command string, user dataprovider.User, usePubKey bool) ([]byte, error) {
	var sshSession *ssh.Session
	var output []byte
	config := &ssh.ClientConfig{
		User: defaultUsername,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if usePubKey {
		key, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
		if err != nil {
			return output, err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return output, err
	}
	defer conn.Close()
	sshSession, err = conn.NewSession()
	if err != nil {
		return output, err
	}
	var stdout, stderr bytes.Buffer
	sshSession.Stdout = &stdout
	sshSession.Stderr = &stderr
	err = sshSession.Run(command)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", command, stderr.Bytes())
	}
	return stdout.Bytes(), err
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
	// we cannot defer closing or Lstat will fail for uploads in atomic mode
	destFile.Close()
	if expectedSize > 0 {
		fi, err := client.Stat(remoteDestPath)
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

func waitQuotaScans() error {
	time.Sleep(100 * time.Millisecond)
	scans, _, err := httpd.GetQuotaScans(http.StatusOK)
	if err != nil {
		return err
	}
	for len(scans) > 0 {
		time.Sleep(100 * time.Millisecond)
		scans, _, err = httpd.GetQuotaScans(http.StatusOK)
		if err != nil {
			return err
		}
	}
	return nil
}

func initGitRepo(path string) ([]byte, error) {
	os.MkdirAll(path, 0777)
	args := []string{"init", "--bare"}
	cmd := exec.Command(gitPath, args...)
	cmd.Dir = path
	return cmd.CombinedOutput()
}

func pushToGitRepo(repoPath string) ([]byte, error) {
	cmd := exec.Command(gitPath, "push")
	cmd.Dir = repoPath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH=%v", gitWrapPath))
	return cmd.CombinedOutput()
}

func cloneGitRepo(basePath, remotePath, username string) ([]byte, error) {
	remoteUrl := fmt.Sprintf("ssh://%v@127.0.0.1:2022%v", username, remotePath)
	args := []string{"clone", remoteUrl}
	cmd := exec.Command(gitPath, args...)
	cmd.Dir = basePath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH=%v", gitWrapPath))
	return cmd.CombinedOutput()
}

func addFileToGitRepo(repoPath string, fileSize int64) ([]byte, error) {
	path := filepath.Join(repoPath, "test")
	err := createTestFile(path, fileSize)
	if err != nil {
		return []byte(""), err
	}
	cmd := exec.Command(gitPath, "config", "user.email", "testuser@example.com")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "config", "user.name", "testuser")
	cmd.Dir = repoPath
	out, err = cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "add", "test")
	cmd.Dir = repoPath
	out, err = cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "commit", "-am", "test")
	cmd.Dir = repoPath
	return cmd.CombinedOutput()
}

func getExtAuthScriptContent(user dataprovider.User, sleepTime int, nonJsonResponse bool) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	u, _ := json.Marshal(user)
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
	if nonJsonResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	extAuthContent = append(extAuthContent, []byte("else\n")...)
	if nonJsonResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte("echo '{\"username\":\"\"}'\n")...)
	}
	extAuthContent = append(extAuthContent, []byte("fi\n")...)
	if sleepTime > 0 {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("sleep %v\n", sleepTime))...)
	}
	return extAuthContent
}

func printLatestLogs(maxNumberOfLines int) {
	var lines []string
	f, err := os.Open(logFilePath)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text()+"\r\n")
		for len(lines) > maxNumberOfLines {
			lines = lines[1:]
		}
	}
	if scanner.Err() != nil {
		logger.WarnToConsole("Unable to print latest logs: %v", scanner.Err())
		return
	}
	for _, line := range lines {
		logger.DebugToConsole(line)
	}
}
