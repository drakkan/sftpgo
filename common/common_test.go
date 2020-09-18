package common

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	logSenderTest    = "common_test"
	httpAddr         = "127.0.0.1:9999"
	httpProxyAddr    = "127.0.0.1:7777"
	configDir        = ".."
	osWindows        = "windows"
	userTestUsername = "common_test_username"
	userTestPwd      = "common_test_pwd"
)

type providerConf struct {
	Config dataprovider.Config `json:"data_provider" mapstructure:"data_provider"`
}

type fakeConnection struct {
	*BaseConnection
	command string
}

func (c *fakeConnection) AddUser(user dataprovider.User) error {
	fs, err := user.GetFilesystem(c.GetID())
	if err != nil {
		return err
	}
	c.BaseConnection.User = user
	c.BaseConnection.Fs = fs
	return nil
}

func (c *fakeConnection) Disconnect() error {
	Connections.Remove(c.GetID())
	return nil
}

func (c *fakeConnection) GetClientVersion() string {
	return ""
}

func (c *fakeConnection) GetCommand() string {
	return c.command
}

func (c *fakeConnection) GetRemoteAddress() string {
	return ""
}

func TestMain(m *testing.M) {
	logfilePath := "common_test.log"
	logger.InitLogger(logfilePath, 5, 1, 28, false, zerolog.DebugLevel)

	viper.SetEnvPrefix("sftpgo")
	replacer := strings.NewReplacer(".", "__")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("sftpgo")
	viper.AutomaticEnv()
	viper.AllowEmptyEnv(true)

	driver, err := initializeDataprovider(-1)
	if err != nil {
		logger.WarnToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}
	logger.InfoToConsole("Starting COMMON tests, provider: %v", driver)
	Initialize(Configuration{})
	httpConfig := httpclient.Config{
		Timeout: 5,
	}
	httpConfig.Initialize(configDir)

	go func() {
		// start a test HTTP server to receive action notifications
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK\n")
		})
		http.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Not found\n")
		})
		if err := http.ListenAndServe(httpAddr, nil); err != nil {
			logger.ErrorToConsole("could not start HTTP notification server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		Config.ProxyProtocol = 2
		listener, err := net.Listen("tcp", httpProxyAddr)
		if err != nil {
			logger.ErrorToConsole("error creating listener for proxy protocol server: %v", err)
			os.Exit(1)
		}
		proxyListener, err := Config.GetProxyListener(listener)
		if err != nil {
			logger.ErrorToConsole("error creating proxy protocol listener: %v", err)
			os.Exit(1)
		}
		Config.ProxyProtocol = 0

		s := &http.Server{}
		if err := s.Serve(proxyListener); err != nil {
			logger.ErrorToConsole("could not start HTTP proxy protocol server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(httpAddr)
	waitTCPListening(httpProxyAddr)
	exitCode := m.Run()
	os.Remove(logfilePath) //nolint:errcheck
	os.Exit(exitCode)
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
		conn.Close()
		break
	}
}

func initializeDataprovider(trackQuota int) (string, error) {
	configDir := ".."
	viper.AddConfigPath(configDir)
	if err := viper.ReadInConfig(); err != nil {
		return "", err
	}
	var cfg providerConf
	if err := viper.Unmarshal(&cfg); err != nil {
		return "", err
	}
	if trackQuota >= 0 && trackQuota <= 2 {
		cfg.Config.TrackQuota = trackQuota
	}
	return cfg.Config.Driver, dataprovider.Initialize(cfg.Config, configDir)
}

func closeDataprovider() error {
	return dataprovider.Close()
}

func TestIdleConnections(t *testing.T) {
	configCopy := Config

	Config.IdleTimeout = 1
	Initialize(Config)

	username := "test_user"
	user := dataprovider.User{
		Username: username,
	}
	c := NewBaseConnection("id1", ProtocolSFTP, user, nil)
	c.lastActivity = time.Now().Add(-24 * time.Hour).UnixNano()
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	assert.Equal(t, Connections.GetActiveSessions(username), 1)
	c = NewBaseConnection("id2", ProtocolFTP, dataprovider.User{}, nil)
	c.lastActivity = time.Now().UnixNano()
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	assert.Equal(t, Connections.GetActiveSessions(username), 1)
	assert.Len(t, Connections.GetStats(), 2)

	startIdleTimeoutTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return Connections.GetActiveSessions(username) == 0 }, 1*time.Second, 200*time.Millisecond)
	stopIdleTimeoutTicker()
	assert.Len(t, Connections.GetStats(), 1)
	c.lastActivity = time.Now().Add(-24 * time.Hour).UnixNano()
	startIdleTimeoutTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 1*time.Second, 200*time.Millisecond)
	stopIdleTimeoutTicker()

	Config = configCopy
}

func TestCloseConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolSFTP, dataprovider.User{}, nil)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	assert.Len(t, Connections.GetStats(), 1)
	res := Connections.Close(fakeConn.GetID())
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
	res = Connections.Close(fakeConn.GetID())
	assert.False(t, res)
	Connections.Remove(fakeConn.GetID())
}

func TestSwapConnection(t *testing.T) {
	c := NewBaseConnection("id", ProtocolFTP, dataprovider.User{}, nil)
	fakeConn := &fakeConnection{
		BaseConnection: c,
	}
	Connections.Add(fakeConn)
	if assert.Len(t, Connections.GetStats(), 1) {
		assert.Equal(t, "", Connections.GetStats()[0].Username)
	}
	c = NewBaseConnection("id", ProtocolFTP, dataprovider.User{
		Username: userTestUsername,
	}, nil)
	fakeConn = &fakeConnection{
		BaseConnection: c,
	}
	err := Connections.Swap(fakeConn)
	assert.NoError(t, err)
	if assert.Len(t, Connections.GetStats(), 1) {
		assert.Equal(t, userTestUsername, Connections.GetStats()[0].Username)
	}
	res := Connections.Close(fakeConn.GetID())
	assert.True(t, res)
	assert.Eventually(t, func() bool { return len(Connections.GetStats()) == 0 }, 300*time.Millisecond, 50*time.Millisecond)
	err = Connections.Swap(fakeConn)
	assert.Error(t, err)
}

func TestAtomicUpload(t *testing.T) {
	configCopy := Config

	Config.UploadMode = UploadModeStandard
	assert.False(t, Config.IsAtomicUploadEnabled())
	Config.UploadMode = UploadModeAtomic
	assert.True(t, Config.IsAtomicUploadEnabled())
	Config.UploadMode = UploadModeAtomicWithResume
	assert.True(t, Config.IsAtomicUploadEnabled())

	Config = configCopy
}

func TestConnectionStatus(t *testing.T) {
	username := "test_user"
	user := dataprovider.User{
		Username: username,
	}
	fs := vfs.NewOsFs("", os.TempDir(), nil)
	c1 := NewBaseConnection("id1", ProtocolSFTP, user, fs)
	fakeConn1 := &fakeConnection{
		BaseConnection: c1,
	}
	t1 := NewBaseTransfer(nil, c1, nil, "/p1", "/r1", TransferUpload, 0, 0, 0, true, fs)
	t1.BytesReceived = 123
	t2 := NewBaseTransfer(nil, c1, nil, "/p2", "/r2", TransferDownload, 0, 0, 0, true, fs)
	t2.BytesSent = 456
	c2 := NewBaseConnection("id2", ProtocolSSH, user, nil)
	fakeConn2 := &fakeConnection{
		BaseConnection: c2,
		command:        "md5sum",
	}
	c3 := NewBaseConnection("id3", ProtocolWebDAV, user, nil)
	fakeConn3 := &fakeConnection{
		BaseConnection: c3,
		command:        "PROPFIND",
	}
	t3 := NewBaseTransfer(nil, c3, nil, "/p2", "/r2", TransferDownload, 0, 0, 0, true, fs)
	Connections.Add(fakeConn1)
	Connections.Add(fakeConn2)
	Connections.Add(fakeConn3)

	stats := Connections.GetStats()
	assert.Len(t, stats, 3)
	for _, stat := range stats {
		assert.Equal(t, stat.Username, username)
		assert.True(t, strings.HasPrefix(stat.GetConnectionInfo(), stat.Protocol))
		assert.True(t, strings.HasPrefix(stat.GetConnectionDuration(), "00:"))
		if stat.ConnectionID == "SFTP_id1" {
			assert.Len(t, stat.Transfers, 2)
			assert.Greater(t, len(stat.GetTransfersAsString()), 0)
			for _, tr := range stat.Transfers {
				if tr.OperationType == operationDownload {
					assert.True(t, strings.HasPrefix(tr.getConnectionTransferAsString(), "DL"))
				} else if tr.OperationType == operationUpload {
					assert.True(t, strings.HasPrefix(tr.getConnectionTransferAsString(), "UL"))
				}
			}
		} else if stat.ConnectionID == "DAV_id3" {
			assert.Len(t, stat.Transfers, 1)
			assert.Greater(t, len(stat.GetTransfersAsString()), 0)
		} else {
			assert.Equal(t, 0, len(stat.GetTransfersAsString()))
		}
	}

	err := t1.Close()
	assert.NoError(t, err)
	err = t2.Close()
	assert.NoError(t, err)

	err = fakeConn3.SignalTransfersAbort()
	assert.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&t3.AbortTransfer))
	err = t3.Close()
	assert.NoError(t, err)
	err = fakeConn3.SignalTransfersAbort()
	assert.Error(t, err)

	Connections.Remove(fakeConn1.GetID())
	Connections.Remove(fakeConn2.GetID())
	Connections.Remove(fakeConn3.GetID())
	stats = Connections.GetStats()
	assert.Len(t, stats, 0)
}

func TestQuotaScans(t *testing.T) {
	username := "username"
	assert.True(t, QuotaScans.AddUserQuotaScan(username))
	assert.False(t, QuotaScans.AddUserQuotaScan(username))
	if assert.Len(t, QuotaScans.GetUsersQuotaScans(), 1) {
		assert.Equal(t, QuotaScans.GetUsersQuotaScans()[0].Username, username)
	}

	assert.True(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.False(t, QuotaScans.RemoveUserQuotaScan(username))
	assert.Len(t, QuotaScans.GetUsersQuotaScans(), 0)

	folderName := "/folder"
	assert.True(t, QuotaScans.AddVFolderQuotaScan(folderName))
	assert.False(t, QuotaScans.AddVFolderQuotaScan(folderName))
	if assert.Len(t, QuotaScans.GetVFoldersQuotaScans(), 1) {
		assert.Equal(t, QuotaScans.GetVFoldersQuotaScans()[0].MappedPath, folderName)
	}

	assert.True(t, QuotaScans.RemoveVFolderQuotaScan(folderName))
	assert.False(t, QuotaScans.RemoveVFolderQuotaScan(folderName))
	assert.Len(t, QuotaScans.GetVFoldersQuotaScans(), 0)
}

func TestProxyProtocolVersion(t *testing.T) {
	c := Configuration{
		ProxyProtocol: 1,
	}
	proxyListener, err := c.GetProxyListener(nil)
	assert.NoError(t, err)
	assert.Nil(t, proxyListener.Policy)

	c.ProxyProtocol = 2
	proxyListener, err = c.GetProxyListener(nil)
	assert.NoError(t, err)
	assert.NotNil(t, proxyListener.Policy)

	c.ProxyProtocol = 1
	c.ProxyAllowed = []string{"invalid"}
	_, err = c.GetProxyListener(nil)
	assert.Error(t, err)

	c.ProxyProtocol = 2
	_, err = c.GetProxyListener(nil)
	assert.Error(t, err)
}

func TestProxyProtocol(t *testing.T) {
	httpClient := httpclient.GetHTTPClient()
	resp, err := httpClient.Get(fmt.Sprintf("http://%v", httpProxyAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestPostConnectHook(t *testing.T) {
	Config.PostConnectHook = ""

	remoteAddr := &net.IPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Zone: "",
	}

	assert.NoError(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolFTP))

	Config.PostConnectHook = "http://foo\x7f.com/"
	assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolSFTP))

	Config.PostConnectHook = "http://invalid:1234/"
	assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolSFTP))

	Config.PostConnectHook = fmt.Sprintf("http://%v/404", httpAddr)
	assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolFTP))

	Config.PostConnectHook = fmt.Sprintf("http://%v", httpAddr)
	assert.NoError(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolFTP))

	Config.PostConnectHook = "invalid"
	assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolFTP))

	if runtime.GOOS == osWindows {
		Config.PostConnectHook = "C:\\bad\\command"
		assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolSFTP))
	} else {
		Config.PostConnectHook = "/invalid/path"
		assert.Error(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolSFTP))

		hookCmd, err := exec.LookPath("true")
		assert.NoError(t, err)
		Config.PostConnectHook = hookCmd
		assert.NoError(t, Config.ExecutePostConnectHook(remoteAddr.String(), ProtocolSFTP))
	}

	Config.PostConnectHook = ""
}
