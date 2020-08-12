package webdavd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"
	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
	"github.com/drakkan/sftpgo/utils"
)

var (
	err401        = errors.New("Unauthorized")
	err403        = errors.New("Forbidden")
	xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
	xRealIP       = http.CanonicalHeaderKey("X-Real-IP")
)

type webDavServer struct {
	config  *Configuration
	certMgr *common.CertManager
}

func newServer(config *Configuration, configDir string) (*webDavServer, error) {
	var err error
	server := &webDavServer{
		config:  config,
		certMgr: nil,
	}
	certificateFile := getConfigPath(config.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(config.CertificateKeyFile, configDir)
	if len(certificateFile) > 0 && len(certificateKeyFile) > 0 {
		server.certMgr, err = common.NewCertManager(certificateFile, certificateKeyFile, logSender)
		if err != nil {
			return server, err
		}
	}
	return server, nil
}

func (s *webDavServer) listenAndServe() error {
	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.config.BindAddress, s.config.BindPort),
		Handler:           server,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}
	if s.certMgr != nil {
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: s.certMgr.GetCertificateFunc(),
		}
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

// ServeHTTP implements the http.Handler interface
func (s *webDavServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	checkRemoteAddress(r)
	if err := common.Config.ExecutePostConnectHook(r.RemoteAddr, common.ProtocolWebDAV); err != nil {
		http.Error(w, common.ErrConnectionDenied.Error(), http.StatusForbidden)
		return
	}
	user, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"SFTPGo WebDAV\"")
		http.Error(w, err401.Error(), http.StatusUnauthorized)
		return
	}

	connectionID, err := s.validateUser(user, r)
	if err != nil {
		updateLoginMetrics(user.Username, r.RemoteAddr, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	fs, err := user.GetFilesystem(connectionID)
	if err != nil {
		updateLoginMetrics(user.Username, r.RemoteAddr, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	updateLoginMetrics(user.Username, r.RemoteAddr, err)

	ctx := context.WithValue(r.Context(), requestIDKey, connectionID)
	ctx = context.WithValue(ctx, requestStartKey, time.Now())

	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connectionID, common.ProtocolWebDAV, user, fs),
		request:        r,
	}
	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	connection.Fs.CheckRootPath(connection.GetUsername(), user.GetUID(), user.GetGID())
	connection.Log(logger.LevelInfo, "User id: %d, logged in with WebDAV, method: %v, username: %#v, home_dir: %#v remote addr: %#v",
		user.ID, r.Method, user.Username, user.HomeDir, r.RemoteAddr)
	dataprovider.UpdateLastLogin(user) //nolint:errcheck

	prefix := path.Join("/", user.Username)
	// see RFC4918, section 9.4
	if r.Method == "GET" {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), prefix)
		info, err := connection.Stat(ctx, p)
		if err == nil && info.IsDir() {
			r.Method = "PROPFIND"
			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}

	handler := webdav.Handler{
		Prefix:     prefix,
		FileSystem: connection,
		LockSystem: webdav.NewMemLS(),
		Logger:     writeLog,
	}
	handler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *webDavServer) authenticate(r *http.Request) (dataprovider.User, error) {
	var user dataprovider.User
	var err error
	username, password, ok := r.BasicAuth()
	if !ok {
		return user, err401
	}
	user, err = dataprovider.CheckUserAndPass(username, password, utils.GetIPFromRemoteAddress(r.RemoteAddr), common.ProtocolWebDAV)
	if err != nil {
		updateLoginMetrics(username, r.RemoteAddr, err)
		return user, err
	}
	return user, err
}

func (s *webDavServer) validateUser(user dataprovider.User, r *http.Request) (string, error) {
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolWebDAV, connID)

	uriSegments := strings.Split(path.Clean(r.URL.Path), "/")
	if len(uriSegments) < 2 || uriSegments[1] != user.Username {
		logger.Debug(logSender, connectionID, "URI %#v not allowed for user %#v", r.URL.Path, user.Username)
		return connID, err403
	}

	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %#v has an invalid home dir: %#v. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return connID, fmt.Errorf("cannot login user with invalid home dir: %#v", user.HomeDir)
	}
	if user.MaxSessions > 0 {
		activeSessions := common.Connections.GetActiveSessions(user.Username)
		if activeSessions >= user.MaxSessions {
			logger.Debug(logSender, connID, "authentication refused for user: %#v, too many open sessions: %v/%v", user.Username,
				activeSessions, user.MaxSessions)
			return connID, fmt.Errorf("too many open sessions: %v", activeSessions)
		}
	}
	if dataprovider.GetQuotaTracking() > 0 && user.HasOverlappedMappedPaths() {
		logger.Debug(logSender, connectionID, "cannot login user %#v, overlapping mapped folders are allowed only with quota tracking disabled",
			user.Username)
		return connID, errors.New("overlapping mapped folders are allowed only with quota tracking disabled")
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, remote address is not allowed: %v", user.Username, r.RemoteAddr)
		return connID, fmt.Errorf("Login for user %#v is not allowed from this address: %v", user.Username, r.RemoteAddr)
	}
	return connID, nil
}

func writeLog(r *http.Request, err error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fields := map[string]interface{}{
		"remote_addr": r.RemoteAddr,
		"proto":       r.Proto,
		"method":      r.Method,
		"user_agent":  r.UserAgent(),
		"uri":         fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)}
	if reqID, ok := r.Context().Value(requestIDKey).(string); ok {
		fields["request_id"] = reqID
	}
	if reqStart, ok := r.Context().Value(requestStartKey).(time.Time); ok {
		fields["elapsed_ms"] = time.Since(reqStart).Nanoseconds() / 1000000
	}
	logger.GetLogger().Info().
		Timestamp().
		Str("sender", logSender).
		Fields(fields).
		Err(err).
		Msg("")
}

func checkRemoteAddress(r *http.Request) {
	if common.Config.ProxyProtocol != 0 {
		return
	}

	var ip string

	if xrip := r.Header.Get(xRealIP); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get(xForwardedFor); xff != "" {
		i := strings.Index(xff, ", ")
		if i == -1 {
			i = len(xff)
		}
		ip = strings.TrimSpace(xff[:i])
	}

	if len(ip) > 0 {
		r.RemoteAddr = ip
	}
}

func updateLoginMetrics(username, remoteAddress string, err error) {
	metrics.AddLoginAttempt(dataprovider.LoginMethodPassword)
	ip := utils.GetIPFromRemoteAddress(remoteAddress)
	if err != nil {
		logger.ConnectionFailedLog(username, ip, dataprovider.LoginMethodPassword, common.ProtocolWebDAV, err.Error())
	}
	metrics.AddLoginResult(dataprovider.LoginMethodPassword, err)
	dataprovider.ExecutePostLoginHook(username, dataprovider.LoginMethodPassword, ip, common.ProtocolWebDAV, err)
}
