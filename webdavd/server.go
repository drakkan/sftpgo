package webdavd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/cors"
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
	status  ServiceStatus
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
	addr := fmt.Sprintf("%s:%d", s.config.BindAddress, s.config.BindPort)
	s.status.IsActive = true
	s.status.Address = addr
	s.status.Protocol = "HTTP"
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}
	if s.config.Cors.Enabled {
		c := cors.New(cors.Options{
			AllowedOrigins:     s.config.Cors.AllowedOrigins,
			AllowedMethods:     s.config.Cors.AllowedMethods,
			AllowedHeaders:     s.config.Cors.AllowedHeaders,
			ExposedHeaders:     s.config.Cors.ExposedHeaders,
			MaxAge:             s.config.Cors.MaxAge,
			AllowCredentials:   s.config.Cors.AllowCredentials,
			OptionsPassthrough: true,
		})
		httpServer.Handler = c.Handler(server)
	} else {
		httpServer.Handler = server
	}
	if s.certMgr != nil {
		s.status.Protocol = "HTTPS"
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: s.certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

func (s *webDavServer) checkRequestMethod(ctx context.Context, r *http.Request, connection *Connection, prefix string) {
	// see RFC4918, section 9.4
	if r.Method == http.MethodGet {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), prefix)
		info, err := connection.Stat(ctx, p)
		if err == nil && info.IsDir() {
			r.Method = "PROPFIND"
			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}
}

// ServeHTTP implements the http.Handler interface
func (s *webDavServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(logSender, "", "panic in ServeHTTP: %#v stack strace: %v", r, string(debug.Stack()))
			http.Error(w, common.ErrGenericFailure.Error(), http.StatusInternalServerError)
		}
	}()
	checkRemoteAddress(r)
	if err := common.Config.ExecutePostConnectHook(r.RemoteAddr, common.ProtocolWebDAV); err != nil {
		http.Error(w, common.ErrConnectionDenied.Error(), http.StatusForbidden)
		return
	}
	user, _, lockSystem, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"SFTPGo WebDAV\"")
		http.Error(w, err401.Error(), http.StatusUnauthorized)
		return
	}

	if path.Clean(r.URL.Path) == "/" && (r.Method == http.MethodGet || r.Method == "PROPFIND" || r.Method == http.MethodOptions) {
		http.Redirect(w, r, path.Join("/", user.Username), http.StatusMovedPermanently)
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

	dataprovider.UpdateLastLogin(user) //nolint:errcheck

	prefix := path.Join("/", user.Username)
	s.checkRequestMethod(ctx, r, connection, prefix)

	handler := webdav.Handler{
		Prefix:     prefix,
		FileSystem: connection,
		LockSystem: lockSystem,
		Logger:     writeLog,
	}
	handler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *webDavServer) authenticate(r *http.Request) (dataprovider.User, bool, webdav.LockSystem, error) {
	var user dataprovider.User
	var err error
	username, password, ok := r.BasicAuth()
	if !ok {
		return user, false, nil, err401
	}
	result, ok := dataprovider.GetCachedWebDAVUser(username)
	if ok {
		cachedUser := result.(*dataprovider.CachedUser)
		if cachedUser.IsExpired() {
			dataprovider.RemoveCachedWebDAVUser(username)
		} else {
			if len(password) > 0 && cachedUser.Password == password {
				return cachedUser.User, true, cachedUser.LockSystem, nil
			}
			updateLoginMetrics(username, r.RemoteAddr, dataprovider.ErrInvalidCredentials)
			return user, false, nil, dataprovider.ErrInvalidCredentials
		}
	}
	user, err = dataprovider.CheckUserAndPass(username, password, utils.GetIPFromRemoteAddress(r.RemoteAddr), common.ProtocolWebDAV)
	if err != nil {
		updateLoginMetrics(username, r.RemoteAddr, err)
		return user, false, nil, err
	}
	lockSystem := webdav.NewMemLS()
	if password != "" {
		cachedUser := &dataprovider.CachedUser{
			User:       user,
			Password:   password,
			LockSystem: lockSystem,
		}
		if s.config.Cache.Users.ExpirationTime > 0 {
			cachedUser.Expiration = time.Now().Add(time.Duration(s.config.Cache.Users.ExpirationTime) * time.Minute)
		}
		dataprovider.CacheWebDAVUser(cachedUser, s.config.Cache.Users.MaxSize)
		tempFs, err := user.GetFilesystem("temp")
		if err == nil {
			tempFs.CheckRootPath(user.Username, user.UID, user.GID)
		}
	}
	return user, false, lockSystem, nil
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
	if utils.IsStringInSlice(common.ProtocolWebDAV, user.Filters.DeniedProtocols) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, protocol DAV is not allowed", user.Username)
		return connID, fmt.Errorf("Protocol DAV is not allowed for user %#v", user.Username)
	}
	if !user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, nil) {
		logger.Debug(logSender, connectionID, "cannot login user %#v, password login method is not allowed", user.Username)
		return connID, fmt.Errorf("Password login method is not allowed for user %#v", user.Username)
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
		Send()
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
