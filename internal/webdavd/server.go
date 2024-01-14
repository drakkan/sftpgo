// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package webdavd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/drakkan/webdav"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type webDavServer struct {
	config  *Configuration
	binding Binding
}

func (s *webDavServer) listenAndServe(compressor *middleware.Compressor) error {
	handler := compressor.Handler(s)
	httpServer := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
		ErrorLog:          log.New(&logger.StdLoggerWrapper{Sender: logSender}, "", 0),
	}
	if s.config.Cors.Enabled {
		c := cors.New(cors.Options{
			AllowedOrigins:       util.RemoveDuplicates(s.config.Cors.AllowedOrigins, true),
			AllowedMethods:       util.RemoveDuplicates(s.config.Cors.AllowedMethods, true),
			AllowedHeaders:       util.RemoveDuplicates(s.config.Cors.AllowedHeaders, true),
			ExposedHeaders:       util.RemoveDuplicates(s.config.Cors.ExposedHeaders, true),
			MaxAge:               s.config.Cors.MaxAge,
			AllowCredentials:     s.config.Cors.AllowCredentials,
			OptionsPassthrough:   s.config.Cors.OptionsPassthrough,
			OptionsSuccessStatus: s.config.Cors.OptionsSuccessStatus,
			AllowPrivateNetwork:  s.config.Cors.AllowPrivateNetwork,
		})
		handler = c.Handler(handler)
	}
	httpServer.Handler = handler
	if certMgr != nil && s.binding.EnableHTTPS {
		serviceStatus.Bindings = append(serviceStatus.Bindings, s.binding)
		certID := common.DefaultTLSKeyPaidID
		if getConfigPath(s.binding.CertificateFile, "") != "" && getConfigPath(s.binding.CertificateKeyFile, "") != "" {
			certID = s.binding.GetAddress()
		}
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(certID),
			MinVersion:     util.GetTLSVersion(s.binding.MinTLSVersion),
			NextProtos:     util.GetALPNProtocols(s.binding.Protocols),
			CipherSuites:   util.GetTLSCiphersFromNames(s.binding.TLSCipherSuites),
		}
		logger.Debug(logSender, "", "configured TLS cipher suites for binding %q: %v, certID: %v",
			s.binding.GetAddress(), httpServer.TLSConfig.CipherSuites, certID)
		if s.binding.isMutualTLSEnabled() {
			httpServer.TLSConfig.ClientCAs = certMgr.GetRootCAs()
			httpServer.TLSConfig.VerifyConnection = s.verifyTLSConnection
			switch s.binding.ClientAuthType {
			case 1:
				httpServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			case 2:
				httpServer.TLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}
		return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, true, logSender)
	}
	s.binding.EnableHTTPS = false
	serviceStatus.Bindings = append(serviceStatus.Bindings, s.binding)
	return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, false, logSender)
}

func (s *webDavServer) verifyTLSConnection(state tls.ConnectionState) error {
	if certMgr != nil {
		var clientCrt *x509.Certificate
		var clientCrtName string
		if len(state.PeerCertificates) > 0 {
			clientCrt = state.PeerCertificates[0]
			clientCrtName = clientCrt.Subject.String()
		}
		if len(state.VerifiedChains) == 0 {
			if s.binding.ClientAuthType == 2 {
				return nil
			}
			logger.Warn(logSender, "", "TLS connection cannot be verified: unable to get verification chain")
			return errors.New("TLS connection cannot be verified: unable to get verification chain")
		}
		for _, verifiedChain := range state.VerifiedChains {
			var caCrt *x509.Certificate
			if len(verifiedChain) > 0 {
				caCrt = verifiedChain[len(verifiedChain)-1]
			}
			if certMgr.IsRevoked(clientCrt, caCrt) {
				logger.Debug(logSender, "", "tls handshake error, client certificate %q has been revoked", clientCrtName)
				return common.ErrCrtRevoked
			}
		}
	}

	return nil
}

// returns true if we have to handle a HEAD response, for a directory, ourself
func (s *webDavServer) checkRequestMethod(ctx context.Context, r *http.Request, connection *Connection) bool {
	// see RFC4918, section 9.4
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		p := path.Clean(r.URL.Path)
		if s.binding.Prefix != "" {
			p = strings.TrimPrefix(p, s.binding.Prefix)
		}
		info, err := connection.Stat(ctx, p)
		if err == nil && info.IsDir() {
			if r.Method == http.MethodHead {
				return true
			}
			r.Method = "PROPFIND"
			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}
	return false
}

// ServeHTTP implements the http.Handler interface
func (s *webDavServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(logSender, "", "panic in ServeHTTP: %q stack trace: %v", r, string(debug.Stack()))
			http.Error(w, common.ErrGenericFailure.Error(), http.StatusInternalServerError)
		}
	}()

	ipAddr := s.checkRemoteAddress(r)

	common.Connections.AddClientConnection(ipAddr)
	defer common.Connections.RemoveClientConnection(ipAddr)

	if err := common.Connections.IsNewConnectionAllowed(ipAddr, common.ProtocolWebDAV); err != nil {
		logger.Log(logger.LevelDebug, common.ProtocolWebDAV, "", "connection not allowed from ip %q: %v", ipAddr, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if common.IsBanned(ipAddr, common.ProtocolWebDAV) {
		http.Error(w, common.ErrConnectionDenied.Error(), http.StatusForbidden)
		return
	}
	delay, err := common.LimitRate(common.ProtocolWebDAV, ipAddr)
	if err != nil {
		delay += 499999999 * time.Nanosecond
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
		w.Header().Set("X-Retry-In", delay.String())
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolWebDAV); err != nil {
		http.Error(w, common.ErrConnectionDenied.Error(), http.StatusForbidden)
		return
	}
	user, isCached, lockSystem, loginMethod, err := s.authenticate(r, ipAddr)
	if err != nil {
		if !s.binding.DisableWWWAuthHeader {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"SFTPGo WebDAV\"")
		}
		http.Error(w, fmt.Sprintf("Authentication error: %v", err), http.StatusUnauthorized)
		return
	}

	connectionID, err := s.validateUser(&user, r, loginMethod)
	if err != nil {
		// remove the cached user, we have not yet validated its filesystem
		dataprovider.RemoveCachedWebDAVUser(user.Username)
		updateLoginMetrics(&user, ipAddr, loginMethod, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !isCached {
		err = user.CheckFsRoot(connectionID)
	} else {
		_, err = user.GetFilesystemForPath("/", connectionID)
	}
	if err != nil {
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable to check fs root: %v close fs error: %v", err, errClose)
		updateLoginMetrics(&user, ipAddr, loginMethod, common.ErrInternalFailure)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connectionID, common.ProtocolWebDAV, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}
	if err = common.Connections.Add(connection); err != nil {
		errClose := user.CloseFs()
		logger.Warn(logSender, connectionID, "unable add connection: %v close fs error: %v", err, errClose)
		updateLoginMetrics(&user, ipAddr, loginMethod, err)
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	updateLoginMetrics(&user, ipAddr, loginMethod, err)

	ctx := context.WithValue(r.Context(), requestIDKey, connectionID)
	ctx = context.WithValue(ctx, requestStartKey, time.Now())

	dataprovider.UpdateLastLogin(&user)

	if s.checkRequestMethod(ctx, r, connection) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		w.Write([]byte("")) //nolint:errcheck
		writeLog(r, http.StatusMultiStatus, nil)
		return
	}

	handler := webdav.Handler{
		Prefix:     s.binding.Prefix,
		FileSystem: connection,
		LockSystem: lockSystem,
		Logger:     writeLog,
	}
	handler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *webDavServer) getCredentialsAndLoginMethod(r *http.Request) (string, string, string, *x509.Certificate, bool) {
	var tlsCert *x509.Certificate
	loginMethod := dataprovider.LoginMethodPassword
	username, password, ok := r.BasicAuth()
	if s.binding.isMutualTLSEnabled() && r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			tlsCert = r.TLS.PeerCertificates[0]
			if ok {
				loginMethod = dataprovider.LoginMethodTLSCertificateAndPwd
			} else {
				loginMethod = dataprovider.LoginMethodTLSCertificate
				username = tlsCert.Subject.CommonName
				password = ""
			}
			ok = true
		}
	}
	return username, password, loginMethod, tlsCert, ok
}

func (s *webDavServer) authenticate(r *http.Request, ip string) (dataprovider.User, bool, webdav.LockSystem, string, error) {
	var user dataprovider.User
	var err error
	username, password, loginMethod, tlsCert, ok := s.getCredentialsAndLoginMethod(r)
	if !ok {
		user.Username = username
		return user, false, nil, loginMethod, common.ErrNoCredentials
	}
	cachedUser, ok := dataprovider.GetCachedWebDAVUser(username)
	if ok {
		if cachedUser.IsExpired() {
			dataprovider.RemoveCachedWebDAVUser(username)
		} else {
			if !cachedUser.User.IsTLSVerificationEnabled() {
				// for backward compatibility with 2.0.x we only check the password
				tlsCert = nil
				loginMethod = dataprovider.LoginMethodPassword
			}
			cu, u, err := dataprovider.CheckCachedUserCredentials(cachedUser, password, ip, loginMethod, common.ProtocolWebDAV, tlsCert)
			if err == nil {
				if cu != nil {
					return cu.User, true, cu.LockSystem, loginMethod, nil
				}
				lockSystem := webdav.NewMemLS()
				cachedUser = &dataprovider.CachedUser{
					User:       *u,
					Password:   password,
					LockSystem: lockSystem,
					Expiration: s.config.Cache.Users.getExpirationTime(),
				}
				dataprovider.CacheWebDAVUser(cachedUser)
				return cachedUser.User, false, cachedUser.LockSystem, loginMethod, nil
			}
			updateLoginMetrics(&cachedUser.User, ip, loginMethod, dataprovider.ErrInvalidCredentials)
			return user, false, nil, loginMethod, dataprovider.ErrInvalidCredentials
		}
	}
	user, loginMethod, err = dataprovider.CheckCompositeCredentials(username, password, ip, loginMethod,
		common.ProtocolWebDAV, tlsCert)
	if err != nil {
		user.Username = username
		updateLoginMetrics(&user, ip, loginMethod, err)
		return user, false, nil, loginMethod, dataprovider.ErrInvalidCredentials
	}
	lockSystem := webdav.NewMemLS()
	cachedUser = &dataprovider.CachedUser{
		User:       user,
		Password:   password,
		LockSystem: lockSystem,
		Expiration: s.config.Cache.Users.getExpirationTime(),
	}
	dataprovider.CacheWebDAVUser(cachedUser)
	return user, false, lockSystem, loginMethod, nil
}

func (s *webDavServer) validateUser(user *dataprovider.User, r *http.Request, loginMethod string) (string, error) {
	connID := xid.New().String()
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolWebDAV, connID)

	if !filepath.IsAbs(user.HomeDir) {
		logger.Warn(logSender, connectionID, "user %q has an invalid home dir: %q. Home dir must be an absolute path, login not allowed",
			user.Username, user.HomeDir)
		return connID, fmt.Errorf("cannot login user with invalid home dir: %q", user.HomeDir)
	}
	if util.Contains(user.Filters.DeniedProtocols, common.ProtocolWebDAV) {
		logger.Info(logSender, connectionID, "cannot login user %q, protocol DAV is not allowed", user.Username)
		return connID, fmt.Errorf("protocol DAV is not allowed for user %q", user.Username)
	}
	if !user.IsLoginMethodAllowed(loginMethod, common.ProtocolWebDAV) {
		logger.Info(logSender, connectionID, "cannot login user %q, %v login method is not allowed",
			user.Username, loginMethod)
		return connID, fmt.Errorf("login method %v is not allowed for user %q", loginMethod, user.Username)
	}
	if !user.IsLoginFromAddrAllowed(r.RemoteAddr) {
		logger.Info(logSender, connectionID, "cannot login user %q, remote address is not allowed: %v",
			user.Username, r.RemoteAddr)
		return connID, fmt.Errorf("login for user %q is not allowed from this address: %v", user.Username, r.RemoteAddr)
	}
	return connID, nil
}

func (s *webDavServer) checkRemoteAddress(r *http.Request) string {
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	var ip net.IP
	isUnixSocket := filepath.IsAbs(s.binding.Address)
	if !isUnixSocket {
		ip = net.ParseIP(ipAddr)
	}
	if isUnixSocket || ip != nil {
		for _, allow := range s.binding.allowHeadersFrom {
			if allow(ip) {
				parsedIP := util.GetRealIP(r, s.binding.ClientIPProxyHeader, s.binding.ClientIPHeaderDepth)
				if parsedIP != "" {
					ipAddr = parsedIP
					r.RemoteAddr = ipAddr
				}
				break
			}
		}
	}
	return ipAddr
}

func writeLog(r *http.Request, status int, err error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fields := map[string]any{
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
	if depth := r.Header.Get("Depth"); depth != "" {
		fields["depth"] = depth
	}
	if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		fields["content_length"] = contentLength
	}
	if timeout := r.Header.Get("Timeout"); timeout != "" {
		fields["timeout"] = timeout
	}
	if status != 0 {
		fields["resp_status"] = status
	}
	logger.GetLogger().Info().
		Timestamp().
		Str("sender", logSender).
		Fields(fields).
		Err(err).
		Send()
}

func updateLoginMetrics(user *dataprovider.User, ip, loginMethod string, err error) {
	metric.AddLoginAttempt(loginMethod)
	if err != nil && err != common.ErrInternalFailure && err != common.ErrNoCredentials {
		logger.ConnectionFailedLog(user.Username, ip, loginMethod, common.ProtocolWebDAV, err.Error())
		event := common.HostEventLoginFailed
		logEv := notifier.LogEventTypeLoginFailed
		if errors.Is(err, util.ErrNotFound) {
			event = common.HostEventUserNotFound
			logEv = notifier.LogEventTypeLoginNoUser
		}
		common.AddDefenderEvent(ip, common.ProtocolWebDAV, event)
		plugin.Handler.NotifyLogEvent(logEv, common.ProtocolWebDAV, user.Username, ip, "", err)
	}
	metric.AddLoginResult(loginMethod, err)
	dataprovider.ExecutePostLoginHook(user, loginMethod, ip, common.ProtocolWebDAV, err)
}
