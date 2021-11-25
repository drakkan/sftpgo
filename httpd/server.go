package httpd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/rs/cors"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sdk"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/version"
)

var (
	compressor      = middleware.NewCompressor(5)
	xForwardedProto = http.CanonicalHeaderKey("X-Forwarded-Proto")
)

type httpdServer struct {
	binding           Binding
	staticFilesPath   string
	openAPIPath       string
	enableWebAdmin    bool
	enableWebClient   bool
	renderOpenAPI     bool
	router            *chi.Mux
	tokenAuth         *jwtauth.JWTAuth
	signingPassphrase string
	cors              CorsConfig
}

func newHttpdServer(b Binding, staticFilesPath, signingPassphrase string, cors CorsConfig,
	openAPIPath string,
) *httpdServer {
	if openAPIPath == "" {
		b.RenderOpenAPI = false
	}
	return &httpdServer{
		binding:           b,
		staticFilesPath:   staticFilesPath,
		openAPIPath:       openAPIPath,
		enableWebAdmin:    b.EnableWebAdmin,
		enableWebClient:   b.EnableWebClient,
		renderOpenAPI:     b.RenderOpenAPI,
		signingPassphrase: signingPassphrase,
		cors:              cors,
	}
}

func (s *httpdServer) listenAndServe() error {
	s.initializeRouter()
	httpServer := &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
		ErrorLog:          log.New(&logger.StdLoggerWrapper{Sender: logSender}, "", 0),
	}
	if certMgr != nil && s.binding.EnableHTTPS {
		config := &tls.Config{
			GetCertificate:           certMgr.GetCertificateFunc(),
			MinVersion:               tls.VersionTLS12,
			CipherSuites:             util.GetTLSCiphersFromNames(s.binding.TLSCipherSuites),
			PreferServerCipherSuites: true,
		}
		logger.Debug(logSender, "", "configured TLS cipher suites for binding %#v: %v", s.binding.GetAddress(),
			config.CipherSuites)
		httpServer.TLSConfig = config
		if s.binding.ClientAuthType == 1 {
			httpServer.TLSConfig.ClientCAs = certMgr.GetRootCAs()
			httpServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			httpServer.TLSConfig.VerifyConnection = s.verifyTLSConnection
		}
		return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, true, logSender)
	}
	return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, false, logSender)
}

func (s *httpdServer) verifyTLSConnection(state tls.ConnectionState) error {
	if certMgr != nil {
		var clientCrt *x509.Certificate
		var clientCrtName string
		if len(state.PeerCertificates) > 0 {
			clientCrt = state.PeerCertificates[0]
			clientCrtName = clientCrt.Subject.String()
		}
		if len(state.VerifiedChains) == 0 {
			logger.Warn(logSender, "", "TLS connection cannot be verified: unable to get verification chain")
			return errors.New("TLS connection cannot be verified: unable to get verification chain")
		}
		for _, verifiedChain := range state.VerifiedChains {
			var caCrt *x509.Certificate
			if len(verifiedChain) > 0 {
				caCrt = verifiedChain[len(verifiedChain)-1]
			}
			if certMgr.IsRevoked(clientCrt, caCrt) {
				logger.Debug(logSender, "", "tls handshake error, client certificate %#v has been revoked", clientCrtName)
				return common.ErrCrtRevoked
			}
		}
	}

	return nil
}

func (s *httpdServer) refreshCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.checkCookieExpiration(w, r)
		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) renderClientLoginPage(w http.ResponseWriter, error string) {
	data := loginPage{
		CurrentURL: webClientLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
	}
	if s.binding.showAdminLoginURL() {
		data.AltLoginURL = webLoginPath
	}
	if smtp.IsEnabled() {
		data.ForgotPwdURL = webClientForgotPwdPath
	}
	renderClientTemplate(w, templateClientLogin, data)
}

func (s *httpdServer) handleClientWebLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	s.renderClientLoginPage(w, "")
}

func (s *httpdServer) handleWebClientLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	if err := r.ParseForm(); err != nil {
		s.renderClientLoginPage(w, err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}}, ipAddr, common.ErrNoCredentials)
		s.renderClientLoginPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}}, ipAddr, err)
		s.renderClientLoginPage(w, err.Error())
		return
	}

	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolHTTP); err != nil {
		s.renderClientLoginPage(w, fmt.Sprintf("access denied by post connect hook: %v", err))
		return
	}

	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, common.ProtocolHTTP)
	if err != nil {
		updateLoginMetrics(&user, ipAddr, err)
		s.renderClientLoginPage(w, dataprovider.ErrInvalidCredentials.Error())
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		updateLoginMetrics(&user, ipAddr, err)
		s.renderClientLoginPage(w, err.Error())
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, ipAddr, common.ErrInternalFailure)
		s.renderClientLoginPage(w, err.Error())
		return
	}
	s.loginUser(w, r, &user, connectionID, ipAddr, false, s.renderClientLoginPage)
}

func (s *httpdServer) handleWebClientPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	err := r.ParseForm()
	if err != nil {
		renderClientResetPwdPage(w, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientForbiddenPage(w, r, err.Error())
		return
	}
	_, user, err := handleResetPassword(r, r.Form.Get("code"), r.Form.Get("password"), false)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			renderClientResetPwdPage(w, e.GetErrorString())
			return
		}
		renderClientResetPwdPage(w, err.Error())
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	if err := checkHTTPClientUser(user, r, connectionID); err != nil {
		renderClientResetPwdPage(w, fmt.Sprintf("Password reset successfully but unable to login: %v", err.Error()))
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		renderClientResetPwdPage(w, fmt.Sprintf("Password reset successfully but unable to login: %v", err.Error()))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	s.loginUser(w, r, user, connectionID, ipAddr, false, renderClientResetPwdPage)
}

func (s *httpdServer) handleWebClientTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		renderNotFoundPage(w, r, nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderClientTwoFactorRecoveryPage(w, err.Error())
		return
	}
	username := claims.Username
	recoveryCode := r.Form.Get("recovery_code")
	if username == "" || recoveryCode == "" {
		renderClientTwoFactorRecoveryPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientTwoFactorRecoveryPage(w, err.Error())
		return
	}
	user, err := dataprovider.UserExists(username)
	if err != nil {
		renderClientTwoFactorRecoveryPage(w, "Invalid credentials")
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		renderClientTwoFactorPage(w, "Two factory authentication is not enabled")
		return
	}
	for idx, code := range user.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			renderClientInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				renderClientTwoFactorRecoveryPage(w, "This recovery code was already used")
				return
			}
			user.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %#v as used: %v", recoveryCode, err)
				renderClientInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
			s.loginUser(w, r, &user, connectionID, util.GetIPFromRemoteAddress(r.RemoteAddr), true,
				renderClientTwoFactorRecoveryPage)
			return
		}
	}
	renderClientTwoFactorRecoveryPage(w, "Invalid recovery code")
}

func (s *httpdServer) handleWebClientTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		renderNotFoundPage(w, r, nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderClientTwoFactorPage(w, err.Error())
		return
	}
	username := claims.Username
	passcode := r.Form.Get("passcode")
	if username == "" || passcode == "" {
		renderClientTwoFactorPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderClientTwoFactorPage(w, err.Error())
		return
	}
	user, err := dataprovider.UserExists(username)
	if err != nil {
		renderClientTwoFactorPage(w, "Invalid credentials")
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		renderClientTwoFactorPage(w, "Two factory authentication is not enabled")
		return
	}
	err = user.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		renderClientInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		renderClientTwoFactorPage(w, "Invalid authentication code")
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	s.loginUser(w, r, &user, connectionID, util.GetIPFromRemoteAddress(r.RemoteAddr), true, renderClientTwoFactorPage)
}

func (s *httpdServer) handleWebAdminTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		renderNotFoundPage(w, r, nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderTwoFactorRecoveryPage(w, err.Error())
		return
	}
	username := claims.Username
	recoveryCode := r.Form.Get("recovery_code")
	if username == "" || recoveryCode == "" {
		renderTwoFactorRecoveryPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderTwoFactorRecoveryPage(w, err.Error())
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		renderTwoFactorRecoveryPage(w, "Invalid credentials")
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		renderTwoFactorRecoveryPage(w, "Two factory authentication is not enabled")
		return
	}
	for idx, code := range admin.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			renderInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				renderTwoFactorRecoveryPage(w, "This recovery code was already used")
				return
			}
			admin.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %#v as used: %v", recoveryCode, err)
				renderInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			s.loginAdmin(w, r, &admin, true, renderTwoFactorRecoveryPage)
			return
		}
	}
	renderTwoFactorRecoveryPage(w, "Invalid recovery code")
}

func (s *httpdServer) handleWebAdminTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		renderNotFoundPage(w, r, nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderTwoFactorPage(w, err.Error())
		return
	}
	username := claims.Username
	passcode := r.Form.Get("passcode")
	if username == "" || passcode == "" {
		renderTwoFactorPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderTwoFactorPage(w, err.Error())
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		renderTwoFactorPage(w, "Invalid credentials")
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		renderTwoFactorPage(w, "Two factory authentication is not enabled")
		return
	}
	err = admin.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		renderInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(admin.Filters.TOTPConfig.ConfigName, passcode,
		admin.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		renderTwoFactorPage(w, "Invalid authentication code")
		return
	}
	s.loginAdmin(w, r, &admin, true, renderTwoFactorPage)
}

func (s *httpdServer) handleWebAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if err := r.ParseForm(); err != nil {
		s.renderAdminLoginPage(w, err.Error())
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		s.renderAdminLoginPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		s.renderAdminLoginPage(w, err.Error())
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		s.renderAdminLoginPage(w, err.Error())
		return
	}
	s.loginAdmin(w, r, &admin, false, s.renderAdminLoginPage)
}

func (s *httpdServer) renderAdminLoginPage(w http.ResponseWriter, error string) {
	data := loginPage{
		CurrentURL: webLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(),
		StaticURL:  webStaticFilesPath,
	}
	if s.binding.showClientLoginURL() {
		data.AltLoginURL = webClientLoginPath
	}
	if smtp.IsEnabled() {
		data.ForgotPwdURL = webAdminForgotPwdPath
	}
	renderAdminTemplate(w, templateLogin, data)
}

func (s *httpdServer) handleWebAdminLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	s.renderAdminLoginPage(w, "")
}

func (s *httpdServer) handleWebAdminPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	err := r.ParseForm()
	if err != nil {
		renderResetPwdPage(w, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	admin, _, err := handleResetPassword(r, r.Form.Get("code"), r.Form.Get("password"), true)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			renderResetPwdPage(w, e.GetErrorString())
			return
		}
		renderResetPwdPage(w, err.Error())
		return
	}

	s.loginAdmin(w, r, admin, false, renderResetPwdPage)
}

func (s *httpdServer) handleWebAdminSetupPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if dataprovider.HasAdmin() {
		renderBadRequestPage(w, r, errors.New("an admin user already exists"))
		return
	}
	err := r.ParseForm()
	if err != nil {
		renderAdminSetupPage(w, r, "", err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderForbiddenPage(w, r, err.Error())
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	confirmPassword := r.Form.Get("confirm_password")
	if username == "" {
		renderAdminSetupPage(w, r, username, "Please set a username")
		return
	}
	if password == "" {
		renderAdminSetupPage(w, r, username, "Please set a password")
		return
	}
	if password != confirmPassword {
		renderAdminSetupPage(w, r, username, "Passwords mismatch")
		return
	}
	admin := dataprovider.Admin{
		Username:    username,
		Password:    password,
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
	}
	err = dataprovider.AddAdmin(&admin, username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		renderAdminSetupPage(w, r, username, err.Error())
		return
	}
	s.loginAdmin(w, r, &admin, false, nil)
}

func (s *httpdServer) loginUser(
	w http.ResponseWriter, r *http.Request, user *dataprovider.User, connectionID, ipAddr string,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, error string),
) {
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: user.Filters.WebClient,
		Signature:   user.GetSignature(),
	}

	audience := tokenAudienceWebClient
	if user.Filters.TOTPConfig.Enabled && util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) &&
		user.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebClientPartial
	}

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to set user login cookie %v", err)
		updateLoginMetrics(user, ipAddr, common.ErrInternalFailure)
		errorFunc(w, err.Error())
		return
	}
	if isSecondFactorAuth {
		invalidateToken(r)
	}
	if audience == tokenAudienceWebClientPartial {
		http.Redirect(w, r, webClientTwoFactorPath, http.StatusFound)
		return
	}
	updateLoginMetrics(user, ipAddr, err)
	dataprovider.UpdateLastLogin(user)
	http.Redirect(w, r, webClientFilesPath, http.StatusFound)
}

func (s *httpdServer) loginAdmin(
	w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, error string),
) {
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}

	audience := tokenAudienceWebAdmin
	if admin.Filters.TOTPConfig.Enabled && admin.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebAdminPartial
	}

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience)
	if err != nil {
		logger.Warn(logSender, "", "unable to set admin login cookie %v", err)
		if errorFunc == nil {
			renderAdminSetupPage(w, r, admin.Username, err.Error())
			return
		}
		errorFunc(w, err.Error())
		return
	}
	if isSecondFactorAuth {
		invalidateToken(r)
	}
	if audience == tokenAudienceWebAdminPartial {
		http.Redirect(w, r, webAdminTwoFactorPath, http.StatusFound)
		return
	}
	dataprovider.UpdateAdminLastLogin(admin)
	http.Redirect(w, r, webUsersPath, http.StatusFound)
}

func (s *httpdServer) logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	invalidateToken(r)
	sendAPIResponse(w, r, nil, "Your token has been invalidated", http.StatusOK)
}

func (s *httpdServer) getUserToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	username, password, ok := r.BasicAuth()
	if !ok {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}}, ipAddr, common.ErrNoCredentials)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}}, ipAddr, common.ErrNoCredentials)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolHTTP); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, common.ProtocolHTTP)
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		updateLoginMetrics(&user, ipAddr, err)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		updateLoginMetrics(&user, ipAddr, err)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if user.Filters.TOTPConfig.Enabled && util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for user %#v and not passcode provided, authentication refused", user.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
		err = user.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			updateLoginMetrics(&user, ipAddr, common.ErrInternalFailure)
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err), http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
			user.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for user %#v, match? %v, err: %v", user.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, ipAddr, common.ErrInternalFailure)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.generateAndSendUserToken(w, r, ipAddr, user)
}

func (s *httpdServer) generateAndSendUserToken(w http.ResponseWriter, r *http.Request, ipAddr string, user dataprovider.User) {
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: user.Filters.WebClient,
		Signature:   user.GetSignature(),
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPIUser)

	if err != nil {
		updateLoginMetrics(&user, ipAddr, common.ErrInternalFailure)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	updateLoginMetrics(&user, ipAddr, err)
	dataprovider.UpdateLastLogin(&user)

	render.JSON(w, r, resp)
}

func (s *httpdServer) getToken(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if admin.Filters.TOTPConfig.Enabled {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for admin %#v and not passcode provided, authentication refused", admin.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		err = admin.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err),
				http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(admin.Filters.TOTPConfig.ConfigName, passcode,
			admin.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for admin %#v, match? %v, err: %v", admin.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	s.generateAndSendToken(w, r, admin)
}

func (s *httpdServer) generateAndSendToken(w http.ResponseWriter, r *http.Request, admin dataprovider.Admin) {
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPI)

	if err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dataprovider.UpdateAdminLastLogin(&admin)
	render.JSON(w, r, resp)
}

func (s *httpdServer) checkCookieExpiration(w http.ResponseWriter, r *http.Request) {
	token, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		return
	}
	tokenClaims := jwtTokenClaims{}
	tokenClaims.Decode(claims)
	if tokenClaims.Username == "" || tokenClaims.Signature == "" {
		return
	}
	if time.Until(token.Expiration()) > tokenRefreshThreshold {
		return
	}
	if util.IsStringInSlice(tokenAudienceWebClient, token.Audience()) {
		s.refreshClientToken(w, r, tokenClaims)
	} else {
		s.refreshAdminToken(w, r, tokenClaims)
	}
}

func (s *httpdServer) refreshClientToken(w http.ResponseWriter, r *http.Request, tokenClaims jwtTokenClaims) {
	user, err := dataprovider.UserExists(tokenClaims.Username)
	if err != nil {
		return
	}
	if user.GetSignature() != tokenClaims.Signature {
		logger.Debug(logSender, "", "signature mismatch for user %#v, unable to refresh cookie", user.Username)
		return
	}
	if err := checkHTTPClientUser(&user, r, xid.New().String()); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for user %#v: %v", user.Username, err)
		return
	}

	tokenClaims.Permissions = user.Filters.WebClient
	logger.Debug(logSender, "", "cookie refreshed for user %#v", user.Username)
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebClient) //nolint:errcheck
}

func (s *httpdServer) refreshAdminToken(w http.ResponseWriter, r *http.Request, tokenClaims jwtTokenClaims) {
	admin, err := dataprovider.AdminExists(tokenClaims.Username)
	if err != nil {
		return
	}
	if admin.Status != 1 {
		logger.Debug(logSender, "", "admin %#v is disabled, unable to refresh cookie", admin.Username)
		return
	}
	if admin.GetSignature() != tokenClaims.Signature {
		logger.Debug(logSender, "", "signature mismatch for admin %#v, unable to refresh cookie", admin.Username)
		return
	}
	if !admin.CanLoginFromIP(util.GetIPFromRemoteAddress(r.RemoteAddr)) {
		logger.Debug(logSender, "", "admin %#v cannot login from %v, unable to refresh cookie", admin.Username, r.RemoteAddr)
		return
	}
	tokenClaims.Permissions = admin.Permissions
	logger.Debug(logSender, "", "cookie refreshed for admin %#v", admin.Username)
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebAdmin) //nolint:errcheck
}

func (s *httpdServer) updateContextFromCookie(r *http.Request) *http.Request {
	token, _, err := jwtauth.FromContext(r.Context())
	if token == nil || err != nil {
		_, err = r.Cookie("jwt")
		if err != nil {
			return r
		}
		token, err = jwtauth.VerifyRequest(s.tokenAuth, r, jwtauth.TokenFromCookie)
		ctx := jwtauth.NewContext(r.Context(), token, err)
		return r.WithContext(ctx)
	}
	return r
}

func (s *httpdServer) checkConnection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		ip := net.ParseIP(ipAddr)
		if ip != nil {
			for _, allow := range s.binding.allowHeadersFrom {
				if allow(ip) {
					parsedIP := util.GetRealIP(r)
					if parsedIP != "" {
						ipAddr = parsedIP
						r.RemoteAddr = ipAddr
					}
					if forwardedProto := r.Header.Get(xForwardedProto); forwardedProto != "" {
						ctx := context.WithValue(r.Context(), forwardedProtoKey, forwardedProto)
						r = r.WithContext(ctx)
					}
					break
				}
			}
		}

		common.Connections.AddClientConnection(ipAddr)
		defer common.Connections.RemoveClientConnection(ipAddr)

		if !common.Connections.IsNewConnectionAllowed(ipAddr) {
			logger.Log(logger.LevelDebug, common.ProtocolHTTP, "", "connection refused, configured limit reached")
			s.sendForbiddenResponse(w, r, "configured connections limit reached")
			return
		}
		if common.IsBanned(ipAddr) {
			s.sendForbiddenResponse(w, r, "your IP address is banned")
			return
		}
		if delay, err := common.LimitRate(common.ProtocolHTTP, ipAddr); err != nil {
			delay += 499999999 * time.Nanosecond
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
			w.Header().Set("X-Retry-In", delay.String())
			s.sendTooManyRequestResponse(w, r, err)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) sendTooManyRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			renderClientMessagePage(w, r, http.StatusText(http.StatusTooManyRequests), "Rate limit exceeded",
				http.StatusTooManyRequests, err, "")
			return
		}
		renderMessagePage(w, r, http.StatusText(http.StatusTooManyRequests), "Rate limit exceeded", http.StatusTooManyRequests,
			err, "")
		return
	}
	sendAPIResponse(w, r, err, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (s *httpdServer) sendForbiddenResponse(w http.ResponseWriter, r *http.Request, message string) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			renderClientForbiddenPage(w, r, message)
			return
		}
		renderForbiddenPage(w, r, message)
		return
	}
	sendAPIResponse(w, r, errors.New(message), message, http.StatusForbidden)
}

func (s *httpdServer) redirectToWebPath(w http.ResponseWriter, r *http.Request, webPath string) {
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webPath, http.StatusMovedPermanently)
		return
	}
	if s.enableWebAdmin {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
	}
}

func (s *httpdServer) isStaticFileURL(r *http.Request) bool {
	var urlPath string
	rctx := chi.RouteContext(r.Context())
	if rctx != nil && rctx.RoutePath != "" {
		urlPath = rctx.RoutePath
	} else {
		urlPath = r.URL.Path
	}
	return !strings.HasPrefix(urlPath, webOpenAPIPath) && !strings.HasPrefix(urlPath, webStaticFilesPath)
}

func (s *httpdServer) initializeRouter() {
	s.tokenAuth = jwtauth.New(jwa.HS256.String(), getSigningKey(s.signingPassphrase), nil)
	s.router = chi.NewRouter()

	s.router.Use(middleware.RequestID)
	s.router.Use(s.checkConnection)
	s.router.Use(logger.NewStructuredLogger(logger.GetLogger()))
	s.router.Use(recoverer)
	if s.cors.Enabled {
		c := cors.New(cors.Options{
			AllowedOrigins:   s.cors.AllowedOrigins,
			AllowedMethods:   s.cors.AllowedMethods,
			AllowedHeaders:   s.cors.AllowedHeaders,
			ExposedHeaders:   s.cors.ExposedHeaders,
			MaxAge:           s.cors.MaxAge,
			AllowCredentials: s.cors.AllowCredentials,
		})
		s.router.Use(c.Handler)
	}
	s.router.Use(middleware.GetHead)
	// StripSlashes causes infinite redirects at the root path if used with http.FileServer
	s.router.Use(middleware.Maybe(middleware.StripSlashes, s.isStaticFileURL))

	s.router.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
			r = s.updateContextFromCookie(r)
			if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
				renderClientNotFoundPage(w, r, nil)
				return
			}
			renderNotFoundPage(w, r, nil)
			return
		}
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}))

	s.router.Get(healthzPath, func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "ok")
	})

	// share API exposed to external users
	s.router.Get(sharesPath+"/{id}", downloadFromShare)
	s.router.Post(sharesPath+"/{id}", uploadToShare)

	s.router.Get(tokenPath, s.getToken)
	s.router.Post(adminPath+"/{username}/forgot-password", forgotAdminPassword)
	s.router.Post(adminPath+"/{username}/reset-password", resetAdminPassword)
	s.router.Post(userPath+"/{username}/forgot-password", forgotUserPassword)
	s.router.Post(userPath+"/{username}/reset-password", resetUserPassword)

	s.router.Group(func(router chi.Router) {
		router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeAdmin))
		router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
		router.Use(jwtAuthenticatorAPI)

		router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
			render.JSON(w, r, version.Get())
		})

		router.With(forbidAPIKeyAuthentication).Get(logoutPath, s.logout)
		router.With(forbidAPIKeyAuthentication).Get(adminProfilePath, getAdminProfile)
		router.With(forbidAPIKeyAuthentication).Put(adminProfilePath, updateAdminProfile)
		router.With(forbidAPIKeyAuthentication).Put(adminPwdPath, changeAdminPassword)
		// compatibility layer to remove in v2.2
		router.With(forbidAPIKeyAuthentication).Put(adminPwdCompatPath, changeAdminPassword)
		// admin TOTP APIs
		router.With(forbidAPIKeyAuthentication).Get(adminTOTPConfigsPath, getTOTPConfigs)
		router.With(forbidAPIKeyAuthentication).Post(adminTOTPGeneratePath, generateTOTPSecret)
		router.With(forbidAPIKeyAuthentication).Post(adminTOTPValidatePath, validateTOTPPasscode)
		router.With(forbidAPIKeyAuthentication).Post(adminTOTPSavePath, saveTOTPConfig)
		router.With(forbidAPIKeyAuthentication).Get(admin2FARecoveryCodesPath, getRecoveryCodes)
		router.With(forbidAPIKeyAuthentication).Post(admin2FARecoveryCodesPath, generateRecoveryCodes)

		router.With(checkPerm(dataprovider.PermAdminViewServerStatus)).
			Get(serverStatusPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, getServicesStatus())
			})

		router.With(checkPerm(dataprovider.PermAdminViewConnections)).
			Get(activeConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, common.Connections.GetStats())
			})

		router.With(checkPerm(dataprovider.PermAdminCloseConnections)).
			Delete(activeConnectionsPath+"/{connectionID}", handleCloseConnection)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanPath, getUsersQuotaScans)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/users/scans", getUsersQuotaScans)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanPath, startUserQuotaScanCompat)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/users/{username}/scan", startUserQuotaScan)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanVFolderPath, getFoldersQuotaScans)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/folders/scans", getFoldersQuotaScans)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanVFolderPath, startFolderQuotaScanCompat)
		router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/folders/{name}/scan", startFolderQuotaScan)
		router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath, getUsers)
		router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(userPath, addUser)
		router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath+"/{username}", getUserByUsername)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}", updateUser)
		router.With(checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(userPath+"/{username}", deleteUser)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}/2fa/disable", disableUser2FA)
		router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath, getFolders)
		router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath+"/{name}", getFolderByName)
		router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(folderPath, addFolder)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(folderPath+"/{name}", updateFolder)
		router.With(checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(folderPath+"/{name}", deleteFolder)
		router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(dumpDataPath, dumpData)
		router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(loadDataPath, loadData)
		router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(loadDataPath, loadDataFromRequest)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateUsedQuotaPath, updateUserQuotaUsageCompat)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/usage", updateUserQuotaUsage)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateFolderUsedQuotaPath, updateFolderQuotaUsageCompat)
		router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/folders/{name}/usage", updateFolderQuotaUsage)
		router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderHosts, getDefenderHosts)
		router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderHosts+"/{id}", getDefenderHostByID)
		router.With(checkPerm(dataprovider.PermAdminManageDefender)).Delete(defenderHosts+"/{id}", deleteDefenderHostByID)
		router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderBanTime, getBanTime)
		router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderScore, getScore)
		router.With(checkPerm(dataprovider.PermAdminManageDefender)).Post(defenderUnban, unban)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath, getAdmins)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Post(adminPath, addAdmin)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath+"/{username}", getAdminByUsername)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Put(adminPath+"/{username}", updateAdmin)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Delete(adminPath+"/{username}", deleteAdmin)
		router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Put(adminPath+"/{username}/2fa/disable", disableAdmin2FA)
		router.With(checkPerm(dataprovider.PermAdminRetentionChecks)).Get(retentionChecksPath, getRetentionChecks)
		router.With(checkPerm(dataprovider.PermAdminRetentionChecks)).Post(retentionBasePath+"/{username}/check",
			startRetentionCheck)
		router.With(checkPerm(dataprovider.PermAdminViewEvents), compressor.Handler).
			Get(fsEventsPath, searchFsEvents)
		router.With(checkPerm(dataprovider.PermAdminViewEvents), compressor.Handler).
			Get(providerEventsPath, searchProviderEvents)
		router.With(forbidAPIKeyAuthentication, checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Get(apiKeysPath, getAPIKeys)
		router.With(forbidAPIKeyAuthentication, checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Post(apiKeysPath, addAPIKey)
		router.With(forbidAPIKeyAuthentication, checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Get(apiKeysPath+"/{id}", getAPIKeyByID)
		router.With(forbidAPIKeyAuthentication, checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Put(apiKeysPath+"/{id}", updateAPIKey)
		router.With(forbidAPIKeyAuthentication, checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Delete(apiKeysPath+"/{id}", deleteAPIKey)
	})

	s.router.Get(userTokenPath, s.getUserToken)

	s.router.Group(func(router chi.Router) {
		router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeUser))
		router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
		router.Use(jwtAuthenticatorAPIUser)

		router.With(forbidAPIKeyAuthentication).Get(userLogoutPath, s.logout)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
			Put(userPwdPath, changeUserPassword)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientPubKeyChangeDisabled)).
			Get(userPublicKeysPath, getUserPublicKeys)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientPubKeyChangeDisabled)).
			Put(userPublicKeysPath, setUserPublicKeys)
		router.With(forbidAPIKeyAuthentication).Get(userProfilePath, getUserProfile)
		router.With(forbidAPIKeyAuthentication).Put(userProfilePath, updateUserProfile)
		// user TOTP APIs
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Get(userTOTPConfigsPath, getTOTPConfigs)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPGeneratePath, generateTOTPSecret)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPValidatePath, validateTOTPPasscode)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPSavePath, saveTOTPConfig)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Get(user2FARecoveryCodesPath, getRecoveryCodes)
		router.With(forbidAPIKeyAuthentication, checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(user2FARecoveryCodesPath, generateRecoveryCodes)

		// compatibility layer to remove in v2.3
		router.With(compressor.Handler).Get(userFolderPath, readUserFolder)
		router.Get(userFilePath, getUserFile)

		router.With(compressor.Handler).Get(userDirsPath, readUserFolder)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Post(userDirsPath, createUserDir)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Patch(userDirsPath, renameUserDir)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Delete(userDirsPath, deleteUserDir)
		router.Get(userFilesPath, getUserFile)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Post(userFilesPath, uploadUserFiles)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Patch(userFilesPath, renameUserFile)
		router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled)).Delete(userFilesPath, deleteUserFile)
		router.Post(userStreamZipPath, getUserFilesAsZipStream)
		router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Get(userSharesPath, getShares)
		router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Post(userSharesPath, addShare)
		router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Get(userSharesPath+"/{id}", getShareByID)
		router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Put(userSharesPath+"/{id}", updateShare)
		router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Delete(userSharesPath+"/{id}", deleteShare)
	})

	if s.renderOpenAPI {
		s.router.Group(func(router chi.Router) {
			router.Use(compressor.Handler)
			fileServer(router, webOpenAPIPath, http.Dir(s.openAPIPath))
		})
	}

	if s.enableWebAdmin || s.enableWebClient {
		s.router.Group(func(router chi.Router) {
			router.Use(compressor.Handler)
			fileServer(router, webStaticFilesPath, http.Dir(s.staticFilesPath))
		})
		if s.enableWebClient {
			s.router.Get(webRootPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webClientLoginPath)
			})
			s.router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webClientLoginPath)
			})
		} else {
			s.router.Get(webRootPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webLoginPath)
			})
			s.router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webLoginPath)
			})
		}
	}

	if s.enableWebClient {
		s.router.Get(webBaseClientPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
			http.Redirect(w, r, webClientLoginPath, http.StatusMovedPermanently)
		})
		s.router.Get(webClientLoginPath, s.handleClientWebLogin)
		s.router.Post(webClientLoginPath, s.handleWebClientLoginPost)
		s.router.Get(webClientForgotPwdPath, handleWebClientForgotPwd)
		s.router.Post(webClientForgotPwdPath, handleWebClientForgotPwdPost)
		s.router.Get(webClientResetPwdPath, handleWebClientPasswordReset)
		s.router.Post(webClientResetPwdPath, s.handleWebClientPasswordResetPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Get(webClientTwoFactorPath, handleWebClientTwoFactor)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Post(webClientTwoFactorPath, s.handleWebClientTwoFactorPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Get(webClientTwoFactorRecoveryPath, handleWebClientTwoFactorRecovery)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Post(webClientTwoFactorRecoveryPath, s.handleWebClientTwoFactorRecoveryPost)
		// share API exposed to external users
		s.router.Get(webClientPubSharesPath+"/{id}", downloadFromShare)
		s.router.Post(webClientPubSharesPath+"/{id}", uploadToShare)

		s.router.Group(func(router chi.Router) {
			router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebClient)

			router.Get(webClientLogoutPath, handleWebClientLogout)
			router.With(s.refreshCookie).Get(webClientFilesPath, handleClientGetFiles)
			router.With(s.refreshCookie).Get(webClientViewPDFPath, handleClientViewPDF)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Post(webClientFilesPath, uploadUserFiles)
			router.With(s.refreshCookie).Get(webClientEditFilePath, handleClientEditFile)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Patch(webClientFilesPath, renameUserFile)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Delete(webClientFilesPath, deleteUserFile)
			router.With(compressor.Handler, s.refreshCookie).Get(webClientDirsPath, handleClientGetDirContents)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Post(webClientDirsPath, createUserDir)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Patch(webClientDirsPath, renameUserDir)
			router.With(checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Delete(webClientDirsPath, deleteUserDir)
			router.With(s.refreshCookie).Get(webClientDownloadZipPath, handleWebClientDownloadZip)
			router.With(s.refreshCookie).Get(webClientProfilePath, handleClientGetProfile)
			router.Post(webClientProfilePath, handleWebClientProfilePost)
			router.With(checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Get(webChangeClientPwdPath, handleWebClientChangePwd)
			router.With(checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Post(webChangeClientPwdPath, handleWebClientChangePwdPost)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath, handleWebClientMFA)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPGeneratePath, generateTOTPSecret)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPValidatePath, validateTOTPPasscode)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPSavePath, saveTOTPConfig)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader, s.refreshCookie).
				Get(webClientRecoveryCodesPath, getRecoveryCodes)
			router.With(checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientRecoveryCodesPath, generateRecoveryCodes)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharesPath, handleClientGetShares)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath, handleClientAddShareGet)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).Post(webClientSharePath,
				handleClientAddSharePost)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath+"/{id}", handleClientUpdateShareGet)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath+"/{id}", handleClientUpdateSharePost)
			router.With(checkHTTPUserPerm(sdk.WebClientSharesDisabled), verifyCSRFHeader).
				Delete(webClientSharePath+"/{id}", deleteShare)
		})
	}

	if s.enableWebAdmin {
		s.router.Get(webBaseAdminPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
			s.redirectToWebPath(w, r, webLoginPath)
		})
		s.router.Get(webLoginPath, s.handleWebAdminLogin)
		s.router.Post(webLoginPath, s.handleWebAdminLoginPost)
		s.router.Get(webAdminSetupPath, handleWebAdminSetupGet)
		s.router.Post(webAdminSetupPath, s.handleWebAdminSetupPost)
		s.router.Get(webAdminForgotPwdPath, handleWebAdminForgotPwd)
		s.router.Post(webAdminForgotPwdPath, handleWebAdminForgotPwdPost)
		s.router.Get(webAdminResetPwdPath, handleWebAdminPasswordReset)
		s.router.Post(webAdminResetPwdPath, s.handleWebAdminPasswordResetPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Get(webAdminTwoFactorPath, handleWebAdminTwoFactor)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Post(webAdminTwoFactorPath, s.handleWebAdminTwoFactorPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Get(webAdminTwoFactorRecoveryPath, handleWebAdminTwoFactorRecovery)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Post(webAdminTwoFactorRecoveryPath, s.handleWebAdminTwoFactorRecoveryPost)

		s.router.Group(func(router chi.Router) {
			router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebAdmin)

			router.Get(webLogoutPath, handleWebLogout)
			router.With(s.refreshCookie).Get(webAdminProfilePath, handleWebAdminProfile)
			router.Post(webAdminProfilePath, handleWebAdminProfilePost)
			router.With(s.refreshCookie).Get(webChangeAdminPwdPath, handleWebAdminChangePwd)
			router.Post(webChangeAdminPwdPath, handleWebAdminChangePwdPost)

			router.With(s.refreshCookie).Get(webAdminMFAPath, handleWebAdminMFA)
			router.With(verifyCSRFHeader).Post(webAdminTOTPGeneratePath, generateTOTPSecret)
			router.With(verifyCSRFHeader).Post(webAdminTOTPValidatePath, validateTOTPPasscode)
			router.With(verifyCSRFHeader).Post(webAdminTOTPSavePath, saveTOTPConfig)
			router.With(verifyCSRFHeader, s.refreshCookie).Get(webAdminRecoveryCodesPath, getRecoveryCodes)
			router.With(verifyCSRFHeader).Post(webAdminRecoveryCodesPath, generateRecoveryCodes)

			router.With(checkPerm(dataprovider.PermAdminViewUsers), s.refreshCookie).
				Get(webUsersPath, handleGetWebUsers)
			router.With(checkPerm(dataprovider.PermAdminAddUsers), s.refreshCookie).
				Get(webUserPath, handleWebAddUserGet)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers), s.refreshCookie).
				Get(webUserPath+"/{username}", handleWebUpdateUserGet)
			router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(webUserPath, handleWebAddUserPost)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Post(webUserPath+"/{username}", handleWebUpdateUserPost)
			router.With(checkPerm(dataprovider.PermAdminViewConnections), s.refreshCookie).
				Get(webConnectionsPath, handleWebGetConnections)
			router.With(checkPerm(dataprovider.PermAdminViewUsers), s.refreshCookie).
				Get(webFoldersPath, handleWebGetFolders)
			router.With(checkPerm(dataprovider.PermAdminAddUsers), s.refreshCookie).
				Get(webFolderPath, handleWebAddFolderGet)
			router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(webFolderPath, handleWebAddFolderPost)
			router.With(checkPerm(dataprovider.PermAdminViewServerStatus), s.refreshCookie).
				Get(webStatusPath, handleWebGetStatus)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminsPath, handleGetWebAdmins)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminPath, handleWebAddAdminGet)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminPath+"/{username}", handleWebUpdateAdminGet)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Post(webAdminPath, handleWebAddAdminPost)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Post(webAdminPath+"/{username}",
				handleWebUpdateAdminPost)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins), verifyCSRFHeader).
				Delete(webAdminPath+"/{username}", deleteAdmin)
			router.With(checkPerm(dataprovider.PermAdminCloseConnections), verifyCSRFHeader).
				Delete(webConnectionsPath+"/{connectionID}", handleCloseConnection)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers), s.refreshCookie).
				Get(webFolderPath+"/{name}", handleWebUpdateFolderGet)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Post(webFolderPath+"/{name}",
				handleWebUpdateFolderPost)
			router.With(checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
				Delete(webFolderPath+"/{name}", deleteFolder)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
				Post(webScanVFolderPath+"/{name}", startFolderQuotaScan)
			router.With(checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
				Delete(webUserPath+"/{username}", deleteUser)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
				Post(webQuotaScanPath+"/{username}", startUserQuotaScan)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(webMaintenancePath, handleWebMaintenance)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(webBackupPath, dumpData)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webRestorePath, handleWebRestore)
			router.With(checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
				Get(webTemplateUser, handleWebTemplateUserGet)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateUser, handleWebTemplateUserPost)
			router.With(checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
				Get(webTemplateFolder, handleWebTemplateFolderGet)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateFolder, handleWebTemplateFolderPost)
			router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(webDefenderPath, handleWebDefenderPage)
			router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(webDefenderHostsPath, getDefenderHosts)
			router.With(checkPerm(dataprovider.PermAdminManageDefender)).Delete(webDefenderHostsPath+"/{id}",
				deleteDefenderHostByID)
		})
	}
}
