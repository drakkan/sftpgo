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
	"github.com/sftpgo/sdk"
	"github.com/unrolled/secure"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
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
			MinVersion:               util.GetTLSVersion(s.binding.MinTLSVersion),
			NextProtos:               []string{"http/1.1", "h2"},
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

func (s *httpdServer) renderClientLoginPage(w http.ResponseWriter, error, ip string) {
	data := loginPage{
		CurrentURL: webClientLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	if s.binding.showAdminLoginURL() {
		data.AltLoginURL = webAdminLoginPath
	}
	if smtp.IsEnabled() {
		data.ForgotPwdURL = webClientForgotPwdPath
	}
	if s.binding.OIDC.isEnabled() {
		data.OpenIDLoginURL = webClientOIDCLoginPath
	}
	renderClientTemplate(w, templateClientLogin, data)
}

func (s *httpdServer) handleWebClientLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	c := jwtTokenClaims{}
	c.removeCookie(w, r, webBaseClientPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebClientChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderClientChangePasswordPage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	err = doChangeUserPassword(r, r.Form.Get("current_password"), r.Form.Get("new_password1"),
		r.Form.Get("new_password2"))
	if err != nil {
		s.renderClientChangePasswordPage(w, r, err.Error())
		return
	}
	s.handleWebClientLogout(w, r)
}

func (s *httpdServer) handleClientWebLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	s.renderClientLoginPage(w, getFlashMessage(w, r), util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebClientLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientLoginPage(w, err.Error(), ipAddr)
		return
	}
	protocol := common.ProtocolHTTP
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials)
		s.renderClientLoginPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err)
		s.renderClientLoginPage(w, err.Error(), ipAddr)
		return
	}

	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		s.renderClientLoginPage(w, fmt.Sprintf("access denied by post connect hook: %v", err), ipAddr)
		return
	}

	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err)
		s.renderClientLoginPage(w, dataprovider.ErrInvalidCredentials.Error(), ipAddr)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err)
		s.renderClientLoginPage(w, err.Error(), ipAddr)
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure)
		s.renderClientLoginPage(w, err.Error(), ipAddr)
		return
	}
	s.loginUser(w, r, &user, connectionID, ipAddr, false, s.renderClientLoginPage)
}

func (s *httpdServer) handleWebClientPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderClientResetPwdPage(w, err.Error(), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientForbiddenPage(w, r, err.Error())
		return
	}
	_, user, err := handleResetPassword(r, r.Form.Get("code"), r.Form.Get("password"), false)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			s.renderClientResetPwdPage(w, e.GetErrorString(), ipAddr)
			return
		}
		s.renderClientResetPwdPage(w, err.Error(), ipAddr)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
	if err := checkHTTPClientUser(user, r, connectionID); err != nil {
		s.renderClientResetPwdPage(w, fmt.Sprintf("Password reset successfully but unable to login: %v", err.Error()), ipAddr)
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		s.renderClientResetPwdPage(w, fmt.Sprintf("Password reset successfully but unable to login: %v", err.Error()), ipAddr)
		return
	}
	s.loginUser(w, r, user, connectionID, ipAddr, false, s.renderClientResetPwdPage)
}

func (s *httpdServer) handleWebClientTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientTwoFactorRecoveryPage(w, err.Error(), ipAddr)
		return
	}
	username := claims.Username
	recoveryCode := r.Form.Get("recovery_code")
	if username == "" || recoveryCode == "" {
		s.renderClientTwoFactorRecoveryPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientTwoFactorRecoveryPage(w, err.Error(), ipAddr)
		return
	}
	user, err := dataprovider.UserExists(username)
	if err != nil {
		s.renderClientTwoFactorRecoveryPage(w, "Invalid credentials", ipAddr)
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		s.renderClientTwoFactorPage(w, "Two factory authentication is not enabled", ipAddr)
		return
	}
	for idx, code := range user.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderClientInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderClientTwoFactorRecoveryPage(w, "This recovery code was already used", ipAddr)
				return
			}
			user.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %#v as used: %v", recoveryCode, err)
				s.renderClientInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
			s.loginUser(w, r, &user, connectionID, ipAddr, true,
				s.renderClientTwoFactorRecoveryPage)
			return
		}
	}
	s.renderClientTwoFactorRecoveryPage(w, "Invalid recovery code", ipAddr)
}

func (s *httpdServer) handleWebClientTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientTwoFactorPage(w, err.Error(), ipAddr)
		return
	}
	username := claims.Username
	passcode := r.Form.Get("passcode")
	if username == "" || passcode == "" {
		s.renderClientTwoFactorPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderClientTwoFactorPage(w, err.Error(), ipAddr)
		return
	}
	user, err := dataprovider.UserExists(username)
	if err != nil {
		s.renderClientTwoFactorPage(w, "Invalid credentials", ipAddr)
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		s.renderClientTwoFactorPage(w, "Two factory authentication is not enabled", ipAddr)
		return
	}
	err = user.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		s.renderClientTwoFactorPage(w, "Invalid authentication code", ipAddr)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
	s.loginUser(w, r, &user, connectionID, ipAddr, true, s.renderClientTwoFactorPage)
}

func (s *httpdServer) handleWebAdminTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	claims, err := getTokenClaims(r)
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderTwoFactorRecoveryPage(w, err.Error(), ipAddr)
		return
	}
	username := claims.Username
	recoveryCode := r.Form.Get("recovery_code")
	if username == "" || recoveryCode == "" {
		s.renderTwoFactorRecoveryPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderTwoFactorRecoveryPage(w, err.Error(), ipAddr)
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		s.renderTwoFactorRecoveryPage(w, "Invalid credentials", ipAddr)
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorRecoveryPage(w, "Two factory authentication is not enabled", ipAddr)
		return
	}
	for idx, code := range admin.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderTwoFactorRecoveryPage(w, "This recovery code was already used", ipAddr)
				return
			}
			admin.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %#v as used: %v", recoveryCode, err)
				s.renderInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			s.loginAdmin(w, r, &admin, true, s.renderTwoFactorRecoveryPage, ipAddr)
			return
		}
	}
	s.renderTwoFactorRecoveryPage(w, "Invalid recovery code", ipAddr)
}

func (s *httpdServer) handleWebAdminTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := getTokenClaims(r)
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderTwoFactorPage(w, err.Error(), ipAddr)
		return
	}
	username := claims.Username
	passcode := r.Form.Get("passcode")
	if username == "" || passcode == "" {
		s.renderTwoFactorPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderTwoFactorPage(w, err.Error(), ipAddr)
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		s.renderTwoFactorPage(w, "Invalid credentials", ipAddr)
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorPage(w, "Two factory authentication is not enabled", ipAddr)
		return
	}
	err = admin.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(admin.Filters.TOTPConfig.ConfigName, passcode,
		admin.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		s.renderTwoFactorPage(w, "Invalid authentication code", ipAddr)
		return
	}
	s.loginAdmin(w, r, &admin, true, s.renderTwoFactorPage, ipAddr)
}

func (s *httpdServer) handleWebAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderAdminLoginPage(w, err.Error(), ipAddr)
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		s.renderAdminLoginPage(w, "Invalid credentials", ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderAdminLoginPage(w, err.Error(), ipAddr)
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, ipAddr)
	if err != nil {
		s.renderAdminLoginPage(w, err.Error(), ipAddr)
		return
	}
	s.loginAdmin(w, r, &admin, false, s.renderAdminLoginPage, ipAddr)
}

func (s *httpdServer) renderAdminLoginPage(w http.ResponseWriter, error, ip string) {
	data := loginPage{
		CurrentURL: webAdminLoginPath,
		Version:    version.Get().Version,
		Error:      error,
		CSRFToken:  createCSRFToken(ip),
		StaticURL:  webStaticFilesPath,
		ExtraCSS:   s.binding.ExtraCSS,
	}
	if s.binding.showClientLoginURL() {
		data.AltLoginURL = webClientLoginPath
	}
	if smtp.IsEnabled() {
		data.ForgotPwdURL = webAdminForgotPwdPath
	}
	if s.binding.OIDC.hasRoles() {
		data.OpenIDLoginURL = webAdminOIDCLoginPath
	}
	renderAdminTemplate(w, templateLogin, data)
}

func (s *httpdServer) handleWebAdminLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	s.renderAdminLoginPage(w, getFlashMessage(w, r), util.GetIPFromRemoteAddress(r.RemoteAddr))
}

func (s *httpdServer) handleWebAdminLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	c := jwtTokenClaims{}
	c.removeCookie(w, r, webBaseAdminPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebAdminChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderChangePasswordPage(w, r, err.Error())
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	err = doChangeAdminPassword(r, r.Form.Get("current_password"), r.Form.Get("new_password1"),
		r.Form.Get("new_password2"))
	if err != nil {
		s.renderChangePasswordPage(w, r, err.Error())
		return
	}
	s.handleWebAdminLogout(w, r)
}

func (s *httpdServer) handleWebAdminPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderResetPwdPage(w, err.Error(), ipAddr)
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	admin, _, err := handleResetPassword(r, r.Form.Get("code"), r.Form.Get("password"), true)
	if err != nil {
		if e, ok := err.(*util.ValidationError); ok {
			s.renderResetPwdPage(w, e.GetErrorString(), ipAddr)
			return
		}
		s.renderResetPwdPage(w, err.Error(), ipAddr)
		return
	}

	s.loginAdmin(w, r, admin, false, s.renderResetPwdPage, ipAddr)
}

func (s *httpdServer) handleWebAdminSetupPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if dataprovider.HasAdmin() {
		s.renderBadRequestPage(w, r, errors.New("an admin user already exists"))
		return
	}
	err := r.ParseForm()
	if err != nil {
		s.renderAdminSetupPage(w, r, "", err.Error())
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken), ipAddr); err != nil {
		s.renderForbiddenPage(w, r, err.Error())
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	confirmPassword := r.Form.Get("confirm_password")
	installCode := r.Form.Get("install_code")
	if installationCode != "" && installCode != resolveInstallationCode() {
		s.renderAdminSetupPage(w, r, username, fmt.Sprintf("%v mismatch", installationCodeHint))
		return
	}
	if username == "" {
		s.renderAdminSetupPage(w, r, username, "Please set a username")
		return
	}
	if password == "" {
		s.renderAdminSetupPage(w, r, username, "Please set a password")
		return
	}
	if password != confirmPassword {
		s.renderAdminSetupPage(w, r, username, "Passwords mismatch")
		return
	}
	admin := dataprovider.Admin{
		Username:    username,
		Password:    password,
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
	}
	err = dataprovider.AddAdmin(&admin, username, ipAddr)
	if err != nil {
		s.renderAdminSetupPage(w, r, username, err.Error())
		return
	}
	s.loginAdmin(w, r, &admin, false, nil, ipAddr)
}

func (s *httpdServer) loginUser(
	w http.ResponseWriter, r *http.Request, user *dataprovider.User, connectionID, ipAddr string,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, error, ip string),
) {
	c := jwtTokenClaims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Signature:                  user.GetSignature(),
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}

	audience := tokenAudienceWebClient
	if user.Filters.TOTPConfig.Enabled && util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) &&
		user.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebClientPartial
	}

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to set user login cookie %v", err)
		updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure)
		errorFunc(w, err.Error(), ipAddr)
		return
	}
	if isSecondFactorAuth {
		invalidateToken(r)
	}
	if audience == tokenAudienceWebClientPartial {
		http.Redirect(w, r, webClientTwoFactorPath, http.StatusFound)
		return
	}
	updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, err)
	dataprovider.UpdateLastLogin(user)
	http.Redirect(w, r, webClientFilesPath, http.StatusFound)
}

func (s *httpdServer) loginAdmin(
	w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, error, ip string),
	ipAddr string,
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

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, "", "unable to set admin login cookie %v", err)
		if errorFunc == nil {
			s.renderAdminSetupPage(w, r, admin.Username, err.Error())
			return
		}
		errorFunc(w, err.Error(), ipAddr)
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
	protocol := common.ProtocolHTTP
	if !ok {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if user.Filters.TOTPConfig.Enabled && util.IsStringInSlice(common.ProtocolHTTP, user.Filters.TOTPConfig.Protocols) {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for user %#v and not passcode provided, authentication refused", user.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
		err = user.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure)
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err), http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
			user.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for user %#v, match? %v, err: %v", user.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.generateAndSendUserToken(w, r, ipAddr, user)
}

func (s *httpdServer) generateAndSendUserToken(w http.ResponseWriter, r *http.Request, ipAddr string, user dataprovider.User) {
	c := jwtTokenClaims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Signature:                  user.GetSignature(),
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPIUser, ipAddr)

	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err)
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
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	admin, err := dataprovider.CheckAdminAndPass(username, password, ipAddr)
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

	s.generateAndSendToken(w, r, admin, ipAddr)
}

func (s *httpdServer) generateAndSendToken(w http.ResponseWriter, r *http.Request, admin dataprovider.Admin, ip string) {
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPI, ip)

	if err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dataprovider.UpdateAdminLastLogin(&admin)
	render.JSON(w, r, resp)
}

func (s *httpdServer) checkCookieExpiration(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value(oidcTokenKey).(string); ok {
		return
	}
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
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebClient, util.GetIPFromRemoteAddress(r.RemoteAddr)) //nolint:errcheck
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
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if !admin.CanLoginFromIP(ipAddr) {
		logger.Debug(logSender, "", "admin %#v cannot login from %v, unable to refresh cookie", admin.Username, r.RemoteAddr)
		return
	}
	tokenClaims.Permissions = admin.Permissions
	logger.Debug(logSender, "", "cookie refreshed for admin %#v", admin.Username)
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebAdmin, ipAddr) //nolint:errcheck
}

func (s *httpdServer) updateContextFromCookie(r *http.Request) *http.Request {
	token, _, err := jwtauth.FromContext(r.Context())
	if token == nil || err != nil {
		_, err = r.Cookie(jwtCookieKey)
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
		areHeadersAllowed := false
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
					areHeadersAllowed = true
					break
				}
			}
		}
		if !areHeadersAllowed {
			for idx := range s.binding.Security.proxyHeaders {
				r.Header.Del(s.binding.Security.proxyHeaders[idx])
			}
		}

		common.Connections.AddClientConnection(ipAddr)
		defer common.Connections.RemoveClientConnection(ipAddr)

		if !common.Connections.IsNewConnectionAllowed(ipAddr) {
			logger.Log(logger.LevelDebug, common.ProtocolHTTP, "", fmt.Sprintf("connection not allowed from ip %#v", ipAddr))
			s.sendForbiddenResponse(w, r, "connection not allowed from your ip")
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
			s.renderClientMessagePage(w, r, http.StatusText(http.StatusTooManyRequests), "Rate limit exceeded",
				http.StatusTooManyRequests, err, "")
			return
		}
		s.renderMessagePage(w, r, http.StatusText(http.StatusTooManyRequests), "Rate limit exceeded", http.StatusTooManyRequests,
			err, "")
		return
	}
	sendAPIResponse(w, r, err, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (s *httpdServer) sendForbiddenResponse(w http.ResponseWriter, r *http.Request, message string) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			s.renderClientForbiddenPage(w, r, message)
			return
		}
		s.renderForbiddenPage(w, r, message)
		return
	}
	sendAPIResponse(w, r, errors.New(message), message, http.StatusForbidden)
}

func (s *httpdServer) badHostHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	for _, header := range s.binding.Security.HostsProxyHeaders {
		if h := r.Header.Get(header); h != "" {
			host = h
			break
		}
	}
	s.sendForbiddenResponse(w, r, fmt.Sprintf("The host %#v is not allowed", host))
}

func (s *httpdServer) redirectToWebPath(w http.ResponseWriter, r *http.Request, webPath string) {
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webPath, http.StatusFound)
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
	s.router.Use(middleware.Recoverer)
	if s.binding.Security.Enabled {
		secureMiddleware := secure.New(secure.Options{
			AllowedHosts:            s.binding.Security.AllowedHosts,
			AllowedHostsAreRegex:    s.binding.Security.AllowedHostsAreRegex,
			HostsProxyHeaders:       s.binding.Security.HostsProxyHeaders,
			SSLRedirect:             s.binding.Security.HTTPSRedirect,
			SSLHost:                 s.binding.Security.HTTPSHost,
			SSLTemporaryRedirect:    true,
			SSLProxyHeaders:         s.binding.Security.getHTTPSProxyHeaders(),
			STSSeconds:              s.binding.Security.STSSeconds,
			STSIncludeSubdomains:    s.binding.Security.STSIncludeSubdomains,
			STSPreload:              s.binding.Security.STSPreload,
			ContentTypeNosniff:      s.binding.Security.ContentTypeNosniff,
			ContentSecurityPolicy:   s.binding.Security.ContentSecurityPolicy,
			PermissionsPolicy:       s.binding.Security.PermissionsPolicy,
			CrossOriginOpenerPolicy: s.binding.Security.CrossOriginOpenerPolicy,
			ExpectCTHeader:          s.binding.Security.ExpectCTHeader,
		})
		secureMiddleware.SetBadHostHandler(http.HandlerFunc(s.badHostHandler))
		s.router.Use(secureMiddleware.Handler)
	}
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
				s.renderClientNotFoundPage(w, r, nil)
				return
			}
			s.renderNotFoundPage(w, r, nil)
			return
		}
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}))

	s.router.Get(healthzPath, func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "ok")
	})

	// share API exposed to external users
	s.router.Get(sharesPath+"/{id}", s.downloadFromShare)
	s.router.Post(sharesPath+"/{id}", s.uploadFilesToShare)
	s.router.Post(sharesPath+"/{id}/{name}", s.uploadFileToShare)
	s.router.With(compressor.Handler).Get(sharesPath+"/{id}/dirs", s.readBrowsableShareContents)
	s.router.Get(sharesPath+"/{id}/files", s.downloadBrowsableSharedFile)

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

		router.With(s.checkPerm(dataprovider.PermAdminViewServerStatus)).
			Get(serverStatusPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, getServicesStatus())
			})

		router.With(s.checkPerm(dataprovider.PermAdminViewConnections)).
			Get(activeConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, common.Connections.GetStats())
			})

		router.With(s.checkPerm(dataprovider.PermAdminCloseConnections)).
			Delete(activeConnectionsPath+"/{connectionID}", handleCloseConnection)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanPath, getUsersQuotaScans)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/users/scans", getUsersQuotaScans)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanPath, startUserQuotaScanCompat)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/users/{username}/scan", startUserQuotaScan)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanVFolderPath, getFoldersQuotaScans)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/folders/scans", getFoldersQuotaScans)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanVFolderPath, startFolderQuotaScanCompat)
		router.With(s.checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/folders/{name}/scan", startFolderQuotaScan)
		router.With(s.checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath, getUsers)
		router.With(s.checkPerm(dataprovider.PermAdminAddUsers)).Post(userPath, addUser)
		router.With(s.checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath+"/{username}", getUserByUsername)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}", updateUser)
		router.With(s.checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(userPath+"/{username}", deleteUser)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}/2fa/disable", disableUser2FA)
		router.With(s.checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath, getFolders)
		router.With(s.checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath+"/{name}", getFolderByName)
		router.With(s.checkPerm(dataprovider.PermAdminAddUsers)).Post(folderPath, addFolder)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(folderPath+"/{name}", updateFolder)
		router.With(s.checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(folderPath+"/{name}", deleteFolder)
		router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Get(dumpDataPath, dumpData)
		router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Get(loadDataPath, loadData)
		router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Post(loadDataPath, loadDataFromRequest)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateUsedQuotaPath, updateUserQuotaUsageCompat)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/usage",
			updateUserQuotaUsage)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/transfer-usage",
			updateUserTransferQuotaUsage)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateFolderUsedQuotaPath, updateFolderQuotaUsageCompat)
		router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/folders/{name}/usage",
			updateFolderQuotaUsage)
		router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderHosts, getDefenderHosts)
		router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderHosts+"/{id}", getDefenderHostByID)
		router.With(s.checkPerm(dataprovider.PermAdminManageDefender)).Delete(defenderHosts+"/{id}", deleteDefenderHostByID)
		router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderBanTime, getBanTime)
		router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderScore, getScore)
		router.With(s.checkPerm(dataprovider.PermAdminManageDefender)).Post(defenderUnban, unban)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath, getAdmins)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Post(adminPath, addAdmin)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath+"/{username}", getAdminByUsername)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Put(adminPath+"/{username}", updateAdmin)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Delete(adminPath+"/{username}", deleteAdmin)
		router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Put(adminPath+"/{username}/2fa/disable", disableAdmin2FA)
		router.With(s.checkPerm(dataprovider.PermAdminRetentionChecks)).Get(retentionChecksPath, getRetentionChecks)
		router.With(s.checkPerm(dataprovider.PermAdminRetentionChecks)).Post(retentionBasePath+"/{username}/check",
			startRetentionCheck)
		router.With(s.checkPerm(dataprovider.PermAdminMetadataChecks)).Get(metadataChecksPath, getMetadataChecks)
		router.With(s.checkPerm(dataprovider.PermAdminMetadataChecks)).Post(metadataBasePath+"/{username}/check",
			startMetadataCheck)
		router.With(s.checkPerm(dataprovider.PermAdminViewEvents), compressor.Handler).
			Get(fsEventsPath, searchFsEvents)
		router.With(s.checkPerm(dataprovider.PermAdminViewEvents), compressor.Handler).
			Get(providerEventsPath, searchProviderEvents)
		router.With(forbidAPIKeyAuthentication, s.checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Get(apiKeysPath, getAPIKeys)
		router.With(forbidAPIKeyAuthentication, s.checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Post(apiKeysPath, addAPIKey)
		router.With(forbidAPIKeyAuthentication, s.checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Get(apiKeysPath+"/{id}", getAPIKeyByID)
		router.With(forbidAPIKeyAuthentication, s.checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Put(apiKeysPath+"/{id}", updateAPIKey)
		router.With(forbidAPIKeyAuthentication, s.checkPerm(dataprovider.PermAdminManageAPIKeys)).
			Delete(apiKeysPath+"/{id}", deleteAPIKey)
	})

	s.router.Get(userTokenPath, s.getUserToken)

	s.router.Group(func(router chi.Router) {
		router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeUser))
		router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
		router.Use(jwtAuthenticatorAPIUser)

		router.With(forbidAPIKeyAuthentication).Get(userLogoutPath, s.logout)
		router.With(forbidAPIKeyAuthentication, s.checkSecondFactorRequirement,
			s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).Put(userPwdPath, changeUserPassword)
		router.With(forbidAPIKeyAuthentication, s.checkSecondFactorRequirement,
			s.checkHTTPUserPerm(sdk.WebClientPubKeyChangeDisabled)).Get(userPublicKeysPath, getUserPublicKeys)
		router.With(forbidAPIKeyAuthentication, s.checkSecondFactorRequirement,
			s.checkHTTPUserPerm(sdk.WebClientPubKeyChangeDisabled)).Put(userPublicKeysPath, setUserPublicKeys)
		router.With(forbidAPIKeyAuthentication).Get(userProfilePath, getUserProfile)
		router.With(forbidAPIKeyAuthentication, s.checkSecondFactorRequirement).Put(userProfilePath, updateUserProfile)
		// user TOTP APIs
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Get(userTOTPConfigsPath, getTOTPConfigs)
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPGeneratePath, generateTOTPSecret)
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPValidatePath, validateTOTPPasscode)
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(userTOTPSavePath, saveTOTPConfig)
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Get(user2FARecoveryCodesPath, getRecoveryCodes)
		router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
			Post(user2FARecoveryCodesPath, generateRecoveryCodes)

		// compatibility layer to remove in v2.3
		router.With(s.checkSecondFactorRequirement, compressor.Handler).Get(userFolderPath, readUserFolder)
		router.With(s.checkSecondFactorRequirement).Get(userFilePath, getUserFile)

		router.With(s.checkSecondFactorRequirement, compressor.Handler).Get(userDirsPath, readUserFolder)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Post(userDirsPath, createUserDir)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Patch(userDirsPath, renameUserDir)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Delete(userDirsPath, deleteUserDir)
		router.With(s.checkSecondFactorRequirement).Get(userFilesPath, getUserFile)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Post(userFilesPath, uploadUserFiles)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Patch(userFilesPath, renameUserFile)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Delete(userFilesPath, deleteUserFile)
		router.With(s.checkSecondFactorRequirement).Post(userStreamZipPath, getUserFilesAsZipStream)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
			Get(userSharesPath, getShares)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
			Post(userSharesPath, addShare)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
			Get(userSharesPath+"/{id}", getShareByID)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
			Put(userSharesPath+"/{id}", updateShare)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
			Delete(userSharesPath+"/{id}", deleteShare)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Post(userUploadFilePath, uploadUserFile)
		router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
			Patch(userFilesDirsMetadataPath, setFileDirMetadata)
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
		if s.binding.OIDC.isEnabled() {
			s.router.Get(webOIDCRedirectPath, s.handleOIDCRedirect)
		}
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
				s.redirectToWebPath(w, r, webAdminLoginPath)
			})
			s.router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webAdminLoginPath)
			})
		}
	}

	s.setupWebClientRoutes()
	s.setupWebAdminRoutes()
}

func (s *httpdServer) setupWebClientRoutes() {
	if s.enableWebClient {
		s.router.Get(webBaseClientPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
			http.Redirect(w, r, webClientLoginPath, http.StatusFound)
		})
		s.router.Get(webClientLoginPath, s.handleClientWebLogin)
		if s.binding.OIDC.isEnabled() {
			s.router.Get(webClientOIDCLoginPath, s.handleWebClientOIDCLogin)
		}
		s.router.Post(webClientLoginPath, s.handleWebClientLoginPost)
		s.router.Get(webClientForgotPwdPath, s.handleWebClientForgotPwd)
		s.router.Post(webClientForgotPwdPath, s.handleWebClientForgotPwdPost)
		s.router.Get(webClientResetPwdPath, s.handleWebClientPasswordReset)
		s.router.Post(webClientResetPwdPath, s.handleWebClientPasswordResetPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Get(webClientTwoFactorPath, s.handleWebClientTwoFactor)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Post(webClientTwoFactorPath, s.handleWebClientTwoFactorPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Get(webClientTwoFactorRecoveryPath, s.handleWebClientTwoFactorRecovery)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
			Post(webClientTwoFactorRecoveryPath, s.handleWebClientTwoFactorRecoveryPost)
		// share API exposed to external users
		s.router.Get(webClientPubSharesPath+"/{id}", s.downloadFromShare)
		s.router.Get(webClientPubSharesPath+"/{id}/browse", s.handleShareGetFiles)
		s.router.Get(webClientPubSharesPath+"/{id}/upload", s.handleClientUploadToShare)
		s.router.With(compressor.Handler).Get(webClientPubSharesPath+"/{id}/dirs", s.handleShareGetDirContents)
		s.router.Post(webClientPubSharesPath+"/{id}", s.uploadFilesToShare)
		s.router.Post(webClientPubSharesPath+"/{id}/{name}", s.uploadFileToShare)

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebClient))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, tokenFromContext, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebClient)

			router.Get(webClientLogoutPath, s.handleWebClientLogout)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie).Get(webClientFilesPath, s.handleClientGetFiles)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie).Get(webClientViewPDFPath, s.handleClientViewPDF)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie, verifyCSRFHeader).Get(webClientFilePath, getUserFile)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Post(webClientFilePath, uploadUserFile)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie).Get(webClientEditFilePath, s.handleClientEditFile)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Patch(webClientFilesPath, renameUserFile)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Delete(webClientFilesPath, deleteUserFile)
			router.With(s.checkSecondFactorRequirement, compressor.Handler, s.refreshCookie).
				Get(webClientDirsPath, s.handleClientGetDirContents)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Post(webClientDirsPath, createUserDir)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Patch(webClientDirsPath, renameUserDir)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), verifyCSRFHeader).
				Delete(webClientDirsPath, deleteUserDir)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie).
				Get(webClientDownloadZipPath, s.handleWebClientDownloadZip)
			router.With(s.checkSecondFactorRequirement, s.refreshCookie, s.requireBuiltinLogin).
				Get(webClientProfilePath, s.handleClientGetProfile)
			router.With(s.checkSecondFactorRequirement, s.requireBuiltinLogin).
				Post(webClientProfilePath, s.handleWebClientProfilePost)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Get(webChangeClientPwdPath, s.handleWebClientChangePwd)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Post(webChangeClientPwdPath, s.handleWebClientChangePwdPost)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath, s.handleWebClientMFA)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPGeneratePath, generateTOTPSecret)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPValidatePath, validateTOTPPasscode)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientTOTPSavePath, saveTOTPConfig)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader, s.refreshCookie).
				Get(webClientRecoveryCodesPath, getRecoveryCodes)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), verifyCSRFHeader).
				Post(webClientRecoveryCodesPath, generateRecoveryCodes)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharesPath, s.handleClientGetShares)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath, s.handleClientAddShareGet)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath, s.handleClientAddSharePost)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath+"/{id}", s.handleClientUpdateShareGet)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath+"/{id}", s.handleClientUpdateSharePost)
			router.With(s.checkSecondFactorRequirement, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), verifyCSRFHeader).
				Delete(webClientSharePath+"/{id}", deleteShare)
		})
	}
}

func (s *httpdServer) setupWebAdminRoutes() {
	if s.enableWebAdmin {
		s.router.Get(webBaseAdminPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
			s.redirectToWebPath(w, r, webAdminLoginPath)
		})
		s.router.Get(webAdminLoginPath, s.handleWebAdminLogin)
		if s.binding.OIDC.hasRoles() {
			s.router.Get(webAdminOIDCLoginPath, s.handleWebAdminOIDCLogin)
		}
		s.router.Post(webAdminLoginPath, s.handleWebAdminLoginPost)
		s.router.Get(webAdminSetupPath, s.handleWebAdminSetupGet)
		s.router.Post(webAdminSetupPath, s.handleWebAdminSetupPost)
		s.router.Get(webAdminForgotPwdPath, s.handleWebAdminForgotPwd)
		s.router.Post(webAdminForgotPwdPath, s.handleWebAdminForgotPwdPost)
		s.router.Get(webAdminResetPwdPath, s.handleWebAdminPasswordReset)
		s.router.Post(webAdminResetPwdPath, s.handleWebAdminPasswordResetPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Get(webAdminTwoFactorPath, s.handleWebAdminTwoFactor)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Post(webAdminTwoFactorPath, s.handleWebAdminTwoFactorPost)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Get(webAdminTwoFactorRecoveryPath, s.handleWebAdminTwoFactorRecovery)
		s.router.With(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie),
			s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
			Post(webAdminTwoFactorRecoveryPath, s.handleWebAdminTwoFactorRecoveryPost)

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebAdmin))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, tokenFromContext, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebAdmin)

			router.Get(webLogoutPath, s.handleWebAdminLogout)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminProfilePath, s.handleWebAdminProfile)
			router.With(s.requireBuiltinLogin).Post(webAdminProfilePath, s.handleWebAdminProfilePost)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webChangeAdminPwdPath, s.handleWebAdminChangePwd)
			router.With(s.requireBuiltinLogin).Post(webChangeAdminPwdPath, s.handleWebAdminChangePwdPost)

			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminMFAPath, s.handleWebAdminMFA)
			router.With(verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPGeneratePath, generateTOTPSecret)
			router.With(verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPValidatePath, validateTOTPPasscode)
			router.With(verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPSavePath, saveTOTPConfig)
			router.With(verifyCSRFHeader, s.requireBuiltinLogin, s.refreshCookie).Get(webAdminRecoveryCodesPath, getRecoveryCodes)
			router.With(verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminRecoveryCodesPath, generateRecoveryCodes)

			router.With(s.checkPerm(dataprovider.PermAdminViewUsers), s.refreshCookie).
				Get(webUsersPath, s.handleGetWebUsers)
			router.With(s.checkPerm(dataprovider.PermAdminAddUsers), s.refreshCookie).
				Get(webUserPath, s.handleWebAddUserGet)
			router.With(s.checkPerm(dataprovider.PermAdminChangeUsers), s.refreshCookie).
				Get(webUserPath+"/{username}", s.handleWebUpdateUserGet)
			router.With(s.checkPerm(dataprovider.PermAdminAddUsers)).Post(webUserPath, s.handleWebAddUserPost)
			router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Post(webUserPath+"/{username}",
				s.handleWebUpdateUserPost)
			router.With(s.checkPerm(dataprovider.PermAdminViewConnections), s.refreshCookie).
				Get(webConnectionsPath, s.handleWebGetConnections)
			router.With(s.checkPerm(dataprovider.PermAdminViewUsers), s.refreshCookie).
				Get(webFoldersPath, s.handleWebGetFolders)
			router.With(s.checkPerm(dataprovider.PermAdminAddUsers), s.refreshCookie).
				Get(webFolderPath, s.handleWebAddFolderGet)
			router.With(s.checkPerm(dataprovider.PermAdminAddUsers)).Post(webFolderPath, s.handleWebAddFolderPost)
			router.With(s.checkPerm(dataprovider.PermAdminViewServerStatus), s.refreshCookie).
				Get(webStatusPath, s.handleWebGetStatus)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminsPath, s.handleGetWebAdmins)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminPath, s.handleWebAddAdminGet)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins), s.refreshCookie).
				Get(webAdminPath+"/{username}", s.handleWebUpdateAdminGet)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Post(webAdminPath, s.handleWebAddAdminPost)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins)).Post(webAdminPath+"/{username}",
				s.handleWebUpdateAdminPost)
			router.With(s.checkPerm(dataprovider.PermAdminManageAdmins), verifyCSRFHeader).
				Delete(webAdminPath+"/{username}", deleteAdmin)
			router.With(s.checkPerm(dataprovider.PermAdminCloseConnections), verifyCSRFHeader).
				Delete(webConnectionsPath+"/{connectionID}", handleCloseConnection)
			router.With(s.checkPerm(dataprovider.PermAdminChangeUsers), s.refreshCookie).
				Get(webFolderPath+"/{name}", s.handleWebUpdateFolderGet)
			router.With(s.checkPerm(dataprovider.PermAdminChangeUsers)).Post(webFolderPath+"/{name}",
				s.handleWebUpdateFolderPost)
			router.With(s.checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
				Delete(webFolderPath+"/{name}", deleteFolder)
			router.With(s.checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
				Post(webScanVFolderPath+"/{name}", startFolderQuotaScan)
			router.With(s.checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
				Delete(webUserPath+"/{username}", deleteUser)
			router.With(s.checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
				Post(webQuotaScanPath+"/{username}", startUserQuotaScan)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Get(webMaintenancePath, s.handleWebMaintenance)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Get(webBackupPath, dumpData)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Post(webRestorePath, s.handleWebRestore)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
				Get(webTemplateUser, s.handleWebTemplateUserGet)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateUser, s.handleWebTemplateUserPost)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
				Get(webTemplateFolder, s.handleWebTemplateFolderGet)
			router.With(s.checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateFolder, s.handleWebTemplateFolderPost)
			router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(webDefenderPath, s.handleWebDefenderPage)
			router.With(s.checkPerm(dataprovider.PermAdminViewDefender)).Get(webDefenderHostsPath, getDefenderHosts)
			router.With(s.checkPerm(dataprovider.PermAdminManageDefender)).Delete(webDefenderHostsPath+"/{id}",
				deleteDefenderHostByID)
		})
	}
}
