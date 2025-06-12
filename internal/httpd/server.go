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
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/rs/cors"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/unrolled/secure"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	jsonAPISuffix = "/json"
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
	enableRESTAPI     bool
	renderOpenAPI     bool
	isShared          int
	router            *chi.Mux
	tokenAuth         *jwtauth.JWTAuth
	csrfTokenAuth     *jwtauth.JWTAuth
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
		enableRESTAPI:     b.EnableRESTAPI,
		renderOpenAPI:     b.RenderOpenAPI,
		signingPassphrase: signingPassphrase,
		cors:              cors,
	}
}

func (s *httpdServer) setShared(value int) {
	s.isShared = value
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
		certID := common.DefaultTLSKeyPaidID
		if getConfigPath(s.binding.CertificateFile, "") != "" && getConfigPath(s.binding.CertificateKeyFile, "") != "" {
			certID = s.binding.GetAddress()
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(certID),
			MinVersion:     util.GetTLSVersion(s.binding.MinTLSVersion),
			NextProtos:     util.GetALPNProtocols(s.binding.Protocols),
			CipherSuites:   util.GetTLSCiphersFromNames(s.binding.TLSCipherSuites),
		}
		httpServer.TLSConfig = config
		logger.Debug(logSender, "", "configured TLS cipher suites for binding %q: %v, certID: %v",
			s.binding.GetAddress(), httpServer.TLSConfig.CipherSuites, certID)
		if s.binding.isMutualTLSEnabled() {
			httpServer.TLSConfig.ClientCAs = certMgr.GetRootCAs()
			httpServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			httpServer.TLSConfig.VerifyConnection = s.verifyTLSConnection
		}
		return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, true,
			s.binding.listenerWrapper(), logSender)
	}
	return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, false,
		s.binding.listenerWrapper(), logSender)
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
				logger.Debug(logSender, "", "tls handshake error, client certificate %q has been revoked", clientCrtName)
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

func (s *httpdServer) renderClientLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := loginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nLoginTitle,
		CurrentURL:     webClientLoginPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, xid.New().String(), webBaseClientPath),
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
		FormDisabled:   s.binding.isWebClientLoginFormDisabled(),
		CheckRedirect:  true,
	}
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		data.CurrentURL += "?next=" + url.QueryEscape(next)
	}
	if s.binding.showAdminLoginURL() {
		data.AltLoginURL = webAdminLoginPath
		data.AltLoginName = s.binding.webAdminBranding().ShortName
	}
	if smtp.IsEnabled() && !data.FormDisabled {
		data.ForgotPwdURL = webClientForgotPwdPath
	}
	if s.binding.OIDC.isEnabled() && !s.binding.isWebClientOIDCLoginDisabled() {
		data.OpenIDLoginURL = webClientOIDCLoginPath
	}
	renderClientTemplate(w, templateCommonLogin, data)
}

func (s *httpdServer) handleWebClientLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	removeCookie(w, r, webBaseClientPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebClientChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if err := r.ParseForm(); err != nil {
		s.renderClientChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err := doChangeUserPassword(r, strings.TrimSpace(r.Form.Get("current_password")),
		strings.TrimSpace(r.Form.Get("new_password1")), strings.TrimSpace(r.Form.Get("new_password2")))
	if err != nil {
		s.renderClientChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
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
	msg := getFlashMessage(w, r)
	s.renderClientLoginPage(w, r, msg.getI18nError())
}

func (s *httpdServer) handleWebClientLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	protocol := common.ProtocolHTTP
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		s.renderClientLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
	}

	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}

	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorFsGeneric))
		return
	}
	s.loginUser(w, r, &user, connectionID, ipAddr, false, s.renderClientLoginPage)
}

func (s *httpdServer) handleWebClientPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	newPassword := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	_, user, err := handleResetPassword(r, strings.TrimSpace(r.Form.Get("code")),
		newPassword, confirmPassword, false)
	if err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}
	connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
	if err := checkHTTPClientUser(user, r, connectionID, true, false); err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorLoginAfterReset))
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorLoginAfterReset))
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
		s.renderClientTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	recoveryCode := strings.TrimSpace(r.Form.Get("recovery_code"))
	if username == "" || recoveryCode == "" {
		s.renderClientTwoFactorRecoveryPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user, userMerged, err := dataprovider.GetUserVariants(username, "")
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderClientTwoFactorRecoveryPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if !userMerged.Filters.TOTPConfig.Enabled || !slices.Contains(userMerged.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(
			util.NewValidationError("two factory authentication is not enabled"), util.I18n2FADisabled))
		return
	}
	for idx, code := range user.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderClientInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderClientTwoFactorRecoveryPage(w, r,
					util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
				return
			}
			user.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %q as used: %v", recoveryCode, err)
				s.renderClientInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
			s.loginUser(w, r, &userMerged, connectionID, ipAddr, true,
				s.renderClientTwoFactorRecoveryPage)
			return
		}
	}
	handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
	s.renderClientTwoFactorRecoveryPage(w, r,
		util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
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
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	passcode := strings.TrimSpace(r.Form.Get("passcode"))
	if username == "" || passcode == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(username, "")
	if err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials))
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(common.ErrInternalFailure, util.I18n2FADisabled))
		return
	}
	err = user.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	connectionID := fmt.Sprintf("%s_%s", getProtocolFromRequest(r), xid.New().String())
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
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	recoveryCode := strings.TrimSpace(r.Form.Get("recovery_code"))
	if username == "" || recoveryCode == "" {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(util.NewValidationError("two factory authentication is not enabled"), util.I18n2FADisabled))
		return
	}
	for idx, code := range admin.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderTwoFactorRecoveryPage(w, r,
					util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
				return
			}
			admin.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %q as used: %v", recoveryCode, err)
				s.renderInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			s.loginAdmin(w, r, &admin, true, s.renderTwoFactorRecoveryPage, ipAddr)
			return
		}
	}
	handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
	s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
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
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	passcode := strings.TrimSpace(r.Form.Get("passcode"))
	if username == "" || passcode == "" {
		s.renderTwoFactorPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials))
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorPage(w, r, util.NewI18nError(common.ErrInternalFailure, util.I18n2FADisabled))
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
		handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
		s.renderTwoFactorPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	s.loginAdmin(w, r, &admin, true, s.renderTwoFactorPage, ipAddr)
}

func (s *httpdServer) handleWebAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))
	if username == "" || password == "" {
		s.renderAdminLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, ipAddr)
	if err != nil {
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		s.renderAdminLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	s.loginAdmin(w, r, &admin, false, s.renderAdminLoginPage, ipAddr)
}

func (s *httpdServer) renderAdminLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := loginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nLoginTitle,
		CurrentURL:     webAdminLoginPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, xid.New().String(), webBaseAdminPath),
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
		FormDisabled:   s.binding.isWebAdminLoginFormDisabled(),
		CheckRedirect:  false,
	}
	if s.binding.showClientLoginURL() {
		data.AltLoginURL = webClientLoginPath
		data.AltLoginName = s.binding.webClientBranding().ShortName
	}
	if smtp.IsEnabled() && !data.FormDisabled {
		data.ForgotPwdURL = webAdminForgotPwdPath
	}
	if s.binding.OIDC.hasRoles() && !s.binding.isWebAdminOIDCLoginDisabled() {
		data.OpenIDLoginURL = webAdminOIDCLoginPath
	}
	renderAdminTemplate(w, templateCommonLogin, data)
}

func (s *httpdServer) handleWebAdminLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	msg := getFlashMessage(w, r)
	s.renderAdminLoginPage(w, r, msg.getI18nError())
}

func (s *httpdServer) handleWebAdminLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	removeCookie(w, r, webBaseAdminPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebAdminChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = doChangeAdminPassword(r, strings.TrimSpace(r.Form.Get("current_password")),
		strings.TrimSpace(r.Form.Get("new_password1")), strings.TrimSpace(r.Form.Get("new_password2")))
	if err != nil {
		s.renderChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}
	s.handleWebAdminLogout(w, r)
}

func (s *httpdServer) handleWebAdminPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	newPassword := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	admin, _, err := handleResetPassword(r, strings.TrimSpace(r.Form.Get("code")),
		newPassword, confirmPassword, true)
	if err != nil {
		s.renderResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
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
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderAdminSetupPage(w, r, "", util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	installCode := strings.TrimSpace(r.Form.Get("install_code"))
	if installationCode != "" && installCode != resolveInstallationCode() {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("%v mismatch", installationCodeHint)),
				util.I18nErrorSetupInstallCode),
		)
		return
	}
	if username == "" {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(util.NewValidationError("please set a username"), util.I18nError500Message))
		return
	}
	if password == "" {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(util.NewValidationError("please set a password"), util.I18nError500Message))
		return
	}
	if password != confirmPassword {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(errors.New("the two password fields do not match"), util.I18nErrorChangePwdNoMatch))
		return
	}
	admin := dataprovider.Admin{
		Username:    username,
		Password:    password,
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
	}
	err = dataprovider.AddAdmin(&admin, username, ipAddr, "")
	if err != nil {
		s.renderAdminSetupPage(w, r, username, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	s.loginAdmin(w, r, &admin, false, nil, ipAddr)
}

func (s *httpdServer) loginUser(
	w http.ResponseWriter, r *http.Request, user *dataprovider.User, connectionID, ipAddr string,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, r *http.Request, err *util.I18nError),
) {
	c := jwtTokenClaims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Signature:                  user.GetSignature(),
		Role:                       user.Role,
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		MustChangePassword:         user.MustChangePassword(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}

	audience := tokenAudienceWebClient
	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) &&
		user.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebClientPartial
	}

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to set user login cookie %v", err)
		updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		errorFunc(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	invalidateToken(r)
	if audience == tokenAudienceWebClientPartial {
		redirectPath := webClientTwoFactorPath
		if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
			redirectPath += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, redirectPath, http.StatusFound)
		return
	}
	updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, err, r)
	dataprovider.UpdateLastLogin(user)
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, webClientFilesPath, http.StatusFound)
}

func (s *httpdServer) loginAdmin(
	w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, r *http.Request, err *util.I18nError),
	ipAddr string,
) {
	c := jwtTokenClaims{
		Username:             admin.Username,
		Permissions:          admin.Permissions,
		Role:                 admin.Role,
		Signature:            admin.GetSignature(),
		HideUserPageSections: admin.Filters.Preferences.HideUserPageSections,
		MustSetTwoFactorAuth: admin.Filters.RequireTwoFactor && !admin.Filters.TOTPConfig.Enabled,
		MustChangePassword:   admin.Filters.RequirePasswordChange,
	}

	audience := tokenAudienceWebAdmin
	if admin.Filters.TOTPConfig.Enabled && admin.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebAdminPartial
	}

	err := c.createAndSetCookie(w, r, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, "", "unable to set admin login cookie %v", err)
		if errorFunc == nil {
			s.renderAdminSetupPage(w, r, admin.Username, util.NewI18nError(err, util.I18nError500Message))
			return
		}
		errorFunc(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	invalidateToken(r)
	if audience == tokenAudienceWebAdminPartial {
		http.Redirect(w, r, webAdminTwoFactorPath, http.StatusFound)
		return
	}
	dataprovider.UpdateAdminLastLogin(admin)
	common.DelayLogin(nil)
	redirectURL := webUsersPath
	if errorFunc == nil {
		redirectURL = webAdminMFAPath
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
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
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if username == "" || strings.TrimSpace(password) == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for user %q and not passcode provided, authentication refused", user.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
		err = user.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err), http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
			user.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for user %q, match? %v, err: %v", user.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
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
		Role:                       user.Role,
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		MustChangePassword:         user.MustChangePassword(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPIUser, ipAddr)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
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
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if admin.Filters.TOTPConfig.Enabled {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for admin %q and not passcode provided, authentication refused", admin.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			err = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
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
			logger.Debug(logSender, "invalid passcode for admin %q, match? %v, err: %v", admin.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			err = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	s.generateAndSendToken(w, r, admin, ipAddr)
}

func (s *httpdServer) generateAndSendToken(w http.ResponseWriter, r *http.Request, admin dataprovider.Admin, ip string) {
	c := jwtTokenClaims{
		Username:             admin.Username,
		Permissions:          admin.Permissions,
		Role:                 admin.Role,
		Signature:            admin.GetSignature(),
		MustSetTwoFactorAuth: admin.Filters.RequireTwoFactor && !admin.Filters.TOTPConfig.Enabled,
		MustChangePassword:   admin.Filters.RequirePasswordChange,
	}

	resp, err := c.createTokenResponse(s.tokenAuth, tokenAudienceAPI, ip)

	if err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dataprovider.UpdateAdminLastLogin(&admin)
	common.DelayLogin(nil)
	render.JSON(w, r, resp)
}

func (s *httpdServer) checkCookieExpiration(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value(oidcTokenKey).(string); ok {
		return
	}
	token, claims, err := jwtauth.FromContext(r.Context())
	if err != nil || token == nil {
		return
	}
	tokenClaims := jwtTokenClaims{}
	tokenClaims.Decode(claims)
	if tokenClaims.Username == "" || tokenClaims.Signature == "" {
		return
	}
	if time.Until(token.Expiration()) > cookieRefreshThreshold {
		return
	}
	if (time.Since(token.IssuedAt()) + cookieTokenDuration) > maxTokenDuration {
		return
	}
	tokenClaims.JwtIssuedAt = token.IssuedAt()
	if slices.Contains(token.Audience(), tokenAudienceWebClient) {
		s.refreshClientToken(w, r, &tokenClaims)
	} else {
		s.refreshAdminToken(w, r, &tokenClaims)
	}
}

func (s *httpdServer) refreshClientToken(w http.ResponseWriter, r *http.Request, tokenClaims *jwtTokenClaims) {
	user, err := dataprovider.GetUserWithGroupSettings(tokenClaims.Username, "")
	if err != nil {
		return
	}
	if user.GetSignature() != tokenClaims.Signature {
		logger.Debug(logSender, "", "signature mismatch for user %q, unable to refresh cookie", user.Username)
		return
	}
	if err := user.CheckLoginConditions(); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for user %q: %v", user.Username, err)
		return
	}
	if err := checkHTTPClientUser(&user, r, xid.New().String(), true, false); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for user %q: %v", user.Username, err)
		return
	}

	tokenClaims.Permissions = user.Filters.WebClient
	tokenClaims.Role = user.Role
	logger.Debug(logSender, "", "cookie refreshed for user %q", user.Username)
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth, tokenAudienceWebClient, util.GetIPFromRemoteAddress(r.RemoteAddr)) //nolint:errcheck
}

func (s *httpdServer) refreshAdminToken(w http.ResponseWriter, r *http.Request, tokenClaims *jwtTokenClaims) {
	admin, err := dataprovider.AdminExists(tokenClaims.Username)
	if err != nil {
		return
	}
	if admin.GetSignature() != tokenClaims.Signature {
		logger.Debug(logSender, "", "signature mismatch for admin %q, unable to refresh cookie", admin.Username)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := admin.CanLogin(ipAddr); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for admin %q, err: %v", admin.Username, err)
		return
	}
	tokenClaims.Permissions = admin.Permissions
	tokenClaims.Role = admin.Role
	tokenClaims.HideUserPageSections = admin.Filters.Preferences.HideUserPageSections
	logger.Debug(logSender, "", "cookie refreshed for admin %q", admin.Username)
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

func (s *httpdServer) parseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", version.GetServerVersion("/", false))
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		var ip net.IP
		isUnixSocket := filepath.IsAbs(s.binding.Address)
		if !isUnixSocket {
			ip = net.ParseIP(ipAddr)
		}
		areHeadersAllowed := false
		if isUnixSocket || ip != nil {
			for _, allow := range s.binding.allowHeadersFrom {
				if allow(ip) {
					parsedIP := util.GetRealIP(r, s.binding.ClientIPProxyHeader, s.binding.ClientIPHeaderDepth)
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

		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) checkConnection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		common.Connections.AddClientConnection(ipAddr)
		defer common.Connections.RemoveClientConnection(ipAddr)

		if err := common.Connections.IsNewConnectionAllowed(ipAddr, common.ProtocolHTTP); err != nil {
			logger.Log(logger.LevelDebug, common.ProtocolHTTP, "", "connection not allowed from ip %q: %v", ipAddr, err)
			s.sendForbiddenResponse(w, r, util.NewI18nError(err, util.I18nErrorConnectionForbidden))
			return
		}
		if common.IsBanned(ipAddr, common.ProtocolHTTP) {
			s.sendForbiddenResponse(w, r, util.NewI18nError(
				util.NewGenericError("your IP address is blocked"),
				util.I18nErrorIPForbidden),
			)
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
			s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
				util.NewI18nError(errors.New(http.StatusText(http.StatusTooManyRequests)), util.I18nError429Message), "")
			return
		}
		s.renderMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(errors.New(http.StatusText(http.StatusTooManyRequests)), util.I18nError429Message), "")
		return
	}
	sendAPIResponse(w, r, err, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (s *httpdServer) sendForbiddenResponse(w http.ResponseWriter, r *http.Request, err error) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			s.renderClientForbiddenPage(w, r, err)
			return
		}
		s.renderForbiddenPage(w, r, err)
		return
	}
	sendAPIResponse(w, r, err, "", http.StatusForbidden)
}

func (s *httpdServer) badHostHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	for _, header := range s.binding.Security.HostsProxyHeaders {
		if h := r.Header.Get(header); h != "" {
			host = h
			break
		}
	}
	logger.Debug(logSender, "", "the host %q is not allowed", host)
	s.sendForbiddenResponse(w, r, util.NewI18nError(
		util.NewGenericError(http.StatusText(http.StatusForbidden)),
		util.I18nErrorConnectionForbidden,
	))
}

func (s *httpdServer) notFoundHandler(w http.ResponseWriter, r *http.Request) {
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

// The StripSlashes causes infinite redirects at the root path if used with http.FileServer.
// We also don't strip paths with more than one trailing slash, see #1434
func (s *httpdServer) mustStripSlash(r *http.Request) bool {
	urlPath := getURLPath(r)
	return !strings.HasSuffix(urlPath, "//") && !strings.HasPrefix(urlPath, webOpenAPIPath) &&
		!strings.HasPrefix(urlPath, webStaticFilesPath) && !strings.HasPrefix(urlPath, acmeChallengeURI)
}

func (s *httpdServer) mustCheckPath(r *http.Request) bool {
	urlPath := getURLPath(r)
	return !strings.HasPrefix(urlPath, webStaticFilesPath) && !strings.HasPrefix(urlPath, acmeChallengeURI)
}

func (s *httpdServer) initializeRouter() {
	var hasHTTPSRedirect bool
	s.tokenAuth = jwtauth.New(jwa.HS256.String(), getSigningKey(s.signingPassphrase), nil)
	s.csrfTokenAuth = jwtauth.New(jwa.HS256.String(), getSigningKey(s.signingPassphrase), nil)
	s.router = chi.NewRouter()

	s.router.Use(middleware.RequestID)
	s.router.Use(s.parseHeaders)
	s.router.Use(logger.NewStructuredLogger(logger.GetLogger()))
	s.router.Use(middleware.Recoverer)
	if s.binding.Security.Enabled {
		secureMiddleware := secure.New(secure.Options{
			AllowedHosts:              s.binding.Security.AllowedHosts,
			AllowedHostsAreRegex:      s.binding.Security.AllowedHostsAreRegex,
			HostsProxyHeaders:         s.binding.Security.HostsProxyHeaders,
			SSLProxyHeaders:           s.binding.Security.getHTTPSProxyHeaders(),
			STSSeconds:                s.binding.Security.STSSeconds,
			STSIncludeSubdomains:      s.binding.Security.STSIncludeSubdomains,
			STSPreload:                s.binding.Security.STSPreload,
			ContentTypeNosniff:        s.binding.Security.ContentTypeNosniff,
			ContentSecurityPolicy:     s.binding.Security.ContentSecurityPolicy,
			PermissionsPolicy:         s.binding.Security.PermissionsPolicy,
			CrossOriginOpenerPolicy:   s.binding.Security.CrossOriginOpenerPolicy,
			CrossOriginResourcePolicy: s.binding.Security.CrossOriginResourcePolicy,
			CrossOriginEmbedderPolicy: s.binding.Security.CrossOriginEmbedderPolicy,
			ReferrerPolicy:            s.binding.Security.ReferrerPolicy,
		})
		secureMiddleware.SetBadHostHandler(http.HandlerFunc(s.badHostHandler))
		if s.binding.Security.CacheControl == "private" {
			s.router.Use(cacheControlMiddleware)
		}
		s.router.Use(secureMiddleware.Handler)
		if s.binding.Security.HTTPSRedirect {
			s.router.Use(s.binding.Security.redirectHandler)
			hasHTTPSRedirect = true
		}
	}
	if s.cors.Enabled {
		c := cors.New(cors.Options{
			AllowedOrigins:       util.RemoveDuplicates(s.cors.AllowedOrigins, true),
			AllowedMethods:       util.RemoveDuplicates(s.cors.AllowedMethods, true),
			AllowedHeaders:       util.RemoveDuplicates(s.cors.AllowedHeaders, true),
			ExposedHeaders:       util.RemoveDuplicates(s.cors.ExposedHeaders, true),
			MaxAge:               s.cors.MaxAge,
			AllowCredentials:     s.cors.AllowCredentials,
			OptionsPassthrough:   s.cors.OptionsPassthrough,
			OptionsSuccessStatus: s.cors.OptionsSuccessStatus,
			AllowPrivateNetwork:  s.cors.AllowPrivateNetwork,
		})
		s.router.Use(c.Handler)
	}
	s.router.Use(middleware.Maybe(s.checkConnection, s.mustCheckPath))
	s.router.Use(middleware.GetHead)
	s.router.Use(middleware.Maybe(middleware.StripSlashes, s.mustStripSlash))

	s.router.NotFound(s.notFoundHandler)

	s.router.Get(healthzPath, func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "ok")
	})

	if hasHTTPSRedirect {
		if p := acme.GetHTTP01WebRoot(); p != "" {
			serveStaticDir(s.router, acmeChallengeURI, p, true)
		}
	}

	s.setupRESTAPIRoutes()

	if s.enableWebAdmin || s.enableWebClient {
		s.router.Group(func(router chi.Router) {
			router.Use(cleanCacheControlMiddleware)
			router.Use(compressor.Handler)
			serveStaticDir(router, webStaticFilesPath, s.staticFilesPath, true)
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

func (s *httpdServer) setupRESTAPIRoutes() {
	if s.enableRESTAPI {
		if !s.binding.isAdminTokenEndpointDisabled() {
			s.router.Get(tokenPath, s.getToken)
			s.router.Post(adminPath+"/{username}/forgot-password", forgotAdminPassword)
			s.router.Post(adminPath+"/{username}/reset-password", resetAdminPassword)
		}

		s.router.Group(func(router chi.Router) {
			router.Use(checkNodeToken(s.tokenAuth))
			if !s.binding.isAdminAPIKeyAuthDisabled() {
				router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeAdmin))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
			router.Use(jwtAuthenticatorAPI)

			router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, version.Get())
			})

			router.With(forbidAPIKeyAuthentication).Get(logoutPath, s.logout)
			router.With(forbidAPIKeyAuthentication).Get(adminProfilePath, getAdminProfile)
			router.With(forbidAPIKeyAuthentication, s.checkAuthRequirements).Put(adminProfilePath, updateAdminProfile)
			router.With(forbidAPIKeyAuthentication).Put(adminPwdPath, changeAdminPassword)
			// admin TOTP APIs
			router.With(forbidAPIKeyAuthentication).Get(adminTOTPConfigsPath, getTOTPConfigs)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPGeneratePath, generateTOTPSecret)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPValidatePath, validateTOTPPasscode)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPSavePath, saveTOTPConfig)
			router.With(forbidAPIKeyAuthentication).Get(admin2FARecoveryCodesPath, getRecoveryCodes)
			router.With(forbidAPIKeyAuthentication).Post(admin2FARecoveryCodesPath, generateRecoveryCodes)

			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Get(apiKeysPath, getAPIKeys)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Post(apiKeysPath, addAPIKey)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Get(apiKeysPath+"/{id}", getAPIKeyByID)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Put(apiKeysPath+"/{id}", updateAPIKey)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Delete(apiKeysPath+"/{id}", deleteAPIKey)

			router.Group(func(router chi.Router) {
				router.Use(s.checkAuthRequirements)

				router.With(s.checkPerms(dataprovider.PermAdminViewServerStatus)).
					Get(serverStatusPath, func(w http.ResponseWriter, r *http.Request) {
						r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
						render.JSON(w, r, getServicesStatus())
					})

				router.With(s.checkPerms(dataprovider.PermAdminViewConnections)).Get(activeConnectionsPath, getActiveConnections)
				router.With(s.checkPerms(dataprovider.PermAdminCloseConnections)).
					Delete(activeConnectionsPath+"/{connectionID}", handleCloseConnection)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/users/scans", getUsersQuotaScans)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/users/{username}/scan", startUserQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/folders/scans", getFoldersQuotaScans)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/folders/{name}/scan", startFolderQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers)).Get(userPath, getUsers)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers)).Post(userPath, addUser)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers)).Get(userPath+"/{username}", getUserByUsername) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}", updateUser)
				router.With(s.checkPerms(dataprovider.PermAdminDeleteUsers)).Delete(userPath+"/{username}", deleteUser)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA)).Put(userPath+"/{username}/2fa/disable", disableUser2FA) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Get(folderPath, getFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Get(folderPath+"/{name}", getFolderByName) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(folderPath, addFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Put(folderPath+"/{name}", updateFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Delete(folderPath+"/{name}", deleteFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Get(groupPath, getGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Get(groupPath+"/{name}", getGroupByName)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(groupPath, addGroup)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Put(groupPath+"/{name}", updateGroup)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Delete(groupPath+"/{name}", deleteGroup)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(dumpDataPath, dumpData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(loadDataPath, loadData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(loadDataPath, loadDataFromRequest)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/usage",
					updateUserQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/transfer-usage",
					updateUserTransferQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/folders/{name}/usage",
					updateFolderQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(defenderHosts, getDefenderHosts)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(defenderHosts+"/{id}", getDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminManageDefender)).Delete(defenderHosts+"/{id}", deleteDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(adminPath, getAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(adminPath, addAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(adminPath+"/{username}", getAdminByUsername)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(adminPath+"/{username}", updateAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(adminPath+"/{username}", deleteAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA)).Put(adminPath+"/{username}/2fa/disable", disableAdmin2FA)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(retentionChecksPath, getRetentionChecks)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(retentionBasePath+"/{username}/check",
					startRetentionCheck)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(fsEventsPath, searchFsEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(providerEventsPath, searchProviderEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(logEventsPath, searchLogEvents)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventActionsPath, getEventActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventActionsPath+"/{name}", getEventActionByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventActionsPath, addEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(eventActionsPath+"/{name}", updateEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(eventActionsPath+"/{name}", deleteEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventRulesPath, getEventRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventRulesPath+"/{name}", getEventRuleByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventRulesPath, addEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(eventRulesPath+"/{name}", updateEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(eventRulesPath+"/{name}", deleteEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventRulesPath+"/run/{name}", runOnDemandRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(rolesPath, getRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(rolesPath, addRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(rolesPath+"/{name}", getRoleByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(rolesPath+"/{name}", updateRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(rolesPath+"/{name}", deleteRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler).Get(ipListsPath+"/{type}", getIPListEntries) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(ipListsPath+"/{type}", addIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(ipListsPath+"/{type}/{ipornet}", getIPListEntry) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(ipListsPath+"/{type}/{ipornet}", updateIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(ipListsPath+"/{type}/{ipornet}", deleteIPListEntry)
			})
		})

		// share API available to external users
		s.router.Get(sharesPath+"/{id}", s.downloadFromShare)
		s.router.Post(sharesPath+"/{id}", s.uploadFilesToShare)
		s.router.Post(sharesPath+"/{id}/{name}", s.uploadFileToShare)
		s.router.With(compressor.Handler).Get(sharesPath+"/{id}/dirs", s.readBrowsableShareContents)
		s.router.Get(sharesPath+"/{id}/files", s.downloadBrowsableSharedFile)

		if !s.binding.isUserTokenEndpointDisabled() {
			s.router.Get(userTokenPath, s.getUserToken)
			s.router.Post(userPath+"/{username}/forgot-password", forgotUserPassword)
			s.router.Post(userPath+"/{username}/reset-password", resetUserPassword)
		}

		s.router.Group(func(router chi.Router) {
			if !s.binding.isUserAPIKeyAuthDisabled() {
				router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeUser))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
			router.Use(jwtAuthenticatorAPIUser)

			router.With(forbidAPIKeyAuthentication).Get(userLogoutPath, s.logout)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Put(userPwdPath, changeUserPassword)
			router.With(forbidAPIKeyAuthentication).Get(userProfilePath, getUserProfile)
			router.With(forbidAPIKeyAuthentication, s.checkAuthRequirements).Put(userProfilePath, updateUserProfile)
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

			router.With(s.checkAuthRequirements, compressor.Handler).Get(userDirsPath, readUserFolder)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userDirsPath, createUserDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userDirsPath, renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Delete(userDirsPath, deleteUserDir)
			router.With(s.checkAuthRequirements).Get(userFilesPath, getUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFilesPath, uploadUserFiles)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userFilesPath, renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Delete(userFilesPath, deleteUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFileActionsPath+"/move", renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFileActionsPath+"/copy", copyUserFsEntry)
			router.With(s.checkAuthRequirements).Post(userStreamZipPath, getUserFilesAsZipStream)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Get(userSharesPath, getShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(userSharesPath, addShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Get(userSharesPath+"/{id}", getShareByID)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Put(userSharesPath+"/{id}", updateShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Delete(userSharesPath+"/{id}", deleteShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userUploadFilePath, uploadUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userFilesDirsMetadataPath, setFileDirMetadata)
		})

		if s.renderOpenAPI {
			s.router.Group(func(router chi.Router) {
				router.Use(cleanCacheControlMiddleware)
				router.Use(compressor.Handler)
				serveStaticDir(router, webOpenAPIPath, s.openAPIPath, false)
			})
		}
	}
}

func (s *httpdServer) setupWebClientRoutes() {
	if s.enableWebClient {
		s.router.Get(webBaseClientPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
			http.Redirect(w, r, webClientLoginPath, http.StatusFound)
		})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webclient/logo.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebClientLogo())
			})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webclient/favicon.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebClientFavicon())
			})
		s.router.Get(webClientLoginPath, s.handleClientWebLogin)
		if s.binding.OIDC.isEnabled() && !s.binding.isWebClientOIDCLoginDisabled() {
			s.router.Get(webClientOIDCLoginPath, s.handleWebClientOIDCLogin)
		}
		if !s.binding.isWebClientLoginFormDisabled() {
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webClientLoginPath, s.handleWebClientLoginPost)
			s.router.Get(webClientForgotPwdPath, s.handleWebClientForgotPwd)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webClientForgotPwdPath, s.handleWebClientForgotPwdPost)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Get(webClientResetPwdPath, s.handleWebClientPasswordReset)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webClientResetPwdPath, s.handleWebClientPasswordResetPost)
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
		}
		// share routes available to external users
		s.router.Get(webClientPubSharesPath+"/{id}/login", s.handleClientShareLoginGet)
		s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
			Post(webClientPubSharesPath+"/{id}/login", s.handleClientShareLoginPost)
		s.router.Get(webClientPubSharesPath+"/{id}/logout", s.handleClientShareLogout)
		s.router.Get(webClientPubSharesPath+"/{id}", s.downloadFromShare)
		s.router.Post(webClientPubSharesPath+"/{id}/partial", s.handleClientSharePartialDownload)
		s.router.Get(webClientPubSharesPath+"/{id}/browse", s.handleShareGetFiles)
		s.router.Post(webClientPubSharesPath+"/{id}/browse/exist", s.handleClientShareCheckExist)
		s.router.Get(webClientPubSharesPath+"/{id}/download", s.handleClientSharedFile)
		s.router.Get(webClientPubSharesPath+"/{id}/upload", s.handleClientUploadToShare)
		s.router.With(compressor.Handler).Get(webClientPubSharesPath+"/{id}/dirs", s.handleShareGetDirContents)
		s.router.Post(webClientPubSharesPath+"/{id}", s.uploadFilesToShare)
		s.router.Post(webClientPubSharesPath+"/{id}/{name}", s.uploadFileToShare)
		s.router.Get(webClientPubSharesPath+"/{id}/viewpdf", s.handleShareViewPDF)
		s.router.Get(webClientPubSharesPath+"/{id}/getpdf", s.handleShareGetPDF)

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebClient))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, oidcTokenFromContext, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebClient)

			router.Get(webClientLogoutPath, s.handleWebClientLogout)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientFilesPath, s.handleClientGetFiles)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientViewPDFPath, s.handleClientViewPDF)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientGetPDFPath, s.handleClientGetPDF)
			router.With(s.checkAuthRequirements, s.refreshCookie, s.verifyCSRFHeader).Get(webClientFilePath, getUserFile)
			router.With(s.checkAuthRequirements, s.refreshCookie, s.verifyCSRFHeader).Get(webClientTasksPath+"/{id}",
				getWebTask)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFilePath, uploadUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientExistPath, s.handleClientCheckExist)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientEditFilePath, s.handleClientEditFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Delete(webClientFilesPath, deleteUserFile)
			router.With(s.checkAuthRequirements, compressor.Handler, s.refreshCookie).
				Get(webClientDirsPath, s.handleClientGetDirContents)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientDirsPath, createUserDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Delete(webClientDirsPath, taskDeleteDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFileActionsPath+"/move", taskRenameFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFileActionsPath+"/copy", taskCopyFsEntry)
			router.With(s.checkAuthRequirements, s.refreshCookie).
				Post(webClientDownloadZipPath, s.handleWebClientDownloadZip)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientPingPath, handlePingRequest)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientProfilePath,
				s.handleClientGetProfile)
			router.With(s.checkAuthRequirements).Post(webClientProfilePath, s.handleWebClientProfilePost)
			router.With(s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Get(webChangeClientPwdPath, s.handleWebClientChangePwd)
			router.With(s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Post(webChangeClientPwdPath, s.handleWebClientChangePwdPost)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath, s.handleWebClientMFA)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath+"/qrcode", getQRCode)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPGeneratePath, generateTOTPSecret)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPValidatePath, validateTOTPPasscode)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPSavePath, saveTOTPConfig)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader, s.refreshCookie).
				Get(webClientRecoveryCodesPath, getRecoveryCodes)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientRecoveryCodesPath, generateRecoveryCodes)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), compressor.Handler, s.refreshCookie).
				Get(webClientSharesPath+jsonAPISuffix, getAllShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharesPath, s.handleClientGetShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath, s.handleClientAddShareGet)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath, s.handleClientAddSharePost)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath+"/{id}", s.handleClientUpdateShareGet)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath+"/{id}", s.handleClientUpdateSharePost)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.verifyCSRFHeader).
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
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webadmin/logo.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebAdminLogo())
			})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webadmin/favicon.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebAdminFavicon())
			})
		s.router.Get(webAdminLoginPath, s.handleWebAdminLogin)
		if s.binding.OIDC.hasRoles() && !s.binding.isWebAdminOIDCLoginDisabled() {
			s.router.Get(webAdminOIDCLoginPath, s.handleWebAdminOIDCLogin)
		}
		s.router.Get(webOAuth2RedirectPath, s.handleOAuth2TokenRedirect)
		s.router.Get(webAdminSetupPath, s.handleWebAdminSetupGet)
		s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
			Post(webAdminSetupPath, s.handleWebAdminSetupPost)
		if !s.binding.isWebAdminLoginFormDisabled() {
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webAdminLoginPath, s.handleWebAdminLoginPost)
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
			s.router.Get(webAdminForgotPwdPath, s.handleWebAdminForgotPwd)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webAdminForgotPwdPath, s.handleWebAdminForgotPwdPost)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Get(webAdminResetPwdPath, s.handleWebAdminPasswordReset)
			s.router.With(jwtauth.Verify(s.csrfTokenAuth, jwtauth.TokenFromCookie)).
				Post(webAdminResetPwdPath, s.handleWebAdminPasswordResetPost)
		}

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebAdmin))
			}
			router.Use(jwtauth.Verify(s.tokenAuth, oidcTokenFromContext, jwtauth.TokenFromCookie))
			router.Use(jwtAuthenticatorWebAdmin)

			router.Get(webLogoutPath, s.handleWebAdminLogout)
			router.With(s.refreshCookie, s.checkAuthRequirements, s.requireBuiltinLogin).Get(
				webAdminProfilePath, s.handleWebAdminProfile)
			router.With(s.checkAuthRequirements, s.requireBuiltinLogin).Post(webAdminProfilePath, s.handleWebAdminProfilePost)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webChangeAdminPwdPath, s.handleWebAdminChangePwd)
			router.With(s.requireBuiltinLogin).Post(webChangeAdminPwdPath, s.handleWebAdminChangePwdPost)

			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminMFAPath, s.handleWebAdminMFA)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminMFAPath+"/qrcode", getQRCode)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPGeneratePath, generateTOTPSecret)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPValidatePath, validateTOTPPasscode)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPSavePath, saveTOTPConfig)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin, s.refreshCookie).Get(webAdminRecoveryCodesPath,
				getRecoveryCodes)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminRecoveryCodesPath, generateRecoveryCodes)

			router.Group(func(router chi.Router) {
				router.Use(s.checkAuthRequirements)

				router.With(s.checkPerms(dataprovider.PermAdminViewUsers), s.refreshCookie).
					Get(webUsersPath, s.handleGetWebUsers)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers), compressor.Handler, s.refreshCookie).
					Get(webUsersPath+jsonAPISuffix, getAllUsers)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers), s.refreshCookie).
					Get(webUserPath, s.handleWebAddUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers), s.refreshCookie).
					Get(webUserPath+"/{username}", s.handleWebUpdateUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers)).Post(webUserPath, s.handleWebAddUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Post(webUserPath+"/{username}",
					s.handleWebUpdateUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupsPath, s.handleWebGetGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), compressor.Handler, s.refreshCookie).
					Get(webGroupsPath+jsonAPISuffix, getAllGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupPath, s.handleWebAddGroupGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(webGroupPath, s.handleWebAddGroupPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupPath+"/{name}", s.handleWebUpdateGroupGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(webGroupPath+"/{name}",
					s.handleWebUpdateGroupPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.verifyCSRFHeader).
					Delete(webGroupPath+"/{name}", deleteGroup)
				router.With(s.checkPerms(dataprovider.PermAdminViewConnections), s.refreshCookie).
					Get(webConnectionsPath, s.handleWebGetConnections)
				router.With(s.checkPerms(dataprovider.PermAdminViewConnections), s.refreshCookie).
					Get(webConnectionsPath+jsonAPISuffix, getActiveConnections)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFoldersPath, s.handleWebGetFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), compressor.Handler, s.refreshCookie).
					Get(webFoldersPath+jsonAPISuffix, getAllFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFolderPath, s.handleWebAddFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webFolderPath, s.handleWebAddFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminViewServerStatus), s.refreshCookie).
					Get(webStatusPath, s.handleWebGetStatus)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminsPath, s.handleGetWebAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminsPath+jsonAPISuffix, getAllAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminPath, s.handleWebAddAdminGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminPath+"/{username}", s.handleWebUpdateAdminGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminPath, s.handleWebAddAdminPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminPath+"/{username}",
					s.handleWebUpdateAdminPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminPath+"/{username}", deleteAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA), s.verifyCSRFHeader).
					Put(webAdminPath+"/{username}/2fa/disable", disableAdmin2FA)
				router.With(s.checkPerms(dataprovider.PermAdminCloseConnections), s.verifyCSRFHeader).
					Delete(webConnectionsPath+"/{connectionID}", handleCloseConnection)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFolderPath+"/{name}", s.handleWebUpdateFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webFolderPath+"/{name}",
					s.handleWebUpdateFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.verifyCSRFHeader).
					Delete(webFolderPath+"/{name}", deleteFolder)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans), s.verifyCSRFHeader).
					Post(webScanVFolderPath+"/{name}", startFolderQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminDeleteUsers), s.verifyCSRFHeader).
					Delete(webUserPath+"/{username}", deleteUser)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA), s.verifyCSRFHeader).
					Put(webUserPath+"/{username}/2fa/disable", disableUser2FA)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans), s.verifyCSRFHeader).
					Post(webQuotaScanPath+"/{username}", startUserQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webMaintenancePath, s.handleWebMaintenance)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webBackupPath, dumpData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webRestorePath, s.handleWebRestore)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers, dataprovider.PermAdminChangeUsers), s.refreshCookie).
					Get(webTemplateUser, s.handleWebTemplateUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers, dataprovider.PermAdminChangeUsers)).
					Post(webTemplateUser, s.handleWebTemplateUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webTemplateFolder, s.handleWebTemplateFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webTemplateFolder, s.handleWebTemplateFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(webDefenderPath, s.handleWebDefenderPage)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(webDefenderHostsPath, getDefenderHosts)
				router.With(s.checkPerms(dataprovider.PermAdminManageDefender), s.verifyCSRFHeader).
					Delete(webDefenderHostsPath+"/{id}", deleteDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminEventActionsPath+jsonAPISuffix, getAllActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionsPath, s.handleWebGetEventActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionPath, s.handleWebAddEventActionGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventActionPath,
					s.handleWebAddEventActionPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionPath+"/{name}", s.handleWebUpdateEventActionGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventActionPath+"/{name}",
					s.handleWebUpdateEventActionPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminEventActionPath+"/{name}", deleteEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminEventRulesPath+jsonAPISuffix, getAllRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulesPath, s.handleWebGetEventRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulePath, s.handleWebAddEventRuleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventRulePath,
					s.handleWebAddEventRulePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulePath+"/{name}", s.handleWebUpdateEventRuleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventRulePath+"/{name}",
					s.handleWebUpdateEventRulePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminEventRulePath+"/{name}", deleteEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Post(webAdminEventRulePath+"/run/{name}", runOnDemandRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolesPath, s.handleWebGetRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminRolesPath+jsonAPISuffix, getAllRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolePath, s.handleWebAddRoleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminRolePath, s.handleWebAddRolePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolePath+"/{name}", s.handleWebUpdateRoleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminRolePath+"/{name}",
					s.handleWebUpdateRolePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminRolePath+"/{name}", deleteRole)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), s.refreshCookie).Get(webEventsPath,
					s.handleWebGetEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsFsSearchPath, searchFsEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsProviderSearchPath, searchProviderEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsLogSearchPath, searchLogEvents)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webIPListsPath, s.handleWebIPListsPage)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webIPListsPath+"/{type}", getIPListEntries)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webIPListPath+"/{type}",
					s.handleWebAddIPListEntryGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webIPListPath+"/{type}",
					s.handleWebAddIPListEntryPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webIPListPath+"/{type}/{ipornet}",
					s.handleWebUpdateIPListEntryGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webIPListPath+"/{type}/{ipornet}",
					s.handleWebUpdateIPListEntryPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webIPListPath+"/{type}/{ipornet}", deleteIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webConfigsPath, s.handleWebConfigs)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webConfigsPath, s.handleWebConfigsPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader, s.refreshCookie).
					Post(webConfigsPath+"/smtp/test", testSMTPConfig)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader, s.refreshCookie).
					Post(webOAuth2TokenPath, s.handleSMTPOAuth2TokenRequestPost)
			})
		})
	}
}
