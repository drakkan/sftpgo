package httpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

var compressor = middleware.NewCompressor(5)

type httpdServer struct {
	binding         Binding
	staticFilesPath string
	enableWebAdmin  bool
	router          *chi.Mux
	tokenAuth       *jwtauth.JWTAuth
}

func newHttpdServer(b Binding, staticFilesPath string, enableWebAdmin bool) *httpdServer {
	return &httpdServer{
		binding:         b,
		staticFilesPath: staticFilesPath,
		enableWebAdmin:  enableWebAdmin && b.EnableWebAdmin,
	}
}

func (s *httpdServer) listenAndServe() error {
	s.initializeRouter()
	httpServer := &http.Server{
		Handler:        s.router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
		ErrorLog:       log.New(&logger.StdLoggerWrapper{Sender: logSender}, "", 0),
	}
	if certMgr != nil && s.binding.EnableHTTPS {
		config := &tls.Config{
			GetCertificate:           certMgr.GetCertificateFunc(),
			MinVersion:               tls.VersionTLS12,
			CipherSuites:             utils.GetTLSCiphersFromNames(s.binding.TLSCipherSuites),
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
		return utils.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, true, logSender)
	}
	return utils.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, false, logSender)
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

func (s *httpdServer) handleWebLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if err := r.ParseForm(); err != nil {
		renderLoginPage(w, err.Error())
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		renderLoginPage(w, "Invalid credentials")
		return
	}
	if err := verifyCSRFToken(r.Form.Get(csrfFormToken)); err != nil {
		renderLoginPage(w, err.Error())
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, utils.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		renderLoginPage(w, err.Error())
		return
	}
	if connAddr, ok := r.Context().Value(connAddrKey).(string); ok {
		if connAddr != r.RemoteAddr {
			if !admin.CanLoginFromIP(utils.GetIPFromRemoteAddress(connAddr)) {
				renderLoginPage(w, fmt.Sprintf("Login from IP %v is not allowed", connAddr))
				return
			}
		}
	}
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}

	err = c.createAndSetCookie(w, r, s.tokenAuth)
	if err != nil {
		renderLoginPage(w, err.Error())
		return
	}

	http.Redirect(w, r, webUsersPath, http.StatusFound)
}

func (s *httpdServer) logout(w http.ResponseWriter, r *http.Request) {
	invalidateToken(r)
	sendAPIResponse(w, r, nil, "Your token has been invalidated", http.StatusOK)
}

func (s *httpdServer) getToken(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, utils.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	s.checkAddrAndSendToken(w, r, admin)
}

func (s *httpdServer) checkAddrAndSendToken(w http.ResponseWriter, r *http.Request, admin dataprovider.Admin) {
	if connAddr, ok := r.Context().Value(connAddrKey).(string); ok {
		if connAddr != r.RemoteAddr {
			if !admin.CanLoginFromIP(utils.GetIPFromRemoteAddress(connAddr)) {
				sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
	}

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
	if time.Until(token.Expiration()) > tokenRefreshMin {
		return
	}
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
	if !admin.CanLoginFromIP(utils.GetIPFromRemoteAddress(r.RemoteAddr)) {
		logger.Debug(logSender, "", "admin %#v cannot login from %v, unable to refresh cookie", admin.Username, r.RemoteAddr)
		return
	}
	if connAddr, ok := r.Context().Value(connAddrKey).(string); ok {
		if connAddr != r.RemoteAddr {
			if !admin.CanLoginFromIP(utils.GetIPFromRemoteAddress(connAddr)) {
				logger.Debug(logSender, "", "admin %#v cannot login from %v, unable to refresh cookie",
					admin.Username, connAddr)
				return
			}
		}
	}
	logger.Debug(logSender, "", "cookie refreshed for admin %#v", admin.Username)
	tokenClaims.createAndSetCookie(w, r, s.tokenAuth) //nolint:errcheck
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

func (s *httpdServer) initializeRouter() {
	s.tokenAuth = jwtauth.New("HS256", utils.GenerateRandomBytes(32), nil)
	s.router = chi.NewRouter()

	s.router.Use(saveConnectionAddress)
	s.router.Use(middleware.GetHead)

	s.router.Group(func(r chi.Router) {
		r.Get(healthzPath, func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, "ok")
		})
	})

	s.router.Group(func(router chi.Router) {
		router.Use(middleware.RequestID)
		router.Use(middleware.RealIP)
		router.Use(logger.NewStructuredLogger(logger.GetLogger()))
		router.Use(middleware.Recoverer)

		router.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.enableWebAdmin && isWebAdminRequest(r) {
				r = s.updateContextFromCookie(r)
				renderNotFoundPage(w, r, nil)
				return
			}
			sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
		}))

		router.Get(tokenPath, s.getToken)

		router.Group(func(router chi.Router) {
			router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromHeader))
			router.Use(jwtAuthenticator)

			router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
				render.JSON(w, r, version.Get())
			})

			router.Get(logoutPath, s.logout)
			router.Put(adminPwdPath, changeAdminPassword)

			router.With(checkPerm(dataprovider.PermAdminViewServerStatus)).
				Get(serverStatusPath, func(w http.ResponseWriter, r *http.Request) {
					render.JSON(w, r, getServicesStatus())
				})

			router.With(checkPerm(dataprovider.PermAdminViewConnections)).
				Get(activeConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
					render.JSON(w, r, common.Connections.GetStats())
				})

			router.With(checkPerm(dataprovider.PermAdminCloseConnections)).
				Delete(activeConnectionsPath+"/{connectionID}", handleCloseConnection)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanPath, getQuotaScans)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanPath, startQuotaScan)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Get(quotaScanVFolderPath, getVFolderQuotaScans)
			router.With(checkPerm(dataprovider.PermAdminQuotaScans)).Post(quotaScanVFolderPath, startVFolderQuotaScan)
			router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath, getUsers)
			router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(userPath, addUser)
			router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(userPath+"/{username}", getUserByUsername)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}", updateUser)
			router.With(checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(userPath+"/{username}", deleteUser)
			router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath, getFolders)
			router.With(checkPerm(dataprovider.PermAdminViewUsers)).Get(folderPath+"/{name}", getFolderByName)
			router.With(checkPerm(dataprovider.PermAdminAddUsers)).Post(folderPath, addFolder)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(folderPath+"/{name}", updateFolder)
			router.With(checkPerm(dataprovider.PermAdminDeleteUsers)).Delete(folderPath+"/{name}", deleteFolder)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(dumpDataPath, dumpData)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(loadDataPath, loadData)
			router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(loadDataPath, loadDataFromRequest)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateUsedQuotaPath, updateUserQuotaUsage)
			router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Put(updateFolderUsedQuotaPath, updateVFolderQuotaUsage)
			router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderBanTime, getBanTime)
			router.With(checkPerm(dataprovider.PermAdminViewDefender)).Get(defenderScore, getScore)
			router.With(checkPerm(dataprovider.PermAdminManageDefender)).Post(defenderUnban, unban)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath, getAdmins)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Post(adminPath, addAdmin)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Get(adminPath+"/{username}", getAdminByUsername)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Put(adminPath+"/{username}", updateAdmin)
			router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Delete(adminPath+"/{username}", deleteAdmin)
		})

		if s.enableWebAdmin {
			router.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, webLoginPath, http.StatusMovedPermanently)
			})

			router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, webLoginPath, http.StatusMovedPermanently)
			})

			router.Get(webLoginPath, handleWebLogin)
			router.Post(webLoginPath, s.handleWebLoginPost)

			router.Group(func(router chi.Router) {
				router.Use(jwtauth.Verify(s.tokenAuth, jwtauth.TokenFromCookie))
				router.Use(jwtAuthenticatorWeb)

				router.Get(webLogoutPath, handleWebLogout)
				router.With(s.refreshCookie).Get(webChangeAdminPwdPath, handleWebAdminChangePwd)
				router.Post(webChangeAdminPwdPath, handleWebAdminChangePwdPost)
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
				router.With(checkPerm(dataprovider.PermAdminManageAdmins)).Post(webAdminPath+"/{username}", handleWebUpdateAdminPost)
				router.With(checkPerm(dataprovider.PermAdminManageAdmins), verifyCSRFHeader).
					Delete(webAdminPath+"/{username}", deleteAdmin)
				router.With(checkPerm(dataprovider.PermAdminCloseConnections), verifyCSRFHeader).
					Delete(webConnectionsPath+"/{connectionID}", handleCloseConnection)
				router.With(checkPerm(dataprovider.PermAdminChangeUsers), s.refreshCookie).
					Get(webFolderPath+"/{name}", handleWebUpdateFolderGet)
				router.With(checkPerm(dataprovider.PermAdminChangeUsers)).Post(webFolderPath+"/{name}", handleWebUpdateFolderPost)
				router.With(checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
					Delete(webFolderPath+"/{name}", deleteFolder)
				router.With(checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
					Post(webScanVFolderPath, startVFolderQuotaScan)
				router.With(checkPerm(dataprovider.PermAdminDeleteUsers), verifyCSRFHeader).
					Delete(webUserPath+"/{username}", deleteUser)
				router.With(checkPerm(dataprovider.PermAdminQuotaScans), verifyCSRFHeader).
					Post(webQuotaScanPath, startQuotaScan)
				router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(webMaintenancePath, handleWebMaintenance)
				router.With(checkPerm(dataprovider.PermAdminManageSystem)).Get(webBackupPath, dumpData)
				router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webRestorePath, handleWebRestore)
				router.With(checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
					Get(webTemplateUser, handleWebTemplateUserGet)
				router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateUser, handleWebTemplateUserPost)
				router.With(checkPerm(dataprovider.PermAdminManageSystem), s.refreshCookie).
					Get(webTemplateFolder, handleWebTemplateFolderGet)
				router.With(checkPerm(dataprovider.PermAdminManageSystem)).Post(webTemplateFolder, handleWebTemplateFolderPost)
			})

			router.Group(func(router chi.Router) {
				router.Use(compressor.Handler)
				fileServer(router, webStaticFilesPath, http.Dir(s.staticFilesPath))
			})
		}
	})
}
