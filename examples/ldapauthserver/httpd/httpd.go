package httpd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/drakkan/sftpgo/ldapauthserver/config"
	"github.com/drakkan/sftpgo/ldapauthserver/logger"
	"github.com/drakkan/sftpgo/ldapauthserver/utils"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

const (
	logSender      = "httpd"
	versionPath    = "/api/v1/version"
	checkAuthPath  = "/api/v1/check_auth"
	maxRequestSize = 1 << 18 // 256KB
)

var (
	ldapConfig config.LDAPConfig
	httpAuth   httpAuthProvider
	certMgr    *certManager
	rootCAs    *x509.CertPool
)

// StartHTTPServer initializes and starts the HTTP Server
func StartHTTPServer(configDir string, httpConfig config.HTTPDConfig) error {
	var err error
	authUserFile := getConfigPath(httpConfig.AuthUserFile, configDir)
	httpAuth, err = newBasicAuthProvider(authUserFile)
	if err != nil {
		return err
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(logger.NewStructuredLogger(logger.GetLogger()))
	router.Use(middleware.Recoverer)

	router.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}))

	router.MethodNotAllowed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendAPIResponse(w, r, nil, "Method not allowed", http.StatusMethodNotAllowed)
	}))

	router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, utils.GetAppVersion())
	})

	router.Group(func(router chi.Router) {
		router.Use(checkAuth)

		router.Post(checkAuthPath, checkSFTPGoUserAuth)
	})

	ldapConfig = config.GetLDAPConfig()
	loadCACerts(configDir)

	certificateFile := getConfigPath(httpConfig.CertificateFile, configDir)
	certificateKeyFile := getConfigPath(httpConfig.CertificateKeyFile, configDir)

	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", httpConfig.BindAddress, httpConfig.BindPort),
		Handler:        router,
		ReadTimeout:    70 * time.Second,
		WriteTimeout:   70 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}
	if len(certificateFile) > 0 && len(certificateKeyFile) > 0 {
		certMgr, err = newCertManager(certificateFile, certificateKeyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(),
			MinVersion:     tls.VersionTLS12,
		}
		httpServer.TLSConfig = config
		return httpServer.ListenAndServeTLS("", "")
	}
	return httpServer.ListenAndServe()
}

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if err != nil {
		errorString = err.Error()
	}
	resp := apiResponse{
		Error:      errorString,
		Message:    message,
		HTTPStatus: code,
	}
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, code)
	render.JSON(w, r.WithContext(ctx), resp)
}

func loadCACerts(configDir string) error {
	var err error
	rootCAs, err = x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	for _, ca := range ldapConfig.CACertificates {
		caPath := getConfigPath(ca, configDir)
		certs, err := os.ReadFile(caPath)
		if err != nil {
			logger.Warn(logSender, "", "error loading ca cert %#v: %v", caPath, err)
			return err
		}
		if !rootCAs.AppendCertsFromPEM(certs) {
			logger.Warn(logSender, "", "unable to add ca cert %#v", caPath)
		} else {
			logger.Debug(logSender, "", "ca cert %#v added to the trusted certificates", caPath)
		}
	}

	return nil
}

// ReloadTLSCertificate reloads the TLS certificate and key from the configured paths
func ReloadTLSCertificate() {
	if certMgr != nil {
		certMgr.loadCertificate()
	}
}

func getConfigPath(name, configDir string) string {
	if !utils.IsFileInputValid(name) {
		return ""
	}
	if len(name) > 0 && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}
