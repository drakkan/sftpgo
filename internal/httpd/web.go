// Copyright (C) 2019-2023 Nicola Murino
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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/unrolled/secure"

	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	pageMFATitle               = "Two-factor authentication"
	page400Title               = "Bad request"
	page403Title               = "Forbidden"
	page404Title               = "Not found"
	page404Body                = "The page you are looking for does not exist."
	page500Title               = "Internal Server Error"
	page500Body                = "The server is unable to fulfill your request."
	pageTwoFactorTitle         = "Two-Factor authentication"
	pageTwoFactorRecoveryTitle = "Two-Factor recovery"
	webDateTimeFormat          = "2006-01-02 15:04:05" // YYYY-MM-DD HH:MM:SS
	redactedSecret             = "[**redacted**]"
	csrfFormToken              = "_form_token"
	csrfHeaderToken            = "X-CSRF-TOKEN"
	templateCommonDir          = "common"
	templateTwoFactor          = "twofactor.html"
	templateTwoFactorRecovery  = "twofactor-recovery.html"
	templateForgotPassword     = "forgot-password.html"
	templateResetPassword      = "reset-password.html"
	templateCommonCSS          = "sftpgo.css"
	templateCommonBase         = "base.html"
	templateCommonBaseLogin    = "baselogin.html"
	templateCommonLogin        = "login.html"
)

var (
	errInvalidTokenClaims = errors.New("invalid token claims")
)

type commonBasePage struct {
	CSPNonce  string
	StaticURL string
	Version   string
}

type loginPage struct {
	commonBasePage
	CurrentURL     string
	Error          *util.I18nError
	CSRFToken      string
	AltLoginURL    string
	AltLoginName   string
	ForgotPwdURL   string
	OpenIDLoginURL string
	Title          string
	Branding       UIBranding
	FormDisabled   bool
}

type twoFactorPage struct {
	commonBasePage
	CurrentURL  string
	Error       *util.I18nError
	CSRFToken   string
	RecoveryURL string
	Title       string
	Branding    UIBranding
}

type forgotPwdPage struct {
	commonBasePage
	CurrentURL string
	Error      *util.I18nError
	CSRFToken  string
	LoginURL   string
	Title      string
	Branding   UIBranding
}

type resetPwdPage struct {
	commonBasePage
	CurrentURL string
	Error      *util.I18nError
	CSRFToken  string
	LoginURL   string
	Title      string
	Branding   UIBranding
}

func getSliceFromDelimitedValues(values, delimiter string) []string {
	result := []string{}
	for _, v := range strings.Split(values, delimiter) {
		cleaned := strings.TrimSpace(v)
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	return result
}

func hasPrefixAndSuffix(key, prefix, suffix string) bool {
	return strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix)
}

func getCommonBasePage(r *http.Request) commonBasePage {
	v := version.Get()
	return commonBasePage{
		CSPNonce:  secure.CSPNonce(r.Context()),
		StaticURL: webStaticFilesPath,
		Version:   fmt.Sprintf("v%v-%v", v.Version, v.CommitHash),
	}
}

func i18nListDirMsg(status int) string {
	if status == http.StatusForbidden {
		return util.I18nErrorDirList403
	}
	return util.I18nErrorDirListGeneric
}

func i18nFsMsg(status int) string {
	if status == http.StatusForbidden {
		return util.I18nError403Message
	}
	return util.I18nErrorFsGeneric
}

func getI18NErrorString(err error, fallback string) string {
	var errI18n *util.I18nError
	if errors.As(err, &errI18n) {
		return errI18n.Message
	}
	return fallback
}

func handlePingRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	render.PlainText(w, r, "PONG")
}
