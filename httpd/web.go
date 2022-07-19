// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"strings"
)

const (
	pageMFATitle              = "Two-factor authentication"
	page400Title              = "Bad request"
	page403Title              = "Forbidden"
	page404Title              = "Not found"
	page404Body               = "The page you are looking for does not exist."
	page500Title              = "Internal Server Error"
	page500Body               = "The server is unable to fulfill your request."
	webDateTimeFormat         = "2006-01-02 15:04:05" // YYYY-MM-DD HH:MM:SS
	redactedSecret            = "[**redacted**]"
	csrfFormToken             = "_form_token"
	csrfHeaderToken           = "X-CSRF-TOKEN"
	templateCommonDir         = "common"
	templateTwoFactor         = "twofactor.html"
	templateTwoFactorRecovery = "twofactor-recovery.html"
	templateForgotPassword    = "forgot-password.html"
	templateResetPassword     = "reset-password.html"
	templateCommonCSS         = "sftpgo.css"
)

type loginPage struct {
	CurrentURL     string
	Version        string
	Error          string
	CSRFToken      string
	StaticURL      string
	AltLoginURL    string
	AltLoginName   string
	ForgotPwdURL   string
	OpenIDLoginURL string
	Branding       UIBranding
	FormDisabled   bool
}

type twoFactorPage struct {
	CurrentURL  string
	Version     string
	Error       string
	CSRFToken   string
	StaticURL   string
	RecoveryURL string
	Branding    UIBranding
}

type forgotPwdPage struct {
	CurrentURL string
	Error      string
	CSRFToken  string
	StaticURL  string
	Title      string
	Branding   UIBranding
}

type resetPwdPage struct {
	CurrentURL string
	Error      string
	CSRFToken  string
	StaticURL  string
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
