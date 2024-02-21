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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	errRecoveryCodeForbidden = errors.New("recovery codes are not available with two-factor authentication disabled")
)

type generateTOTPRequest struct {
	ConfigName string `json:"config_name"`
}

type generateTOTPResponse struct {
	ConfigName string `json:"config_name"`
	Issuer     string `json:"issuer"`
	Secret     string `json:"secret"`
	URL        string `json:"url"`
	QRCode     []byte `json:"qr_code"`
}

type validateTOTPRequest struct {
	ConfigName string `json:"config_name"`
	Passcode   string `json:"passcode"`
	Secret     string `json:"secret"`
}

type recoveryCode struct {
	Code string `json:"code"`
	Used bool   `json:"used"`
}

func getTOTPConfigs(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	render.JSON(w, r, mfa.GetAvailableTOTPConfigs())
}

func generateTOTPSecret(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var accountName string
	if claims.hasUserAudience() {
		accountName = fmt.Sprintf("User %q", claims.Username)
	} else {
		accountName = fmt.Sprintf("Admin %q", claims.Username)
	}

	var req generateTOTPRequest
	err = render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	configName, key, qrCode, err := mfa.GenerateTOTPSecret(req.ConfigName, accountName)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	render.JSON(w, r, generateTOTPResponse{
		ConfigName: configName,
		Issuer:     key.Issuer(),
		Secret:     key.Secret(),
		URL:        key.URL(),
		QRCode:     qrCode,
	})
}

func getQRCode(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	img, err := mfa.GenerateQRCodeFromURL(r.URL.Query().Get("url"), 400, 400)
	if err != nil {
		sendAPIResponse(w, r, nil, "unable to generate qr code", http.StatusInternalServerError)
		return
	}
	imgSize := int64(len(img))
	w.Header().Set("Content-Length", strconv.FormatInt(imgSize, 10))
	w.Header().Set("Content-Type", "image/png")
	io.CopyN(w, bytes.NewBuffer(img), imgSize) //nolint:errcheck
}

func saveTOTPConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	recoveryCodes := make([]dataprovider.RecoveryCode, 0, 12)
	for i := 0; i < 12; i++ {
		code := getNewRecoveryCode()
		recoveryCodes = append(recoveryCodes, dataprovider.RecoveryCode{Secret: kms.NewPlainSecret(code)})
	}
	baseURL := webBaseClientPath
	if claims.hasUserAudience() {
		if err := saveUserTOTPConfig(claims.Username, r, recoveryCodes); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	} else {
		if err := saveAdminTOTPConfig(claims.Username, r, recoveryCodes); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		baseURL = webBasePath
	}
	if claims.MustSetTwoFactorAuth {
		// force logout
		defer func() {
			c := jwtTokenClaims{}
			c.removeCookie(w, r, baseURL)
		}()
	}

	sendAPIResponse(w, r, nil, "TOTP configuration saved", http.StatusOK)
}

func validateTOTPPasscode(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req validateTOTPRequest
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(req.ConfigName, req.Passcode, req.Secret)
	if !match || err != nil {
		sendAPIResponse(w, r, err, "Invalid passcode", http.StatusBadRequest)
		return
	}
	sendAPIResponse(w, r, nil, "Passcode successfully validated", http.StatusOK)
}

func getRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	recoveryCodes := make([]recoveryCode, 0, 12)
	var accountRecoveryCodes []dataprovider.RecoveryCode
	if claims.hasUserAudience() {
		user, err := dataprovider.UserExists(claims.Username, "")
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if !user.Filters.TOTPConfig.Enabled {
			sendAPIResponse(w, r, errRecoveryCodeForbidden, "", http.StatusForbidden)
			return
		}
		accountRecoveryCodes = user.Filters.RecoveryCodes
	} else {
		admin, err := dataprovider.AdminExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if !admin.Filters.TOTPConfig.Enabled {
			sendAPIResponse(w, r, errRecoveryCodeForbidden, "", http.StatusForbidden)
			return
		}
		accountRecoveryCodes = admin.Filters.RecoveryCodes
	}

	for _, code := range accountRecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			sendAPIResponse(w, r, err, "Unable to decrypt recovery codes", getRespStatus(err))
			return
		}
		recoveryCodes = append(recoveryCodes, recoveryCode{
			Code: code.Secret.GetPayload(),
			Used: code.Used,
		})
	}
	render.JSON(w, r, recoveryCodes)
}

func generateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	recoveryCodes := make([]string, 0, 12)
	accountRecoveryCodes := make([]dataprovider.RecoveryCode, 0, 12)
	for i := 0; i < 12; i++ {
		code := getNewRecoveryCode()
		recoveryCodes = append(recoveryCodes, code)
		accountRecoveryCodes = append(accountRecoveryCodes, dataprovider.RecoveryCode{Secret: kms.NewPlainSecret(code)})
	}
	if claims.hasUserAudience() {
		user, err := dataprovider.UserExists(claims.Username, "")
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if !user.Filters.TOTPConfig.Enabled {
			sendAPIResponse(w, r, errRecoveryCodeForbidden, "", http.StatusForbidden)
			return
		}
		user.Filters.RecoveryCodes = accountRecoveryCodes
		if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), user.Role); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	} else {
		admin, err := dataprovider.AdminExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if !admin.Filters.TOTPConfig.Enabled {
			sendAPIResponse(w, r, errRecoveryCodeForbidden, "", http.StatusForbidden)
			return
		}
		admin.Filters.RecoveryCodes = accountRecoveryCodes
		if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), admin.Role); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	}

	render.JSON(w, r, recoveryCodes)
}

func getNewRecoveryCode() string {
	return fmt.Sprintf("RC-%v", strings.ToUpper(util.GenerateUniqueID()))
}

func saveUserTOTPConfig(username string, r *http.Request, recoveryCodes []dataprovider.RecoveryCode) error {
	user, userMerged, err := dataprovider.GetUserVariants(username, "")
	if err != nil {
		return err
	}
	currentTOTPSecret := user.Filters.TOTPConfig.Secret
	user.Filters.TOTPConfig.Secret = nil
	err = render.DecodeJSON(r.Body, &user.Filters.TOTPConfig)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("unable to decode JSON body: %v", err))
	}
	if !user.Filters.TOTPConfig.Enabled && len(userMerged.Filters.TwoFactorAuthProtocols) > 0 {
		return util.NewValidationError("two-factor authentication must be enabled")
	}
	for _, p := range userMerged.Filters.TwoFactorAuthProtocols {
		if !util.Contains(user.Filters.TOTPConfig.Protocols, p) {
			return util.NewValidationError(fmt.Sprintf("totp: the following protocols are required: %q",
				strings.Join(userMerged.Filters.TwoFactorAuthProtocols, ", ")))
		}
	}
	if user.Filters.TOTPConfig.Secret == nil || !user.Filters.TOTPConfig.Secret.IsPlain() {
		user.Filters.TOTPConfig.Secret = currentTOTPSecret
	}
	if user.Filters.TOTPConfig.Enabled {
		if user.CountUnusedRecoveryCodes() < 5 && user.Filters.TOTPConfig.Enabled {
			user.Filters.RecoveryCodes = recoveryCodes
		}
	} else {
		user.Filters.RecoveryCodes = nil
	}
	return dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), user.Role)
}

func saveAdminTOTPConfig(username string, r *http.Request, recoveryCodes []dataprovider.RecoveryCode) error {
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		return err
	}
	currentTOTPSecret := admin.Filters.TOTPConfig.Secret
	admin.Filters.TOTPConfig.Secret = nil
	err = render.DecodeJSON(r.Body, &admin.Filters.TOTPConfig)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("unable to decode JSON body: %v", err))
	}
	if !admin.Filters.TOTPConfig.Enabled && admin.Filters.RequireTwoFactor {
		return util.NewValidationError("two-factor authentication must be enabled")
	}
	if admin.Filters.TOTPConfig.Enabled {
		if admin.CountUnusedRecoveryCodes() < 5 && admin.Filters.TOTPConfig.Enabled {
			admin.Filters.RecoveryCodes = recoveryCodes
		}
	} else {
		admin.Filters.RecoveryCodes = nil
	}
	if admin.Filters.TOTPConfig.Secret == nil || !admin.Filters.TOTPConfig.Secret.IsPlain() {
		admin.Filters.TOTPConfig.Secret = currentTOTPSecret
	}
	return dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), admin.Role)
}
