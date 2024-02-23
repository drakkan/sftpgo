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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getAdmins(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	admins, err := dataprovider.GetAdmins(limit, offset, order)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, admins)
}

func getAdminByUsername(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	renderAdmin(w, r, username, http.StatusOK)
}

func renderAdmin(w http.ResponseWriter, r *http.Request, username string, status int) {
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	admin.HideConfidentialData()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, http.StatusCreated)
		render.JSON(w, r.WithContext(ctx), admin)
	} else {
		render.JSON(w, r, admin)
	}
}

func addAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	admin := dataprovider.Admin{}
	err = render.DecodeJSON(r.Body, &admin)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddAdmin(&admin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", adminPath, url.PathEscape(admin.Username)))
	renderAdmin(w, r, admin.Username, http.StatusCreated)
}

func disableAdmin2FA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	admin, err := dataprovider.AdminExists(getURLParam(r, "username"))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		sendAPIResponse(w, r, nil, "two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}
	if admin.Username == claims.Username {
		if admin.Filters.RequireTwoFactor {
			err := util.NewValidationError("two-factor authentication must be enabled")
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	}
	admin.Filters.RecoveryCodes = nil
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled: false,
	}
	if err := dataprovider.UpdateAdmin(&admin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "2FA disabled", http.StatusOK)
}

func updateAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedAdmin dataprovider.Admin
	err = render.DecodeJSON(r.Body, &updatedAdmin)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	if username == claims.Username {
		if claims.APIKeyID != "" {
			sendAPIResponse(w, r, errors.New("updating the admin impersonated with an API key is not allowed"), "",
				http.StatusBadRequest)
			return
		}
		if claims.isCriticalPermRemoved(updatedAdmin.Permissions) {
			sendAPIResponse(w, r, errors.New("you cannot remove these permissions to yourself"), "", http.StatusBadRequest)
			return
		}
		if updatedAdmin.Status == 0 {
			sendAPIResponse(w, r, errors.New("you cannot disable yourself"), "", http.StatusBadRequest)
			return
		}
		if updatedAdmin.Role != claims.Role {
			sendAPIResponse(w, r, errors.New("you cannot add/change your role"), "", http.StatusBadRequest)
			return
		}
		updatedAdmin.Filters.RequirePasswordChange = admin.Filters.RequirePasswordChange
		updatedAdmin.Filters.RequireTwoFactor = admin.Filters.RequireTwoFactor
	}
	updatedAdmin.ID = admin.ID
	updatedAdmin.Username = admin.Username
	if updatedAdmin.Password == "" {
		updatedAdmin.Password = admin.Password
	}
	updatedAdmin.Filters.TOTPConfig = admin.Filters.TOTPConfig
	updatedAdmin.Filters.RecoveryCodes = admin.Filters.RecoveryCodes
	err = dataprovider.UpdateAdmin(&updatedAdmin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Admin updated", http.StatusOK)
}

func deleteAdmin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	if username == claims.Username {
		sendAPIResponse(w, r, errors.New("you cannot delete yourself"), "", http.StatusBadRequest)
		return
	}

	err = dataprovider.DeleteAdmin(username, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Admin deleted", http.StatusOK)
}

func getAdminProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	resp := adminProfile{
		baseProfile: baseProfile{
			Email:           admin.Email,
			Description:     admin.Description,
			AllowAPIKeyAuth: admin.Filters.AllowAPIKeyAuth,
		},
	}
	render.JSON(w, r, resp)
}

func updateAdminProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var req adminProfile
	err = render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	admin.Email = req.Email
	admin.Description = req.Description
	admin.Filters.AllowAPIKeyAuth = req.AllowAPIKeyAuth
	if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Profile updated", http.StatusOK)
}

func forgotAdminPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		sendAPIResponse(w, r, nil, "No SMTP configuration", http.StatusBadRequest)
		return
	}

	err := handleForgotPassword(r, getURLParam(r, "username"), true)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	sendAPIResponse(w, r, err, "Check your email for the confirmation code", http.StatusOK)
}

func resetAdminPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req pwdReset
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	_, _, err = handleResetPassword(r, req.Code, req.Password, req.Password, true)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Password reset successful", http.StatusOK)
}

func changeAdminPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var pwd pwdChange
	err := render.DecodeJSON(r.Body, &pwd)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = doChangeAdminPassword(r, pwd.CurrentPassword, pwd.NewPassword, pwd.NewPassword)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Password updated", http.StatusOK)
}

func doChangeAdminPassword(r *http.Request, currentPassword, newPassword, confirmNewPassword string) error {
	if currentPassword == "" || newPassword == "" || confirmNewPassword == "" {
		return util.NewI18nError(
			util.NewValidationError("please provide the current password and the new one two times"),
			util.I18nErrorChangePwdRequiredFields,
		)
	}
	if newPassword != confirmNewPassword {
		return util.NewI18nError(util.NewValidationError("the two password fields do not match"), util.I18nErrorChangePwdNoMatch)
	}
	if currentPassword == newPassword {
		return util.NewI18nError(
			util.NewValidationError("the new password must be different from the current one"),
			util.I18nErrorChangePwdNoDifferent,
		)
	}
	claims, err := getTokenClaims(r)
	if err != nil {
		return util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken)
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		return err
	}
	match, err := admin.CheckPassword(currentPassword)
	if !match || err != nil {
		return util.NewI18nError(util.NewValidationError("current password does not match"), util.I18nErrorChangePwdCurrentNoMatch)
	}

	admin.Password = newPassword
	admin.Filters.RequirePasswordChange = false

	return dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
}

func getTokenClaims(r *http.Request) (jwtTokenClaims, error) {
	tokenClaims := jwtTokenClaims{}
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		return tokenClaims, err
	}
	tokenClaims.Decode(claims)

	return tokenClaims, nil
}
