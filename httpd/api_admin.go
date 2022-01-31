package httpd

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
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
	var admin dataprovider.Admin
	err = render.DecodeJSON(r.Body, &admin)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddAdmin(&admin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
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
	admin.Filters.RecoveryCodes = nil
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{
		Enabled: false,
	}
	if err := dataprovider.UpdateAdmin(&admin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
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

	adminID := admin.ID
	username = admin.Username
	totpConfig := admin.Filters.TOTPConfig
	recoveryCodes := admin.Filters.RecoveryCodes
	admin.Filters.TOTPConfig = dataprovider.AdminTOTPConfig{}
	admin.Filters.RecoveryCodes = nil
	err = render.DecodeJSON(r.Body, &admin)
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
		if claims.isCriticalPermRemoved(admin.Permissions) {
			sendAPIResponse(w, r, errors.New("you cannot remove these permissions to yourself"), "", http.StatusBadRequest)
			return
		}
		if admin.Status == 0 {
			sendAPIResponse(w, r, errors.New("you cannot disable yourself"), "", http.StatusBadRequest)
			return
		}
	}
	admin.ID = adminID
	admin.Username = username
	admin.Filters.TOTPConfig = totpConfig
	admin.Filters.RecoveryCodes = recoveryCodes
	if err := dataprovider.UpdateAdmin(&admin, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
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

	err = dataprovider.DeleteAdmin(username, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
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
	if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
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
	_, _, err = handleResetPassword(r, req.Code, req.Password, true)
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
		return util.NewValidationError("please provide the current password and the new one two times")
	}
	if newPassword != confirmNewPassword {
		return util.NewValidationError("the two password fields do not match")
	}
	if currentPassword == newPassword {
		return util.NewValidationError("the new password must be different from the current one")
	}
	claims, err := getTokenClaims(r)
	if err != nil {
		return err
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		return err
	}
	match, err := admin.CheckPassword(currentPassword)
	if !match || err != nil {
		return util.NewValidationError("current password does not match")
	}

	admin.Password = newPassword

	return dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
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
