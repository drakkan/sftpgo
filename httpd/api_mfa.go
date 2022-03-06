package httpd

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/util"
)

type generateTOTPRequest struct {
	ConfigName string `json:"config_name"`
}

type generateTOTPResponse struct {
	ConfigName string `json:"config_name"`
	Issuer     string `json:"issuer"`
	Secret     string `json:"secret"`
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
		accountName = fmt.Sprintf("User %#v", claims.Username)
	} else {
		accountName = fmt.Sprintf("Admin %#v", claims.Username)
	}

	var req generateTOTPRequest
	err = render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	configName, issuer, secret, qrCode, err := mfa.GenerateTOTPSecret(req.ConfigName, accountName)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	render.JSON(w, r, generateTOTPResponse{
		ConfigName: configName,
		Issuer:     issuer,
		Secret:     secret,
		QRCode:     qrCode,
	})
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
	if claims.hasUserAudience() {
		if err := saveUserTOTPConfig(claims.Username, r, recoveryCodes); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		if claims.MustSetTwoFactorAuth {
			// force logout
			defer func() {
				c := jwtTokenClaims{}
				c.removeCookie(w, r, webBaseClientPath)
			}()
		}
	} else {
		if err := saveAdminTOTPConfig(claims.Username, r, recoveryCodes); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
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
		user, err := dataprovider.UserExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		accountRecoveryCodes = user.Filters.RecoveryCodes
	} else {
		admin, err := dataprovider.AdminExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
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
		user, err := dataprovider.UserExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		user.Filters.RecoveryCodes = accountRecoveryCodes
		if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	} else {
		admin, err := dataprovider.AdminExists(claims.Username)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		admin.Filters.RecoveryCodes = accountRecoveryCodes
		if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
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
	user, err := dataprovider.UserExists(username)
	if err != nil {
		return err
	}
	currentTOTPSecret := user.Filters.TOTPConfig.Secret
	user.Filters.TOTPConfig.Secret = nil
	err = render.DecodeJSON(r.Body, &user.Filters.TOTPConfig)
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("unable to decode JSON body: %v", err))
	}
	if !user.Filters.TOTPConfig.Enabled && len(user.Filters.TwoFactorAuthProtocols) > 0 {
		return util.NewValidationError("two-factor authentication must be enabled")
	}
	for _, p := range user.Filters.TwoFactorAuthProtocols {
		if !util.IsStringInSlice(p, user.Filters.TOTPConfig.Protocols) {
			return util.NewValidationError(fmt.Sprintf("totp: the following protocols are required: %#v",
				strings.Join(user.Filters.TwoFactorAuthProtocols, ", ")))
		}
	}
	if user.Filters.TOTPConfig.Secret == nil || !user.Filters.TOTPConfig.Secret.IsPlain() {
		user.Filters.TOTPConfig.Secret = currentTOTPSecret
	}
	if user.CountUnusedRecoveryCodes() < 5 && user.Filters.TOTPConfig.Enabled {
		user.Filters.RecoveryCodes = recoveryCodes
	}
	return dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
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
	if admin.CountUnusedRecoveryCodes() < 5 && admin.Filters.TOTPConfig.Enabled {
		admin.Filters.RecoveryCodes = recoveryCodes
	}
	if admin.Filters.TOTPConfig.Secret == nil || !admin.Filters.TOTPConfig.Secret.IsPlain() {
		admin.Filters.TOTPConfig.Secret = currentTOTPSecret
	}
	return dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, util.GetIPFromRemoteAddress(r.RemoteAddr))
}
