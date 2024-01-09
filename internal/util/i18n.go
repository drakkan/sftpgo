// Copyright (C) 2023 Nicola Murino
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

package util

import (
	"encoding/json"
	"errors"
)

// localization id for the Web frontend
const (
	I18nSetupTitle                     = "title.setup"
	I18nLoginTitle                     = "title.login"
	I18nShareLoginTitle                = "title.share_login"
	I18nFilesTitle                     = "title.files"
	I18nSharesTitle                    = "title.shares"
	I18nShareAddTitle                  = "title.add_share"
	I18nShareUpdateTitle               = "title.update_share"
	I18nProfileTitle                   = "title.profile"
	I18nChangePwdTitle                 = "title.change_password"
	I18n2FATitle                       = "title.two_factor_auth"
	I18nEditFileTitle                  = "title.edit_file"
	I18nViewFileTitle                  = "title.view_file"
	I18nForgotPwdTitle                 = "title.recovery_password"
	I18nResetPwdTitle                  = "title.reset_password"
	I18nSharedFilesTitle               = "title.shared_files"
	I18nShareUploadTitle               = "title.upload_to_share"
	I18nShareDownloadTitle             = "title.download_shared_file"
	I18nShareAccessErrorTitle          = "title.share_access_error"
	I18nInvalidAuthReqTitle            = "title.invalid_auth_request"
	I18nError403Title                  = "title.error403"
	I18nError400Title                  = "title.error400"
	I18nError404Title                  = "title.error404"
	I18nError416Title                  = "title.error416"
	I18nError429Title                  = "title.error429"
	I18nError500Title                  = "title.error500"
	I18nErrorPDFTitle                  = "title.errorPDF"
	I18nErrorEditorTitle               = "title.error_editor"
	I18nAddUserTitle                   = "title.add_user"
	I18nUpdateUserTitle                = "title.update_user"
	I18nTemplateUserTitle              = "title.template_user"
	I18nErrorSetupInstallCode          = "setup.install_code_mismatch"
	I18nInvalidAuth                    = "general.invalid_auth_request"
	I18nError429Message                = "general.error429"
	I18nError400Message                = "general.error400"
	I18nError403Message                = "general.error403"
	I18nError404Message                = "general.error404"
	I18nError416Message                = "general.error416"
	I18nError500Message                = "general.error500"
	I18nErrorPDFMessage                = "general.errorPDF"
	I18nErrorInvalidToken              = "general.invalid_token"
	I18nErrorInvalidForm               = "general.invalid_form"
	I18nErrorInvalidCredentials        = "general.invalid_credentials"
	I18nErrorInvalidCSRF               = "general.invalid_csrf"
	I18nErrorFsGeneric                 = "fs.err_generic"
	I18nErrorDirListGeneric            = "fs.dir_list.err_generic"
	I18nErrorDirList403                = "fs.dir_list.err_403"
	I18nErrorDirList429                = "fs.dir_list.err_429"
	I18nErrorDirListUser               = "fs.dir_list.err_user"
	I18nErrorFsValidation              = "fs.err_validation"
	I18nErrorChangePwdRequiredFields   = "change_pwd.required_fields"
	I18nErrorChangePwdNoMatch          = "change_pwd.no_match"
	I18nErrorChangePwdGeneric          = "change_pwd.generic"
	I18nErrorChangePwdNoDifferent      = "change_pwd.no_different"
	I18nErrorChangePwdCurrentNoMatch   = "change_pwd.current_no_match"
	I18nErrorChangePwdRequired         = "change_pwd.required"
	I18nErrorUsernameRequired          = "general.username_required"
	I18nErrorGetUser                   = "general.err_user"
	I18nErrorPwdResetForbidded         = "login.reset_pwd_forbidden"
	I18nErrorPwdResetNoEmail           = "login.reset_pwd_no_email"
	I18nErrorPwdResetSendEmail         = "login.reset_pwd_send_email_err"
	I18nErrorPwdResetGeneric           = "login.reset_pwd_err_generic"
	I18nErrorProtocolForbidden         = "general.err_protocol_forbidden"
	I18nErrorPwdLoginForbidden         = "general.pwd_login_forbidden"
	I18nErrorIPForbidden               = "general.ip_forbidden"
	I18nErrorConnectionForbidden       = "general.connection_forbidden"
	I18nErrorReservedUsername          = "user.username_reserved"
	I18nErrorInvalidEmail              = "general.email_invalid"
	I18nErrorInvalidUser               = "user.username_invalid"
	I18nErrorHomeRequired              = "user.home_required"
	I18nErrorHomeInvalid               = "user.home_invalid"
	I18nErrorPubKeyInvalid             = "user.pub_key_invalid"
	I18nErrorPrimaryGroup              = "user.err_primary_group"
	I18nErrorDuplicateGroup            = "user.err_duplicate_group"
	I18nErrorNoPermission              = "user.no_permissions"
	I18nErrorNoRootPermission          = "user.no_root_permissions"
	I18nErrorGenericPermission         = "user.err_permissions_generic"
	I18nError2FAInvalid                = "user.2fa_invalid"
	I18nErrorRecoveryCodesInvalid      = "user.recovery_codes_invalid"
	I18nErrorFolderNameRequired        = "general.foldername_required"
	I18nErrorFolderMountPathRequired   = "user.folder_path_required"
	I18nErrorDuplicatedFolders         = "user.folder_duplicated"
	I18nErrorOverlappedFolders         = "user.folder_overlapped"
	I18nErrorFolderQuotaSizeInvalid    = "user.folder_quota_size_invalid"
	I18nErrorFolderQuotaFileInvalid    = "user.folder_quota_file_invalid"
	I18nErrorFolderQuotaInvalid        = "user.folder_quota_invalid"
	I18nErrorPasswordComplexity        = "general.err_password_complexity"
	I18nErrorIPFiltersInvalid          = "user.ip_filters_invalid"
	I18nErrorSourceBWLimitInvalid      = "user.src_bw_limits_invalid"
	I18nErrorShareExpirationInvalid    = "user.share_expiration_invalid"
	I18nErrorFilePatternPathInvalid    = "user.file_pattern_path_invalid"
	I18nErrorFilePatternDuplicated     = "user.file_pattern_duplicated"
	I18nErrorFilePatternInvalid        = "user.file_pattern_invalid"
	I18nErrorDisableActive2FA          = "user.disable_active_2fa"
	I18nErrorPwdChangeConflict         = "user.pwd_change_conflict"
	I18nErrorLoginAfterReset           = "login.reset_ok_login_error"
	I18nErrorShareScope                = "share.scope_invalid"
	I18nErrorShareMaxTokens            = "share.max_tokens_invalid"
	I18nErrorShareExpiration           = "share.expiration_invalid"
	I18nErrorShareNoPwd                = "share.err_no_password"
	I18nErrorShareExpirationOutOfRange = "share.expiration_out_of_range"
	I18nErrorShareGeneric              = "share.generic"
	I18nErrorNameRequired              = "general.name_required"
	I18nErrorSharePathRequired         = "share.path_required"
	I18nErrorShareWriteScope           = "share.path_write_scope"
	I18nErrorShareNestedPaths          = "share.nested_paths"
	I18nErrorShareExpirationPast       = "share.expiration_past"
	I18nErrorInvalidIPMask             = "general.allowed_ip_mask_invalid"
	I18nErrorShareUsage                = "share.usage_exceed"
	I18nErrorShareExpired              = "share.expired"
	I18nErrorLoginFromIPDenied         = "login.ip_not_allowed"
	I18nError2FARequired               = "login.two_factor_required"
	I18nErrorNoOIDCFeature             = "general.no_oidc_feature"
	I18nErrorNoPermissions             = "general.no_permissions"
	I18nErrorShareBrowsePaths          = "share.browsable_multiple_paths"
	I18nErrorShareBrowseNoDir          = "share.browsable_non_dir"
	I18nErrorShareInvalidPath          = "share.invalid_path"
	I18nErrorPathInvalid               = "general.path_invalid"
	I18nErrorQuotaRead                 = "general.err_quota_read"
	I18nErrorEditDir                   = "general.error_edit_dir"
	I18nErrorEditSize                  = "general.error_edit_size"
	I18nProfileUpdated                 = "general.profile_updated"
	I18nShareLoginOK                   = "general.share_ok"
	I18n2FADisabled                    = "2fa.disabled"
	I18nOIDCTokenExpired               = "oidc.token_expired"
	I18nOIDCTokenInvalidAdmin          = "oidc.token_invalid_webadmin"
	I18nOIDCTokenInvalidUser           = "oidc.token_invalid_webclient"
	I18nOIDCErrTokenExchange           = "oidc.token_exchange_err"
	I18nOIDCTokenInvalid               = "oidc.token_invalid"
	I18nOIDCTokenInvalidRoleAdmin      = "oidc.role_admin_err"
	I18nOIDCTokenInvalidRoleUser       = "oidc.role_user_err"
	I18nOIDCErrGetUser                 = "oidc.get_user_err"
	I18nStorageLocal                   = "storage.local"
	I18nStorageLocalEncrypted          = "storage.encrypted"
	I18nStorageS3                      = "storage.s3"
	I18nStorageGCS                     = "storage.gcs"
	I18nStorageAzureBlob               = "storage.azblob"
	I18nStorageSFTP                    = "storage.sftp"
	I18nStorageHTTP                    = "storage.http"
	I18nErrorInvalidQuotaSize          = "user.invalid_quota_size"
	I18nErrorInvalidMaxFilesize        = "filters.max_upload_size_invalid"
)

// NewI18nError returns a I18nError wrappring the provided error
func NewI18nError(err error, message string, options ...I18nErrorOption) *I18nError {
	var errI18n *I18nError
	if errors.As(err, &errI18n) {
		return errI18n
	}
	errI18n = &I18nError{
		err:     err,
		Message: message,
		args:    nil,
	}
	for _, opt := range options {
		opt(errI18n)
	}
	return errI18n
}

// I18nErrorOption defines a functional option type that allows to configure the I18nError.
type I18nErrorOption func(*I18nError)

// I18nErrorArgs is a functional option to set I18nError arguments.
func I18nErrorArgs(args map[string]any) I18nErrorOption {
	return func(e *I18nError) {
		e.args = args
	}
}

// I18nError is an error wrapper that add a message to use for localization.
type I18nError struct {
	err     error
	Message string
	args    map[string]any
}

// Error returns the wrapped error string.
func (e *I18nError) Error() string {
	return e.err.Error()
}

// Unwrap returns the underlying error
func (e *I18nError) Unwrap() error {
	return e.err
}

// Is reports if target matches
func (e *I18nError) Is(target error) bool {
	if errors.Is(e.err, target) {
		return true
	}
	_, ok := target.(*I18nError)
	return ok
}

// HasArgs returns true if the error has i18n args.
func (e *I18nError) HasArgs() bool {
	return len(e.args) > 0
}

// Args returns the provided args in JSON format
func (e *I18nError) Args() string {
	if len(e.args) > 0 {
		data, err := json.Marshal(e.args)
		if err == nil {
			return string(data)
		}
	}
	return "{}"
}
