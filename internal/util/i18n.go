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
	I18nUsersTitle                     = "title.users"
	I18nGroupsTitle                    = "title.groups"
	I18nFoldersTitle                   = "title.folders"
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
	I18nAddAdminTitle                  = "title.add_admin"
	I18nUpdateAdminTitle               = "title.update_admin"
	I18nTemplateUserTitle              = "title.template_user"
	I18nMaintenanceTitle               = "title.maintenance"
	I18nConfigsTitle                   = "title.configs"
	I18nOAuth2Title                    = "title.oauth2_success"
	I18nOAuth2ErrorTitle               = "title.oauth2_error"
	I18nSessionsTitle                  = "title.connections"
	I18nRolesTitle                     = "title.roles"
	I18nAdminsTitle                    = "title.admins"
	I18nIPListsTitle                   = "title.ip_lists"
	I18nAddIPListTitle                 = "title.add_ip_list"
	I18nUpdateIPListTitle              = "title.update_ip_list"
	I18nDefenderTitle                  = "title.defender"
	I18nEventsTitle                    = "title.logs"
	I18nActionsTitle                   = "title.event_actions"
	I18nRulesTitle                     = "title.event_rules"
	I18nAddActionTitle                 = "title.add_action"
	I18nUpdateActionTitle              = "title.update_action"
	I18nAddRuleTitle                   = "title.add_rule"
	I18nUpdateRuleTitle                = "title.update_rule"
	I18nStatusTitle                    = "status.desc"
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
	I18nErrorPasswordRequired          = "general.password_required"
	I18nErrorPermissionsRequired       = "general.permissions_required"
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
	I18nErrorInvalidName               = "general.name_invalid"
	I18nErrorHomeRequired              = "user.home_required"
	I18nErrorHomeInvalid               = "user.home_invalid"
	I18nErrorPubKeyInvalid             = "user.pub_key_invalid"
	I18nErrorPrivKeyInvalid            = "user.priv_key_invalid"
	I18nErrorKeySizeInvalid            = "user.key_invalid_size"
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
	I18nError2FAConflict               = "user.two_factor_conflict"
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
	I18nError2FARequiredGeneric        = "login.two_factor_required_generic"
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
	I18nErrorTimeOfDayInvalid          = "user.time_of_day_invalid"
	I18nErrorTimeOfDayConflict         = "user.time_of_day_conflict"
	I18nErrorInvalidMaxFilesize        = "filters.max_upload_size_invalid"
	I18nErrorInvalidHomeDir            = "storage.home_dir_invalid"
	I18nErrorBucketRequired            = "storage.bucket_required"
	I18nErrorRegionRequired            = "storage.region_required"
	I18nErrorKeyPrefixInvalid          = "storage.key_prefix_invalid"
	I18nErrorULPartSizeInvalid         = "storage.ul_part_size_invalid"
	I18nErrorDLPartSizeInvalid         = "storage.dl_part_size_invalid"
	I18nErrorULConcurrencyInvalid      = "storage.ul_concurrency_invalid"
	I18nErrorDLConcurrencyInvalid      = "storage.dl_concurrency_invalid"
	I18nErrorAccessKeyRequired         = "storage.access_key_required"
	I18nErrorAccessSecretRequired      = "storage.access_secret_required"
	I18nErrorFsCredentialsRequired     = "storage.credentials_required"
	I18nErrorContainerRequired         = "storage.container_required"
	I18nErrorAccountNameRequired       = "storage.account_name_required"
	I18nErrorSASURLInvalid             = "storage.sas_url_invalid"
	I18nErrorPassphraseRequired        = "storage.passphrase_required"
	I18nErrorEndpointInvalid           = "storage.endpoint_invalid"
	I18nErrorEndpointRequired          = "storage.endpoint_required"
	I18nErrorFsUsernameRequired        = "storage.username_required"
	I18nAddGroupTitle                  = "title.add_group"
	I18nUpdateGroupTitle               = "title.update_group"
	I18nRoleAddTitle                   = "title.add_role"
	I18nRoleUpdateTitle                = "title.update_role"
	I18nErrorInvalidTLSCert            = "user.tls_cert_invalid"
	I18nAddFolderTitle                 = "title.add_folder"
	I18nUpdateFolderTitle              = "title.update_folder"
	I18nTemplateFolderTitle            = "title.template_folder"
	I18nErrorDuplicatedUsername        = "general.duplicated_username"
	I18nErrorDuplicatedName            = "general.duplicated_name"
	I18nErrorDuplicatedIPNet           = "ip_list.duplicated"
	I18nErrorRoleAdminPerms            = "admin.role_permissions"
	I18nBackupOK                       = "maintenance.backup_ok"
	I18nErrorFolderTemplate            = "virtual_folders.template_no_folder"
	I18nErrorUserTemplate              = "user.template_no_user"
	I18nConfigsOK                      = "general.configs_saved"
	I18nOAuth2ErrorVerifyState         = "oauth2.auth_verify_error"
	I18nOAuth2ErrorValidateState       = "oauth2.auth_validation_error"
	I18nOAuth2InvalidState             = "oauth2.auth_invalid"
	I18nOAuth2ErrTokenExchange         = "oauth2.token_exchange_err"
	I18nOAuth2ErrNoRefreshToken        = "oauth2.no_refresh_token"
	I18nOAuth2OK                       = "oauth2.success"
	I18nErrorAdminSelfPerms            = "admin.self_permissions"
	I18nErrorAdminSelfDisable          = "admin.self_disable"
	I18nErrorAdminSelfRole             = "admin.self_role"
	I18nErrorIPInvalid                 = "ip_list.ip_invalid"
	I18nErrorNetInvalid                = "ip_list.net_invalid"
	I18nFTPTLSDisabled                 = "status.tls_disabled"
	I18nFTPTLSExplicit                 = "status.tls_explicit"
	I18nFTPTLSImplicit                 = "status.tls_implicit"
	I18nFTPTLSMixed                    = "status.tls_mixed"
	I18nErrorBackupFile                = "maintenance.backup_invalid_file"
	I18nErrorRestore                   = "maintenance.restore_error"
	I18nErrorACMEGeneric               = "acme.generic_error"
	I18nErrorSMTPRequiredFields        = "smtp.err_required_fields"
	I18nErrorSMTPClientIDRequired      = "smtp.client_id_required"
	I18nErrorSMTPClientSecretRequired  = "smtp.client_secret_required"
	I18nErrorSMTPRefreshTokenRequired  = "smtp.refresh_token_required"
	I18nErrorURLRequired               = "actions.http_url_required"
	I18nErrorURLInvalid                = "actions.http_url_invalid"
	I18nErrorHTTPPartNameRequired      = "actions.http_part_name_required"
	I18nErrorHTTPPartBodyRequired      = "actions.http_part_body_required"
	I18nErrorMultipartBody             = "actions.http_multipart_body_error"
	I18nErrorMultipartCType            = "actions.http_multipart_ctype_error"
	I18nErrorPathDuplicated            = "actions.path_duplicated"
	I18nErrorCommandRequired           = "actions.command_required"
	I18nErrorCommandInvalid            = "actions.command_invalid"
	I18nErrorEmailRecipientRequired    = "actions.email_recipient_required"
	I18nErrorEmailSubjectRequired      = "actions.email_subject_required"
	I18nErrorEmailBodyRequired         = "actions.email_body_required"
	I18nErrorRetentionDirRequired      = "actions.retention_directory_required"
	I18nErrorPathRequired              = "actions.path_required"
	I18nErrorSourceDestMatch           = "actions.source_dest_different"
	I18nErrorRootNotAllowed            = "actions.root_not_allowed"
	I18nErrorArchiveNameRequired       = "actions.archive_name_required"
	I18nErrorIDPTemplateRequired       = "actions.idp_template_required"
	I18nActionTypeHTTP                 = "actions.types.http"
	I18nActionTypeEmail                = "actions.types.email"
	I18nActionTypeBackup               = "actions.types.backup"
	I18nActionTypeUserQuotaReset       = "actions.types.user_quota_reset"
	I18nActionTypeFolderQuotaReset     = "actions.types.folder_quota_reset"
	I18nActionTypeTransferQuotaReset   = "actions.types.transfer_quota_reset"
	I18nActionTypeDataRetentionCheck   = "actions.types.data_retention_check"
	I18nActionTypeFilesystem           = "actions.types.filesystem"
	I18nActionTypePwdExpirationCheck   = "actions.types.password_expiration_check"
	I18nActionTypeUserExpirationCheck  = "actions.types.user_expiration_check"
	I18nActionTypeUserInactivityCheck  = "actions.types.user_inactivity_check"
	I18nActionTypeIDPCheck             = "actions.types.idp_check"
	I18nActionTypeCommand              = "actions.types.command"
	I18nActionFsTypeRename             = "actions.fs_types.rename"
	I18nActionFsTypeDelete             = "actions.fs_types.delete"
	I18nActionFsTypePathExists         = "actions.fs_types.path_exists"
	I18nActionFsTypeCompress           = "actions.fs_types.compress"
	I18nActionFsTypeCopy               = "actions.fs_types.copy"
	I18nActionFsTypeCreateDirs         = "actions.fs_types.create_dirs"
	I18nActionThresholdRequired        = "actions.inactivity_threshold_required"
	I18nActionThresholdsInvalid        = "actions.inactivity_thresholds_invalid"
	I18nTriggerFsEvent                 = "rules.triggers.fs_event"
	I18nTriggerProviderEvent           = "rules.triggers.provider_event"
	I18nTriggerIPBlockedEvent          = "rules.triggers.ip_blocked"
	I18nTriggerCertificateRenewEvent   = "rules.triggers.certificate_renewal"
	I18nTriggerOnDemandEvent           = "rules.triggers.on_demand"
	I18nTriggerIDPLoginEvent           = "rules.triggers.idp_login"
	I18nTriggerScheduleEvent           = "rules.triggers.schedule"
	I18nErrorInvalidMinSize            = "rules.invalid_fs_min_size"
	I18nErrorInvalidMaxSize            = "rules.invalid_fs_max_size"
	I18nErrorRuleActionRequired        = "rules.action_required"
	I18nErrorRuleFsEventRequired       = "rules.fs_event_required"
	I18nErrorRuleProviderEventRequired = "rules.provider_event_required"
	I18nErrorRuleScheduleRequired      = "rules.schedule_required"
	I18nErrorRuleScheduleInvalid       = "rules.schedule_invalid"
	I18nErrorRuleDuplicateActions      = "rules.duplicate_actions"
	I18nErrorEvSyncFailureActions      = "rules.sync_failure_actions"
	I18nErrorEvSyncUnsupported         = "rules.sync_unsupported"
	I18nErrorEvSyncUnsupportedFs       = "rules.sync_unsupported_fs_event"
	I18nErrorRuleFailureActionsOnly    = "rules.only_failure_actions"
	I18nErrorRuleSyncActionRequired    = "rules.sync_action_required"
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
