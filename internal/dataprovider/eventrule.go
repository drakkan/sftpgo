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

package dataprovider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// Supported event actions
const (
	ActionTypeHTTP = iota + 1
	ActionTypeCommand
	ActionTypeEmail
	ActionTypeBackup
	ActionTypeUserQuotaReset
	ActionTypeFolderQuotaReset
	ActionTypeTransferQuotaReset
	ActionTypeDataRetentionCheck
	ActionTypeFilesystem
	actionTypeReserved
	ActionTypePasswordExpirationCheck
	ActionTypeUserExpirationCheck
	ActionTypeIDPAccountCheck
	ActionTypeUserInactivityCheck
)

var (
	supportedEventActions = []int{ActionTypeHTTP, ActionTypeCommand, ActionTypeEmail, ActionTypeFilesystem,
		ActionTypeBackup, ActionTypeUserQuotaReset, ActionTypeFolderQuotaReset, ActionTypeTransferQuotaReset,
		ActionTypeDataRetentionCheck, ActionTypePasswordExpirationCheck,
		ActionTypeUserExpirationCheck, ActionTypeUserInactivityCheck, ActionTypeIDPAccountCheck}
)

func isActionTypeValid(action int) bool {
	return util.Contains(supportedEventActions, action)
}

func getActionTypeAsString(action int) string {
	switch action {
	case ActionTypeHTTP:
		return util.I18nActionTypeHTTP
	case ActionTypeEmail:
		return util.I18nActionTypeEmail
	case ActionTypeBackup:
		return util.I18nActionTypeBackup
	case ActionTypeUserQuotaReset:
		return util.I18nActionTypeUserQuotaReset
	case ActionTypeFolderQuotaReset:
		return util.I18nActionTypeFolderQuotaReset
	case ActionTypeTransferQuotaReset:
		return util.I18nActionTypeTransferQuotaReset
	case ActionTypeDataRetentionCheck:
		return util.I18nActionTypeDataRetentionCheck
	case ActionTypeFilesystem:
		return util.I18nActionTypeFilesystem
	case ActionTypePasswordExpirationCheck:
		return util.I18nActionTypePwdExpirationCheck
	case ActionTypeUserExpirationCheck:
		return util.I18nActionTypeUserExpirationCheck
	case ActionTypeUserInactivityCheck:
		return util.I18nActionTypeUserInactivityCheck
	case ActionTypeIDPAccountCheck:
		return util.I18nActionTypeIDPCheck
	default:
		return util.I18nActionTypeCommand
	}
}

// Supported event triggers
const (
	// Filesystem events such as upload, download, mkdir ...
	EventTriggerFsEvent = iota + 1
	// Provider events such as add, update, delete
	EventTriggerProviderEvent
	EventTriggerSchedule
	EventTriggerIPBlocked
	EventTriggerCertificate
	EventTriggerOnDemand
	EventTriggerIDPLogin
)

var (
	supportedEventTriggers = []int{EventTriggerFsEvent, EventTriggerProviderEvent, EventTriggerSchedule,
		EventTriggerIPBlocked, EventTriggerCertificate, EventTriggerIDPLogin, EventTriggerOnDemand}
)

func isEventTriggerValid(trigger int) bool {
	return util.Contains(supportedEventTriggers, trigger)
}

func getTriggerTypeAsString(trigger int) string {
	switch trigger {
	case EventTriggerFsEvent:
		return util.I18nTriggerFsEvent
	case EventTriggerProviderEvent:
		return util.I18nTriggerProviderEvent
	case EventTriggerIPBlocked:
		return util.I18nTriggerIPBlockedEvent
	case EventTriggerCertificate:
		return util.I18nTriggerCertificateRenewEvent
	case EventTriggerOnDemand:
		return util.I18nTriggerOnDemandEvent
	case EventTriggerIDPLogin:
		return util.I18nTriggerIDPLoginEvent
	default:
		return util.I18nTriggerScheduleEvent
	}
}

// Supported IDP login events
const (
	IDPLoginAny = iota
	IDPLoginUser
	IDPLoginAdmin
)

var (
	supportedIDPLoginEvents = []int{IDPLoginAny, IDPLoginUser, IDPLoginAdmin}
)

// Supported filesystem actions
const (
	FilesystemActionRename = iota + 1
	FilesystemActionDelete
	FilesystemActionMkdirs
	FilesystemActionExist
	FilesystemActionCompress
	FilesystemActionCopy
)

const (
	// RetentionReportPlaceHolder defines the placeholder for data retention reports
	RetentionReportPlaceHolder = "{{RetentionReports}}"
)

var (
	supportedFsActions = []int{FilesystemActionRename, FilesystemActionDelete, FilesystemActionMkdirs,
		FilesystemActionCopy, FilesystemActionCompress, FilesystemActionExist}
)

func isFilesystemActionValid(value int) bool {
	return util.Contains(supportedFsActions, value)
}

func getFsActionTypeAsString(value int) string {
	switch value {
	case FilesystemActionRename:
		return util.I18nActionFsTypeRename
	case FilesystemActionDelete:
		return util.I18nActionFsTypeDelete
	case FilesystemActionExist:
		return util.I18nActionFsTypePathExists
	case FilesystemActionCompress:
		return util.I18nActionFsTypeCompress
	case FilesystemActionCopy:
		return util.I18nActionFsTypeCopy
	default:
		return util.I18nActionFsTypeCreateDirs
	}
}

// TODO: replace the copied strings with shared constants
var (
	// SupportedFsEvents defines the supported filesystem events
	SupportedFsEvents = []string{"upload", "pre-upload", "first-upload", "download", "pre-download",
		"first-download", "delete", "pre-delete", "rename", "mkdir", "rmdir", "copy", "ssh_cmd"}
	// SupportedProviderEvents defines the supported provider events
	SupportedProviderEvents = []string{operationAdd, operationUpdate, operationDelete}
	// SupportedRuleConditionProtocols defines the supported protcols for rule conditions
	SupportedRuleConditionProtocols = []string{"SFTP", "SCP", "SSH", "FTP", "DAV", "HTTP", "HTTPShare",
		"OIDC"}
	// SupporteRuleConditionProviderObjects defines the supported provider objects for rule conditions
	SupporteRuleConditionProviderObjects = []string{actionObjectUser, actionObjectFolder, actionObjectGroup,
		actionObjectAdmin, actionObjectAPIKey, actionObjectShare, actionObjectEventRule, actionObjectEventAction}
	// SupportedHTTPActionMethods defines the supported methods for HTTP actions
	SupportedHTTPActionMethods = []string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete}
	allowedSyncFsEvents        = []string{"upload", "pre-upload", "pre-download", "pre-delete"}
	mandatorySyncFsEvents      = []string{"pre-upload", "pre-download", "pre-delete"}
)

// enum mappings
var (
	EventActionTypes  []EnumMapping
	EventTriggerTypes []EnumMapping
	FsActionTypes     []EnumMapping
)

func init() {
	for _, t := range supportedEventActions {
		EventActionTypes = append(EventActionTypes, EnumMapping{
			Value: t,
			Name:  getActionTypeAsString(t),
		})
	}
	for _, t := range supportedEventTriggers {
		EventTriggerTypes = append(EventTriggerTypes, EnumMapping{
			Value: t,
			Name:  getTriggerTypeAsString(t),
		})
	}
	for _, t := range supportedFsActions {
		FsActionTypes = append(FsActionTypes, EnumMapping{
			Value: t,
			Name:  getFsActionTypeAsString(t),
		})
	}
}

// EnumMapping defines a mapping between enum values and names
type EnumMapping struct {
	Name  string
	Value int
}

// KeyValue defines a key/value pair
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (k *KeyValue) isNotValid() bool {
	return k.Key == "" || k.Value == ""
}

// HTTPPart defines a part for HTTP multipart requests
type HTTPPart struct {
	Name     string     `json:"name,omitempty"`
	Filepath string     `json:"filepath,omitempty"`
	Headers  []KeyValue `json:"headers,omitempty"`
	Body     string     `json:"body,omitempty"`
	Order    int        `json:"-"`
}

func (p *HTTPPart) validate() error {
	if p.Name == "" {
		return util.NewI18nError(util.NewValidationError("HTTP part name is required"), util.I18nErrorHTTPPartNameRequired)
	}
	for _, kv := range p.Headers {
		if kv.isNotValid() {
			return util.NewValidationError("invalid HTTP part headers")
		}
	}
	if p.Filepath == "" {
		if p.Body == "" {
			return util.NewI18nError(
				util.NewValidationError("HTTP part body is required if no file path is provided"),
				util.I18nErrorHTTPPartBodyRequired,
			)
		}
	} else {
		p.Body = ""
		if p.Filepath != RetentionReportPlaceHolder {
			p.Filepath = util.CleanPath(p.Filepath)
		}
	}
	return nil
}

// EventActionHTTPConfig defines the configuration for an HTTP event target
type EventActionHTTPConfig struct {
	Endpoint        string      `json:"endpoint,omitempty"`
	Username        string      `json:"username,omitempty"`
	Password        *kms.Secret `json:"password,omitempty"`
	Headers         []KeyValue  `json:"headers,omitempty"`
	Timeout         int         `json:"timeout,omitempty"`
	SkipTLSVerify   bool        `json:"skip_tls_verify,omitempty"`
	Method          string      `json:"method,omitempty"`
	QueryParameters []KeyValue  `json:"query_parameters,omitempty"`
	Body            string      `json:"body,omitempty"`
	Parts           []HTTPPart  `json:"parts,omitempty"`
}

// HasJSONBody returns true if the content type header indicates a JSON body
func (c *EventActionHTTPConfig) HasJSONBody() bool {
	for _, h := range c.Headers {
		if http.CanonicalHeaderKey(h.Key) == "Content-Type" {
			return strings.Contains(strings.ToLower(h.Value), "application/json")
		}
	}
	return false
}

func (c *EventActionHTTPConfig) isTimeoutNotValid() bool {
	if c.HasMultipartFiles() {
		return false
	}
	return c.Timeout < 1 || c.Timeout > 180
}

func (c *EventActionHTTPConfig) validateMultiparts() error {
	filePaths := make(map[string]bool)
	for idx := range c.Parts {
		if err := c.Parts[idx].validate(); err != nil {
			return err
		}
		if filePath := c.Parts[idx].Filepath; filePath != "" {
			if filePaths[filePath] {
				return util.NewI18nError(fmt.Errorf("filepath %q is duplicated", filePath), util.I18nErrorPathDuplicated)
			}
			filePaths[filePath] = true
		}
	}
	if len(c.Parts) > 0 {
		if c.Body != "" {
			return util.NewI18nError(
				util.NewValidationError("multipart requests require no body. The request body is build from the specified parts"),
				util.I18nErrorMultipartBody,
			)
		}
		for _, k := range c.Headers {
			if strings.ToLower(k.Key) == "content-type" {
				return util.NewI18nError(
					util.NewValidationError("content type is automatically set for multipart requests"),
					util.I18nErrorMultipartCType,
				)
			}
		}
	}
	return nil
}

func (c *EventActionHTTPConfig) validate(additionalData string) error {
	if c.Endpoint == "" {
		return util.NewI18nError(util.NewValidationError("HTTP endpoint is required"), util.I18nErrorURLRequired)
	}
	if !util.IsStringPrefixInSlice(c.Endpoint, []string{"http://", "https://"}) {
		return util.NewI18nError(
			util.NewValidationError("invalid HTTP endpoint schema: http and https are supported"),
			util.I18nErrorURLInvalid,
		)
	}
	if c.isTimeoutNotValid() {
		return util.NewValidationError(fmt.Sprintf("invalid HTTP timeout %d", c.Timeout))
	}
	for _, kv := range c.Headers {
		if kv.isNotValid() {
			return util.NewValidationError("invalid HTTP headers")
		}
	}
	if err := c.validateMultiparts(); err != nil {
		return err
	}
	if c.Password.IsRedacted() {
		return util.NewValidationError("cannot save HTTP configuration with a redacted secret")
	}
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		err := c.Password.Encrypt()
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt HTTP password: %v", err))
		}
	}
	if !util.Contains(SupportedHTTPActionMethods, c.Method) {
		return util.NewValidationError(fmt.Sprintf("unsupported HTTP method: %s", c.Method))
	}
	for _, kv := range c.QueryParameters {
		if kv.isNotValid() {
			return util.NewValidationError("invalid HTTP query parameters")
		}
	}
	return nil
}

// GetContext returns the context and the cancel func to use for the HTTP request
func (c *EventActionHTTPConfig) GetContext() (context.Context, context.CancelFunc) {
	if c.HasMultipartFiles() {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Second)
}

// HasObjectData returns true if the {{ObjectData}} placeholder is defined
func (c *EventActionHTTPConfig) HasObjectData() bool {
	if strings.Contains(c.Body, "{{ObjectData}}") {
		return true
	}
	for _, part := range c.Parts {
		if strings.Contains(part.Body, "{{ObjectData}}") {
			return true
		}
	}
	return false
}

// HasMultipartFiles returns true if at least a file must be uploaded via a multipart request
func (c *EventActionHTTPConfig) HasMultipartFiles() bool {
	for _, part := range c.Parts {
		if part.Filepath != "" && part.Filepath != RetentionReportPlaceHolder {
			return true
		}
	}
	return false
}

// TryDecryptPassword decrypts the password if encryptet
func (c *EventActionHTTPConfig) TryDecryptPassword() error {
	if c.Password != nil && !c.Password.IsEmpty() {
		if err := c.Password.TryDecrypt(); err != nil {
			return fmt.Errorf("unable to decrypt HTTP password: %w", err)
		}
	}
	return nil
}

// GetHTTPClient returns an HTTP client based on the config
func (c *EventActionHTTPConfig) GetHTTPClient() *http.Client {
	client := &http.Client{}
	if c.SkipTLSVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
		client.Transport = transport
	}
	return client
}

// EventActionCommandConfig defines the configuration for a command event target
type EventActionCommandConfig struct {
	Cmd     string     `json:"cmd,omitempty"`
	Args    []string   `json:"args,omitempty"`
	Timeout int        `json:"timeout,omitempty"`
	EnvVars []KeyValue `json:"env_vars,omitempty"`
}

func (c *EventActionCommandConfig) validate() error {
	if c.Cmd == "" {
		return util.NewI18nError(util.NewValidationError("command is required"), util.I18nErrorCommandRequired)
	}
	if !filepath.IsAbs(c.Cmd) {
		return util.NewI18nError(
			util.NewValidationError("invalid command, it must be an absolute path"),
			util.I18nErrorCommandInvalid,
		)
	}
	if c.Timeout < 1 || c.Timeout > 120 {
		return util.NewValidationError(fmt.Sprintf("invalid command action timeout %d", c.Timeout))
	}
	for _, kv := range c.EnvVars {
		if kv.isNotValid() {
			return util.NewValidationError("invalid command env vars")
		}
	}
	c.Args = util.RemoveDuplicates(c.Args, true)
	for _, arg := range c.Args {
		if arg == "" {
			return util.NewValidationError("invalid command args")
		}
	}
	return nil
}

// GetArgumentsAsString returns the list of command arguments as comma separated string
func (c EventActionCommandConfig) GetArgumentsAsString() string {
	return strings.Join(c.Args, ",")
}

// EventActionEmailConfig defines the configuration options for SMTP event actions
type EventActionEmailConfig struct {
	Recipients  []string `json:"recipients,omitempty"`
	Bcc         []string `json:"bcc,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Body        string   `json:"body,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
	ContentType int      `json:"content_type,omitempty"`
}

// GetRecipientsAsString returns the list of recipients as comma separated string
func (c EventActionEmailConfig) GetRecipientsAsString() string {
	return strings.Join(c.Recipients, ",")
}

// GetBccAsString returns the list of bcc as comma separated string
func (c EventActionEmailConfig) GetBccAsString() string {
	return strings.Join(c.Bcc, ",")
}

// GetAttachmentsAsString returns the list of attachments as comma separated string
func (c EventActionEmailConfig) GetAttachmentsAsString() string {
	return strings.Join(c.Attachments, ",")
}

func (c *EventActionEmailConfig) hasFilesAttachments() bool {
	for _, a := range c.Attachments {
		if a != RetentionReportPlaceHolder {
			return true
		}
	}
	return false
}

func (c *EventActionEmailConfig) validate() error {
	if len(c.Recipients) == 0 {
		return util.NewI18nError(
			util.NewValidationError("at least one email recipient is required"),
			util.I18nErrorEmailRecipientRequired,
		)
	}
	c.Recipients = util.RemoveDuplicates(c.Recipients, false)
	for _, r := range c.Recipients {
		if r == "" {
			return util.NewValidationError("invalid email recipients")
		}
	}
	c.Bcc = util.RemoveDuplicates(c.Bcc, false)
	for _, r := range c.Bcc {
		if r == "" {
			return util.NewValidationError("invalid email bcc")
		}
	}
	if c.Subject == "" {
		return util.NewI18nError(
			util.NewValidationError("email subject is required"),
			util.I18nErrorEmailSubjectRequired,
		)
	}
	if c.Body == "" {
		return util.NewI18nError(
			util.NewValidationError("email body is required"),
			util.I18nErrorEmailBodyRequired,
		)
	}
	if c.ContentType < 0 || c.ContentType > 1 {
		return util.NewValidationError("invalid email content type")
	}
	for idx, val := range c.Attachments {
		val = strings.TrimSpace(val)
		if val == "" {
			return util.NewValidationError("invalid path to attach")
		}
		if val == RetentionReportPlaceHolder {
			c.Attachments[idx] = val
		} else {
			c.Attachments[idx] = util.CleanPath(val)
		}
	}
	c.Attachments = util.RemoveDuplicates(c.Attachments, false)
	return nil
}

// FolderRetention defines a folder retention configuration
type FolderRetention struct {
	// Path is the virtual directory path, if no other specific retention is defined,
	// the retention applies for sub directories too. For example if retention is defined
	// for the paths "/" and "/sub" then the retention for "/" is applied for any file outside
	// the "/sub" directory
	Path string `json:"path"`
	// Retention time in hours. 0 means exclude this path
	Retention int `json:"retention"`
	// DeleteEmptyDirs defines if empty directories will be deleted.
	// The user need the delete permission
	DeleteEmptyDirs bool `json:"delete_empty_dirs,omitempty"`
	// IgnoreUserPermissions defines whether to delete files even if the user does not have the delete permission.
	// The default is "false" which means that files will be skipped if the user does not have the permission
	// to delete them. This applies to sub directories too.
	IgnoreUserPermissions bool `json:"ignore_user_permissions,omitempty"`
}

// Validate returns an error if the configuration is not valid
func (f *FolderRetention) Validate() error {
	f.Path = util.CleanPath(f.Path)
	if f.Retention < 0 {
		return util.NewValidationError(fmt.Sprintf("invalid folder retention %v, it must be greater or equal to zero",
			f.Retention))
	}
	return nil
}

// EventActionDataRetentionConfig defines the configuration for a data retention check
type EventActionDataRetentionConfig struct {
	Folders []FolderRetention `json:"folders,omitempty"`
}

func (c *EventActionDataRetentionConfig) validate() error {
	folderPaths := make(map[string]bool)
	nothingToDo := true
	for idx := range c.Folders {
		f := &c.Folders[idx]
		if err := f.Validate(); err != nil {
			return err
		}
		if f.Retention > 0 {
			nothingToDo = false
		}
		if _, ok := folderPaths[f.Path]; ok {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("duplicated folder path %q", f.Path)),
				util.I18nErrorPathDuplicated,
			)
		}
		folderPaths[f.Path] = true
	}
	if nothingToDo {
		return util.NewI18nError(
			util.NewValidationError("nothing to delete!"),
			util.I18nErrorRetentionDirRequired,
		)
	}
	return nil
}

// EventActionFsCompress defines the configuration for the compress filesystem action
type EventActionFsCompress struct {
	// Archive path
	Name string `json:"name,omitempty"`
	// Paths to compress
	Paths []string `json:"paths,omitempty"`
}

func (c *EventActionFsCompress) validate() error {
	if c.Name == "" {
		return util.NewI18nError(util.NewValidationError("archive name is mandatory"), util.I18nErrorArchiveNameRequired)
	}
	c.Name = util.CleanPath(strings.TrimSpace(c.Name))
	if c.Name == "/" {
		return util.NewI18nError(util.NewValidationError("invalid archive name"), util.I18nErrorRootNotAllowed)
	}
	if len(c.Paths) == 0 {
		return util.NewI18nError(util.NewValidationError("no path to compress specified"), util.I18nErrorPathRequired)
	}
	for idx, val := range c.Paths {
		val = strings.TrimSpace(val)
		if val == "" {
			return util.NewValidationError("invalid path to compress")
		}
		c.Paths[idx] = util.CleanPath(val)
	}
	c.Paths = util.RemoveDuplicates(c.Paths, false)
	return nil
}

// EventActionFilesystemConfig defines the configuration for filesystem actions
type EventActionFilesystemConfig struct {
	// Filesystem actions, see the above enum
	Type int `json:"type,omitempty"`
	// files/dirs to rename, key is the source and target the value
	Renames []KeyValue `json:"renames,omitempty"`
	// directories to create
	MkDirs []string `json:"mkdirs,omitempty"`
	// files/dirs to delete
	Deletes []string `json:"deletes,omitempty"`
	// file/dirs to check for existence
	Exist []string `json:"exist,omitempty"`
	// files/dirs to copy, key is the source and target the value
	Copy []KeyValue `json:"copy,omitempty"`
	// paths to compress and archive name
	Compress EventActionFsCompress `json:"compress"`
}

// GetDeletesAsString returns the list of items to delete as comma separated string.
// Using a pointer receiver will not work in web templates
func (c EventActionFilesystemConfig) GetDeletesAsString() string {
	return strings.Join(c.Deletes, ",")
}

// GetMkDirsAsString returns the list of directories to create as comma separated string.
// Using a pointer receiver will not work in web templates
func (c EventActionFilesystemConfig) GetMkDirsAsString() string {
	return strings.Join(c.MkDirs, ",")
}

// GetExistAsString returns the list of items to check for existence as comma separated string.
// Using a pointer receiver will not work in web templates
func (c EventActionFilesystemConfig) GetExistAsString() string {
	return strings.Join(c.Exist, ",")
}

// GetCompressPathsAsString returns the list of items to compress as comma separated string.
// Using a pointer receiver will not work in web templates
func (c EventActionFilesystemConfig) GetCompressPathsAsString() string {
	return strings.Join(c.Compress.Paths, ",")
}

func (c *EventActionFilesystemConfig) validateRenames() error {
	if len(c.Renames) == 0 {
		return util.NewI18nError(util.NewValidationError("no path to rename specified"), util.I18nErrorPathRequired)
	}
	for idx, kv := range c.Renames {
		key := strings.TrimSpace(kv.Key)
		value := strings.TrimSpace(kv.Value)
		if key == "" || value == "" {
			return util.NewValidationError("invalid paths to rename")
		}
		key = util.CleanPath(key)
		value = util.CleanPath(value)
		if key == value {
			return util.NewI18nError(
				util.NewValidationError("rename source and target cannot be equal"),
				util.I18nErrorSourceDestMatch,
			)
		}
		if key == "/" || value == "/" {
			return util.NewI18nError(
				util.NewValidationError("renaming the root directory is not allowed"),
				util.I18nErrorRootNotAllowed,
			)
		}
		c.Renames[idx] = KeyValue{
			Key:   key,
			Value: value,
		}
	}
	return nil
}

func (c *EventActionFilesystemConfig) validateCopy() error {
	if len(c.Copy) == 0 {
		return util.NewI18nError(util.NewValidationError("no path to copy specified"), util.I18nErrorPathRequired)
	}
	for idx, kv := range c.Copy {
		key := strings.TrimSpace(kv.Key)
		value := strings.TrimSpace(kv.Value)
		if key == "" || value == "" {
			return util.NewValidationError("invalid paths to copy")
		}
		key = util.CleanPath(key)
		value = util.CleanPath(value)
		if key == value {
			return util.NewI18nError(
				util.NewValidationError("copy source and target cannot be equal"),
				util.I18nErrorSourceDestMatch,
			)
		}
		if key == "/" || value == "/" {
			return util.NewI18nError(
				util.NewValidationError("copying the root directory is not allowed"),
				util.I18nErrorRootNotAllowed,
			)
		}
		if strings.HasSuffix(c.Copy[idx].Key, "/") {
			key += "/"
		}
		if strings.HasSuffix(c.Copy[idx].Value, "/") {
			value += "/"
		}
		c.Copy[idx] = KeyValue{
			Key:   key,
			Value: value,
		}
	}
	return nil
}

func (c *EventActionFilesystemConfig) validateDeletes() error {
	if len(c.Deletes) == 0 {
		return util.NewI18nError(util.NewValidationError("no path to delete specified"), util.I18nErrorPathRequired)
	}
	for idx, val := range c.Deletes {
		val = strings.TrimSpace(val)
		if val == "" {
			return util.NewValidationError("invalid path to delete")
		}
		c.Deletes[idx] = util.CleanPath(val)
	}
	c.Deletes = util.RemoveDuplicates(c.Deletes, false)
	return nil
}

func (c *EventActionFilesystemConfig) validateMkdirs() error {
	if len(c.MkDirs) == 0 {
		return util.NewI18nError(util.NewValidationError("no directory to create specified"), util.I18nErrorPathRequired)
	}
	for idx, val := range c.MkDirs {
		val = strings.TrimSpace(val)
		if val == "" {
			return util.NewValidationError("invalid directory to create")
		}
		c.MkDirs[idx] = util.CleanPath(val)
	}
	c.MkDirs = util.RemoveDuplicates(c.MkDirs, false)
	return nil
}

func (c *EventActionFilesystemConfig) validateExist() error {
	if len(c.Exist) == 0 {
		return util.NewI18nError(util.NewValidationError("no path to check for existence specified"), util.I18nErrorPathRequired)
	}
	for idx, val := range c.Exist {
		val = strings.TrimSpace(val)
		if val == "" {
			return util.NewValidationError("invalid path to check for existence")
		}
		c.Exist[idx] = util.CleanPath(val)
	}
	c.Exist = util.RemoveDuplicates(c.Exist, false)
	return nil
}

func (c *EventActionFilesystemConfig) validate() error {
	if !isFilesystemActionValid(c.Type) {
		return util.NewValidationError(fmt.Sprintf("invalid filesystem action type: %d", c.Type))
	}
	switch c.Type {
	case FilesystemActionRename:
		c.MkDirs = nil
		c.Deletes = nil
		c.Exist = nil
		c.Copy = nil
		c.Compress = EventActionFsCompress{}
		if err := c.validateRenames(); err != nil {
			return err
		}
	case FilesystemActionDelete:
		c.Renames = nil
		c.MkDirs = nil
		c.Exist = nil
		c.Copy = nil
		c.Compress = EventActionFsCompress{}
		if err := c.validateDeletes(); err != nil {
			return err
		}
	case FilesystemActionMkdirs:
		c.Renames = nil
		c.Deletes = nil
		c.Exist = nil
		c.Copy = nil
		c.Compress = EventActionFsCompress{}
		if err := c.validateMkdirs(); err != nil {
			return err
		}
	case FilesystemActionExist:
		c.Renames = nil
		c.Deletes = nil
		c.MkDirs = nil
		c.Copy = nil
		c.Compress = EventActionFsCompress{}
		if err := c.validateExist(); err != nil {
			return err
		}
	case FilesystemActionCompress:
		c.Renames = nil
		c.MkDirs = nil
		c.Deletes = nil
		c.Exist = nil
		c.Copy = nil
		if err := c.Compress.validate(); err != nil {
			return err
		}
	case FilesystemActionCopy:
		c.Renames = nil
		c.Deletes = nil
		c.MkDirs = nil
		c.Exist = nil
		c.Compress = EventActionFsCompress{}
		if err := c.validateCopy(); err != nil {
			return err
		}
	}
	return nil
}

func (c *EventActionFilesystemConfig) getACopy() EventActionFilesystemConfig {
	mkdirs := make([]string, len(c.MkDirs))
	copy(mkdirs, c.MkDirs)
	deletes := make([]string, len(c.Deletes))
	copy(deletes, c.Deletes)
	exist := make([]string, len(c.Exist))
	copy(exist, c.Exist)
	compressPaths := make([]string, len(c.Compress.Paths))
	copy(compressPaths, c.Compress.Paths)

	return EventActionFilesystemConfig{
		Type:    c.Type,
		Renames: cloneKeyValues(c.Renames),
		MkDirs:  mkdirs,
		Deletes: deletes,
		Exist:   exist,
		Copy:    cloneKeyValues(c.Copy),
		Compress: EventActionFsCompress{
			Paths: compressPaths,
			Name:  c.Compress.Name,
		},
	}
}

// EventActionPasswordExpiration defines the configuration for password expiration actions
type EventActionPasswordExpiration struct {
	// An email notification will be generated for users whose password expires in a number
	// of days less than or equal to this threshold
	Threshold int `json:"threshold,omitempty"`
}

func (c *EventActionPasswordExpiration) validate() error {
	if c.Threshold <= 0 {
		return util.NewValidationError("threshold must be greater than 0")
	}
	return nil
}

// EventActionUserInactivity defines the configuration for user inactivity checks.
type EventActionUserInactivity struct {
	// DisableThreshold defines inactivity in days, since the last login before disabling the account
	DisableThreshold int `json:"disable_threshold,omitempty"`
	// DeleteThreshold defines inactivity in days, since the last login before deleting the account
	DeleteThreshold int `json:"delete_threshold,omitempty"`
}

func (c *EventActionUserInactivity) validate() error {
	if c.DeleteThreshold < 0 {
		c.DeleteThreshold = 0
	}
	if c.DisableThreshold < 0 {
		c.DisableThreshold = 0
	}
	if c.DisableThreshold == 0 && c.DeleteThreshold == 0 {
		return util.NewI18nError(
			util.NewValidationError("at least a threshold must be defined"),
			util.I18nActionThresholdRequired,
		)
	}
	if c.DeleteThreshold > 0 && c.DisableThreshold > 0 {
		if c.DeleteThreshold <= c.DisableThreshold {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("deletion threshold %d must be greater than deactivation threshold: %d", c.DeleteThreshold, c.DisableThreshold)),
				util.I18nActionThresholdsInvalid,
			)
		}
	}
	return nil
}

// EventActionIDPAccountCheck defines the check to execute after a successful IDP login
type EventActionIDPAccountCheck struct {
	// 0 create/update, 1 create the account if it doesn't exist
	Mode          int    `json:"mode,omitempty"`
	TemplateUser  string `json:"template_user,omitempty"`
	TemplateAdmin string `json:"template_admin,omitempty"`
}

func (c *EventActionIDPAccountCheck) validate() error {
	if c.TemplateAdmin == "" && c.TemplateUser == "" {
		return util.NewI18nError(
			util.NewValidationError("at least a template must be set"),
			util.I18nErrorIDPTemplateRequired,
		)
	}
	if c.Mode < 0 || c.Mode > 1 {
		return util.NewValidationError(fmt.Sprintf("invalid account check mode: %d", c.Mode))
	}
	return nil
}

// BaseEventActionOptions defines the supported configuration options for a base event actions
type BaseEventActionOptions struct {
	HTTPConfig           EventActionHTTPConfig          `json:"http_config"`
	CmdConfig            EventActionCommandConfig       `json:"cmd_config"`
	EmailConfig          EventActionEmailConfig         `json:"email_config"`
	RetentionConfig      EventActionDataRetentionConfig `json:"retention_config"`
	FsConfig             EventActionFilesystemConfig    `json:"fs_config"`
	PwdExpirationConfig  EventActionPasswordExpiration  `json:"pwd_expiration_config"`
	UserInactivityConfig EventActionUserInactivity      `json:"user_inactivity_config"`
	IDPConfig            EventActionIDPAccountCheck     `json:"idp_config"`
}

func (o *BaseEventActionOptions) getACopy() BaseEventActionOptions {
	o.SetEmptySecretsIfNil()
	emailRecipients := make([]string, len(o.EmailConfig.Recipients))
	copy(emailRecipients, o.EmailConfig.Recipients)
	emailBcc := make([]string, len(o.EmailConfig.Bcc))
	copy(emailBcc, o.EmailConfig.Bcc)
	emailAttachments := make([]string, len(o.EmailConfig.Attachments))
	copy(emailAttachments, o.EmailConfig.Attachments)
	cmdArgs := make([]string, len(o.CmdConfig.Args))
	copy(cmdArgs, o.CmdConfig.Args)
	folders := make([]FolderRetention, 0, len(o.RetentionConfig.Folders))
	for _, folder := range o.RetentionConfig.Folders {
		folders = append(folders, FolderRetention{
			Path:                  folder.Path,
			Retention:             folder.Retention,
			DeleteEmptyDirs:       folder.DeleteEmptyDirs,
			IgnoreUserPermissions: folder.IgnoreUserPermissions,
		})
	}
	httpParts := make([]HTTPPart, 0, len(o.HTTPConfig.Parts))
	for _, part := range o.HTTPConfig.Parts {
		httpParts = append(httpParts, HTTPPart{
			Name:     part.Name,
			Filepath: part.Filepath,
			Headers:  cloneKeyValues(part.Headers),
			Body:     part.Body,
		})
	}

	return BaseEventActionOptions{
		HTTPConfig: EventActionHTTPConfig{
			Endpoint:        o.HTTPConfig.Endpoint,
			Username:        o.HTTPConfig.Username,
			Password:        o.HTTPConfig.Password.Clone(),
			Headers:         cloneKeyValues(o.HTTPConfig.Headers),
			Timeout:         o.HTTPConfig.Timeout,
			SkipTLSVerify:   o.HTTPConfig.SkipTLSVerify,
			Method:          o.HTTPConfig.Method,
			QueryParameters: cloneKeyValues(o.HTTPConfig.QueryParameters),
			Body:            o.HTTPConfig.Body,
			Parts:           httpParts,
		},
		CmdConfig: EventActionCommandConfig{
			Cmd:     o.CmdConfig.Cmd,
			Args:    cmdArgs,
			Timeout: o.CmdConfig.Timeout,
			EnvVars: cloneKeyValues(o.CmdConfig.EnvVars),
		},
		EmailConfig: EventActionEmailConfig{
			Recipients:  emailRecipients,
			Bcc:         emailBcc,
			Subject:     o.EmailConfig.Subject,
			ContentType: o.EmailConfig.ContentType,
			Body:        o.EmailConfig.Body,
			Attachments: emailAttachments,
		},
		RetentionConfig: EventActionDataRetentionConfig{
			Folders: folders,
		},
		PwdExpirationConfig: EventActionPasswordExpiration{
			Threshold: o.PwdExpirationConfig.Threshold,
		},
		UserInactivityConfig: EventActionUserInactivity{
			DisableThreshold: o.UserInactivityConfig.DisableThreshold,
			DeleteThreshold:  o.UserInactivityConfig.DeleteThreshold,
		},
		IDPConfig: EventActionIDPAccountCheck{
			Mode:          o.IDPConfig.Mode,
			TemplateUser:  o.IDPConfig.TemplateUser,
			TemplateAdmin: o.IDPConfig.TemplateAdmin,
		},
		FsConfig: o.FsConfig.getACopy(),
	}
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (o *BaseEventActionOptions) SetEmptySecretsIfNil() {
	if o.HTTPConfig.Password == nil {
		o.HTTPConfig.Password = kms.NewEmptySecret()
	}
}

func (o *BaseEventActionOptions) setNilSecretsIfEmpty() {
	if o.HTTPConfig.Password != nil && o.HTTPConfig.Password.IsEmpty() {
		o.HTTPConfig.Password = nil
	}
}

func (o *BaseEventActionOptions) hideConfidentialData() {
	if o.HTTPConfig.Password != nil {
		o.HTTPConfig.Password.Hide()
	}
}

func (o *BaseEventActionOptions) validate(action int, name string) error {
	o.SetEmptySecretsIfNil()
	switch action {
	case ActionTypeHTTP:
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.HTTPConfig.validate(name)
	case ActionTypeCommand:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.CmdConfig.validate()
	case ActionTypeEmail:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.EmailConfig.validate()
	case ActionTypeDataRetentionCheck:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.RetentionConfig.validate()
	case ActionTypeFilesystem:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.FsConfig.validate()
	case ActionTypePasswordExpirationCheck:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.PwdExpirationConfig.validate()
	case ActionTypeUserInactivityCheck:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		return o.UserInactivityConfig.validate()
	case ActionTypeIDPAccountCheck:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.UserInactivityConfig = EventActionUserInactivity{}
		return o.IDPConfig.validate()
	default:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		o.RetentionConfig = EventActionDataRetentionConfig{}
		o.FsConfig = EventActionFilesystemConfig{}
		o.PwdExpirationConfig = EventActionPasswordExpiration{}
		o.IDPConfig = EventActionIDPAccountCheck{}
		o.UserInactivityConfig = EventActionUserInactivity{}
	}
	return nil
}

// BaseEventAction defines the common fields for an event action
type BaseEventAction struct {
	// Data provider unique identifier
	ID int64 `json:"id"`
	// Action name
	Name string `json:"name"`
	// optional description
	Description string `json:"description,omitempty"`
	// ActionType, see the above enum
	Type int `json:"type"`
	// Configuration options specific for the action type
	Options BaseEventActionOptions `json:"options"`
	// list of rule names associated with this event action
	Rules []string `json:"rules,omitempty"`
}

func (a *BaseEventAction) getACopy() BaseEventAction {
	rules := make([]string, len(a.Rules))
	copy(rules, a.Rules)
	return BaseEventAction{
		ID:          a.ID,
		Name:        a.Name,
		Description: a.Description,
		Type:        a.Type,
		Options:     a.Options.getACopy(),
		Rules:       rules,
	}
}

// GetTypeAsString returns the action type as string
func (a *BaseEventAction) GetTypeAsString() string {
	return getActionTypeAsString(a.Type)
}

// GetRulesAsString returns the list of rules as comma separated string
func (a *BaseEventAction) GetRulesAsString() string {
	return strings.Join(a.Rules, ",")
}

// PrepareForRendering prepares a BaseEventAction for rendering.
// It hides confidential data and set to nil the empty secrets
// so they are not serialized
func (a *BaseEventAction) PrepareForRendering() {
	a.Options.setNilSecretsIfEmpty()
	a.Options.hideConfidentialData()
}

// RenderAsJSON implements the renderer interface used within plugins
func (a *BaseEventAction) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		action, err := provider.eventActionExists(a.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload event action before rendering as json: %v", err)
			return nil, err
		}
		action.PrepareForRendering()
		return json.Marshal(action)
	}
	a.PrepareForRendering()
	return json.Marshal(a)
}

func (a *BaseEventAction) validate() error {
	if a.Name == "" {
		return util.NewI18nError(util.NewValidationError("name is mandatory"), util.I18nErrorNameRequired)
	}
	if !isActionTypeValid(a.Type) {
		return util.NewValidationError(fmt.Sprintf("invalid action type: %d", a.Type))
	}
	return a.Options.validate(a.Type, a.Name)
}

// EventActionOptions defines the supported configuration options for an event action
type EventActionOptions struct {
	IsFailureAction bool `json:"is_failure_action"`
	StopOnFailure   bool `json:"stop_on_failure"`
	ExecuteSync     bool `json:"execute_sync"`
}

// EventAction defines an event action
type EventAction struct {
	BaseEventAction
	// Order defines the execution order
	Order   int                `json:"order,omitempty"`
	Options EventActionOptions `json:"relation_options"`
}

func (a *EventAction) getACopy() EventAction {
	return EventAction{
		BaseEventAction: a.BaseEventAction.getACopy(),
		Order:           a.Order,
		Options: EventActionOptions{
			IsFailureAction: a.Options.IsFailureAction,
			StopOnFailure:   a.Options.StopOnFailure,
			ExecuteSync:     a.Options.ExecuteSync,
		},
	}
}

func (a *EventAction) validateAssociation(trigger int, fsEvents []string) error {
	if a.Options.IsFailureAction {
		if a.Options.ExecuteSync {
			return util.NewI18nError(
				util.NewValidationError("sync execution is not supported for failure actions"),
				util.I18nErrorEvSyncFailureActions,
			)
		}
	}
	if a.Options.ExecuteSync {
		if trigger != EventTriggerFsEvent && trigger != EventTriggerIDPLogin {
			return util.NewI18nError(
				util.NewValidationError("sync execution is only supported for some filesystem events and Identity Provider logins"),
				util.I18nErrorEvSyncUnsupported,
			)
		}
		if trigger == EventTriggerFsEvent {
			for _, ev := range fsEvents {
				if !util.Contains(allowedSyncFsEvents, ev) {
					return util.NewI18nError(
						util.NewValidationError("sync execution is only supported for upload and pre-* events"),
						util.I18nErrorEvSyncUnsupportedFs,
					)
				}
			}
		}
	}
	return nil
}

// ConditionPattern defines a pattern for condition filters
type ConditionPattern struct {
	Pattern      string `json:"pattern,omitempty"`
	InverseMatch bool   `json:"inverse_match,omitempty"`
}

func (p *ConditionPattern) validate() error {
	if p.Pattern == "" {
		return util.NewValidationError("empty condition pattern not allowed")
	}
	_, err := path.Match(p.Pattern, "abc")
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("invalid condition pattern %q", p.Pattern))
	}
	return nil
}

// ConditionOptions defines options for event conditions
type ConditionOptions struct {
	// Usernames or folder names
	Names []ConditionPattern `json:"names,omitempty"`
	// Group names
	GroupNames []ConditionPattern `json:"group_names,omitempty"`
	// Role names
	RoleNames []ConditionPattern `json:"role_names,omitempty"`
	// Virtual paths
	FsPaths         []ConditionPattern `json:"fs_paths,omitempty"`
	Protocols       []string           `json:"protocols,omitempty"`
	ProviderObjects []string           `json:"provider_objects,omitempty"`
	MinFileSize     int64              `json:"min_size,omitempty"`
	MaxFileSize     int64              `json:"max_size,omitempty"`
	// allow to execute scheduled tasks concurrently from multiple instances
	ConcurrentExecution bool `json:"concurrent_execution,omitempty"`
}

func (f *ConditionOptions) getACopy() ConditionOptions {
	protocols := make([]string, len(f.Protocols))
	copy(protocols, f.Protocols)
	providerObjects := make([]string, len(f.ProviderObjects))
	copy(providerObjects, f.ProviderObjects)

	return ConditionOptions{
		Names:               cloneConditionPatterns(f.Names),
		GroupNames:          cloneConditionPatterns(f.GroupNames),
		RoleNames:           cloneConditionPatterns(f.RoleNames),
		FsPaths:             cloneConditionPatterns(f.FsPaths),
		Protocols:           protocols,
		ProviderObjects:     providerObjects,
		MinFileSize:         f.MinFileSize,
		MaxFileSize:         f.MaxFileSize,
		ConcurrentExecution: f.ConcurrentExecution,
	}
}

func (f *ConditionOptions) validate() error {
	if err := validateConditionPatterns(f.Names); err != nil {
		return err
	}
	if err := validateConditionPatterns(f.GroupNames); err != nil {
		return err
	}
	if err := validateConditionPatterns(f.RoleNames); err != nil {
		return err
	}
	if err := validateConditionPatterns(f.FsPaths); err != nil {
		return err
	}

	for _, p := range f.Protocols {
		if !util.Contains(SupportedRuleConditionProtocols, p) {
			return util.NewValidationError(fmt.Sprintf("unsupported rule condition protocol: %q", p))
		}
	}
	for _, p := range f.ProviderObjects {
		if !util.Contains(SupporteRuleConditionProviderObjects, p) {
			return util.NewValidationError(fmt.Sprintf("unsupported provider object: %q", p))
		}
	}
	if f.MinFileSize > 0 && f.MaxFileSize > 0 {
		if f.MaxFileSize <= f.MinFileSize {
			return util.NewValidationError(fmt.Sprintf("invalid max file size %s, it is lesser or equal than min file size %s",
				util.ByteCountSI(f.MaxFileSize), util.ByteCountSI(f.MinFileSize)))
		}
	}
	if config.IsShared == 0 {
		f.ConcurrentExecution = false
	}
	return nil
}

// Schedule defines an event schedule
type Schedule struct {
	Hours      string `json:"hour"`
	DayOfWeek  string `json:"day_of_week"`
	DayOfMonth string `json:"day_of_month"`
	Month      string `json:"month"`
}

// GetCronSpec returns the cron compatible schedule string
func (s *Schedule) GetCronSpec() string {
	return fmt.Sprintf("0 %s %s %s %s", s.Hours, s.DayOfMonth, s.Month, s.DayOfWeek)
}

func (s *Schedule) validate() error {
	_, err := cron.ParseStandard(s.GetCronSpec())
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("invalid schedule, hour: %q, day of month: %q, month: %q, day of week: %q",
			s.Hours, s.DayOfMonth, s.Month, s.DayOfWeek))
	}
	return nil
}

// EventConditions defines the conditions for an event rule
type EventConditions struct {
	// Only one between FsEvents, ProviderEvents and Schedule is allowed
	FsEvents       []string   `json:"fs_events,omitempty"`
	ProviderEvents []string   `json:"provider_events,omitempty"`
	Schedules      []Schedule `json:"schedules,omitempty"`
	// 0 any, 1 user, 2 admin
	IDPLoginEvent int              `json:"idp_login_event,omitempty"`
	Options       ConditionOptions `json:"options"`
}

func (c *EventConditions) getACopy() EventConditions {
	fsEvents := make([]string, len(c.FsEvents))
	copy(fsEvents, c.FsEvents)
	providerEvents := make([]string, len(c.ProviderEvents))
	copy(providerEvents, c.ProviderEvents)
	schedules := make([]Schedule, 0, len(c.Schedules))
	for _, schedule := range c.Schedules {
		schedules = append(schedules, Schedule{
			Hours:      schedule.Hours,
			DayOfWeek:  schedule.DayOfWeek,
			DayOfMonth: schedule.DayOfMonth,
			Month:      schedule.Month,
		})
	}

	return EventConditions{
		FsEvents:       fsEvents,
		ProviderEvents: providerEvents,
		Schedules:      schedules,
		IDPLoginEvent:  c.IDPLoginEvent,
		Options:        c.Options.getACopy(),
	}
}

func (c *EventConditions) validateSchedules() error {
	if len(c.Schedules) == 0 {
		return util.NewI18nError(
			util.NewValidationError("at least one schedule is required"),
			util.I18nErrorRuleScheduleRequired,
		)
	}
	for _, schedule := range c.Schedules {
		if err := schedule.validate(); err != nil {
			return util.NewI18nError(err, util.I18nErrorRuleScheduleInvalid)
		}
	}
	return nil
}

func (c *EventConditions) validate(trigger int) error {
	switch trigger {
	case EventTriggerFsEvent:
		c.ProviderEvents = nil
		c.Schedules = nil
		c.Options.ProviderObjects = nil
		c.IDPLoginEvent = 0
		if len(c.FsEvents) == 0 {
			return util.NewI18nError(
				util.NewValidationError("at least one filesystem event is required"),
				util.I18nErrorRuleFsEventRequired,
			)
		}
		for _, ev := range c.FsEvents {
			if !util.Contains(SupportedFsEvents, ev) {
				return util.NewValidationError(fmt.Sprintf("unsupported fs event: %q", ev))
			}
		}
	case EventTriggerProviderEvent:
		c.FsEvents = nil
		c.Schedules = nil
		c.Options.GroupNames = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.IDPLoginEvent = 0
		if len(c.ProviderEvents) == 0 {
			return util.NewI18nError(
				util.NewValidationError("at least one provider event is required"),
				util.I18nErrorRuleProviderEventRequired,
			)
		}
		for _, ev := range c.ProviderEvents {
			if !util.Contains(SupportedProviderEvents, ev) {
				return util.NewValidationError(fmt.Sprintf("unsupported provider event: %q", ev))
			}
		}
	case EventTriggerSchedule:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Options.ProviderObjects = nil
		c.IDPLoginEvent = 0
		if err := c.validateSchedules(); err != nil {
			return err
		}
	case EventTriggerIPBlocked, EventTriggerCertificate:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.Names = nil
		c.Options.GroupNames = nil
		c.Options.RoleNames = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Schedules = nil
		c.IDPLoginEvent = 0
	case EventTriggerOnDemand:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Options.ProviderObjects = nil
		c.Schedules = nil
		c.IDPLoginEvent = 0
		c.Options.ConcurrentExecution = false
	case EventTriggerIDPLogin:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.GroupNames = nil
		c.Options.RoleNames = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Schedules = nil
		if !util.Contains(supportedIDPLoginEvents, c.IDPLoginEvent) {
			return util.NewValidationError(fmt.Sprintf("invalid Identity Provider login event %d", c.IDPLoginEvent))
		}
	default:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.GroupNames = nil
		c.Options.RoleNames = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Schedules = nil
		c.IDPLoginEvent = 0
	}

	return c.Options.validate()
}

// EventRule defines the trigger, conditions and actions for an event
type EventRule struct {
	// Data provider unique identifier
	ID int64 `json:"id"`
	// Rule name
	Name string `json:"name"`
	// 1 enabled, 0 disabled
	Status int `json:"status"`
	// optional description
	Description string `json:"description,omitempty"`
	// Creation time as unix timestamp in milliseconds
	CreatedAt int64 `json:"created_at"`
	// last update time as unix timestamp in milliseconds
	UpdatedAt int64 `json:"updated_at"`
	// Event trigger
	Trigger int `json:"trigger"`
	// Event conditions
	Conditions EventConditions `json:"conditions"`
	// actions to execute
	Actions []EventAction `json:"actions"`
	// in multi node setups we mark the rule as deleted to be able to update the cache
	DeletedAt int64 `json:"-"`
}

func (r *EventRule) getACopy() EventRule {
	actions := make([]EventAction, 0, len(r.Actions))
	for _, action := range r.Actions {
		actions = append(actions, action.getACopy())
	}

	return EventRule{
		ID:          r.ID,
		Name:        r.Name,
		Status:      r.Status,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		Trigger:     r.Trigger,
		Conditions:  r.Conditions.getACopy(),
		Actions:     actions,
		DeletedAt:   r.DeletedAt,
	}
}

// GuardFromConcurrentExecution returns true if the rule cannot be executed concurrently
// from multiple instances
func (r *EventRule) GuardFromConcurrentExecution() bool {
	if config.IsShared == 0 {
		return false
	}
	return !r.Conditions.Options.ConcurrentExecution
}

// GetTriggerAsString returns the rule trigger as string
func (r *EventRule) GetTriggerAsString() string {
	return getTriggerTypeAsString(r.Trigger)
}

// GetActionsAsString returns the list of action names as comma separated string
func (r *EventRule) GetActionsAsString() string {
	actions := make([]string, 0, len(r.Actions))
	for _, action := range r.Actions {
		actions = append(actions, action.Name)
	}
	return strings.Join(actions, ",")
}

func (r *EventRule) isStatusValid() bool {
	return r.Status >= 0 && r.Status <= 1
}

func (r *EventRule) validate() error {
	if r.Name == "" {
		return util.NewI18nError(util.NewValidationError("name is mandatory"), util.I18nErrorNameRequired)
	}
	if !r.isStatusValid() {
		return util.NewValidationError(fmt.Sprintf("invalid event rule status: %d", r.Status))
	}
	if !isEventTriggerValid(r.Trigger) {
		return util.NewValidationError(fmt.Sprintf("invalid event rule trigger: %d", r.Trigger))
	}
	if err := r.Conditions.validate(r.Trigger); err != nil {
		return err
	}
	if len(r.Actions) == 0 {
		return util.NewI18nError(util.NewValidationError("at least one action is required"), util.I18nErrorRuleActionRequired)
	}
	actionNames := make(map[string]bool)
	actionOrders := make(map[int]bool)
	failureActions := 0
	hasSyncAction := false
	for idx := range r.Actions {
		if r.Actions[idx].Name == "" {
			return util.NewValidationError(fmt.Sprintf("invalid action at position %d, name not specified", idx))
		}
		if actionNames[r.Actions[idx].Name] {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("duplicated action %q", r.Actions[idx].Name)),
				util.I18nErrorRuleDuplicateActions,
			)
		}
		if actionOrders[r.Actions[idx].Order] {
			return util.NewValidationError(fmt.Sprintf("duplicated order %d for action %q",
				r.Actions[idx].Order, r.Actions[idx].Name))
		}
		if err := r.Actions[idx].validateAssociation(r.Trigger, r.Conditions.FsEvents); err != nil {
			return err
		}
		if r.Actions[idx].Options.IsFailureAction {
			failureActions++
		}
		if r.Actions[idx].Options.ExecuteSync {
			hasSyncAction = true
		}
		actionNames[r.Actions[idx].Name] = true
		actionOrders[r.Actions[idx].Order] = true
	}
	if len(r.Actions) == failureActions {
		return util.NewI18nError(
			util.NewValidationError("at least a non-failure action is required"),
			util.I18nErrorRuleFailureActionsOnly,
		)
	}
	if !hasSyncAction {
		return r.validateMandatorySyncActions()
	}
	return nil
}

func (r *EventRule) validateMandatorySyncActions() error {
	if r.Trigger != EventTriggerFsEvent {
		return nil
	}
	for _, ev := range r.Conditions.FsEvents {
		if util.Contains(mandatorySyncFsEvents, ev) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("event %q requires at least a sync action", ev)),
				util.I18nErrorRuleSyncActionRequired,
				util.I18nErrorArgs(map[string]any{
					"val": ev,
				}),
			)
		}
	}
	return nil
}

func (r *EventRule) checkIPBlockedAndCertificateActions() error {
	unavailableActions := []int{ActionTypeUserQuotaReset, ActionTypeFolderQuotaReset, ActionTypeTransferQuotaReset,
		ActionTypeDataRetentionCheck, ActionTypeFilesystem, ActionTypePasswordExpirationCheck,
		ActionTypeUserExpirationCheck}
	for _, action := range r.Actions {
		if util.Contains(unavailableActions, action.Type) {
			return fmt.Errorf("action %q, type %q is not supported for event trigger %q",
				action.Name, getActionTypeAsString(action.Type), getTriggerTypeAsString(r.Trigger))
		}
	}
	return nil
}

func (r *EventRule) checkProviderEventActions(providerObjectType string) error {
	// user quota reset, transfer quota reset, data retention check and filesystem actions
	// can be executed only if we modify a user. They will be executed for the
	// affected user. Folder quota reset can be executed only for folders.
	userSpecificActions := []int{ActionTypeUserQuotaReset, ActionTypeTransferQuotaReset,
		ActionTypeDataRetentionCheck, ActionTypeFilesystem,
		ActionTypePasswordExpirationCheck, ActionTypeUserExpirationCheck}
	for _, action := range r.Actions {
		if util.Contains(userSpecificActions, action.Type) && providerObjectType != actionObjectUser {
			return fmt.Errorf("action %q, type %q is only supported for provider user events",
				action.Name, getActionTypeAsString(action.Type))
		}
		if action.Type == ActionTypeFolderQuotaReset && providerObjectType != actionObjectFolder {
			return fmt.Errorf("action %q, type %q is only supported for provider folder events",
				action.Name, getActionTypeAsString(action.Type))
		}
	}
	return nil
}

func (r *EventRule) hasUserAssociated(providerObjectType string) bool {
	switch r.Trigger {
	case EventTriggerProviderEvent:
		return providerObjectType == actionObjectUser
	case EventTriggerFsEvent:
		return true
	default:
		if len(r.Actions) > 0 {
			// should we allow schedules where backup is not the first action?
			// maybe we could pass the action index and check before that index
			return r.Actions[0].Type == ActionTypeBackup
		}
	}
	return false
}

func (r *EventRule) checkActions(providerObjectType string) error {
	numSyncAction := 0
	hasIDPAccountCheck := false
	for _, action := range r.Actions {
		if action.Options.ExecuteSync {
			numSyncAction++
		}
		if action.Type == ActionTypeEmail && action.BaseEventAction.Options.EmailConfig.hasFilesAttachments() {
			if !r.hasUserAssociated(providerObjectType) {
				return errors.New("cannot send an email with attachments for a rule with no user associated")
			}
		}
		if action.Type == ActionTypeHTTP && action.BaseEventAction.Options.HTTPConfig.HasMultipartFiles() {
			if !r.hasUserAssociated(providerObjectType) {
				return errors.New("cannot upload file/s for a rule with no user associated")
			}
		}
		if action.Type == ActionTypeIDPAccountCheck {
			if r.Trigger != EventTriggerIDPLogin {
				return errors.New("IDP account check action is only supported for IDP login trigger")
			}
			if !action.Options.ExecuteSync {
				return errors.New("IDP account check must be a sync action")
			}
			hasIDPAccountCheck = true
		}
	}
	if hasIDPAccountCheck && numSyncAction != 1 {
		return errors.New("IDP account check must be the only sync action")
	}
	return nil
}

// CheckActionsConsistency returns an error if the actions cannot be executed
func (r *EventRule) CheckActionsConsistency(providerObjectType string) error {
	switch r.Trigger {
	case EventTriggerProviderEvent:
		if err := r.checkProviderEventActions(providerObjectType); err != nil {
			return err
		}
	case EventTriggerFsEvent:
		// folder quota reset cannot be executed
		for _, action := range r.Actions {
			if action.Type == ActionTypeFolderQuotaReset {
				return fmt.Errorf("action %q, type %q is not supported for filesystem events",
					action.Name, getActionTypeAsString(action.Type))
			}
		}
	case EventTriggerIPBlocked, EventTriggerCertificate:
		if err := r.checkIPBlockedAndCertificateActions(); err != nil {
			return err
		}
	}
	return r.checkActions(providerObjectType)
}

// PrepareForRendering prepares an EventRule for rendering.
// It hides confidential data and set to nil the empty secrets
// so they are not serialized
func (r *EventRule) PrepareForRendering() {
	for idx := range r.Actions {
		r.Actions[idx].PrepareForRendering()
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (r *EventRule) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		rule, err := provider.eventRuleExists(r.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload event rule before rendering as json: %v", err)
			return nil, err
		}
		rule.PrepareForRendering()
		return json.Marshal(rule)
	}
	r.PrepareForRendering()
	return json.Marshal(r)
}

func cloneKeyValues(keyVals []KeyValue) []KeyValue {
	res := make([]KeyValue, 0, len(keyVals))
	for _, kv := range keyVals {
		res = append(res, KeyValue{
			Key:   kv.Key,
			Value: kv.Value,
		})
	}
	return res
}

func cloneConditionPatterns(patterns []ConditionPattern) []ConditionPattern {
	res := make([]ConditionPattern, 0, len(patterns))
	for _, p := range patterns {
		res = append(res, ConditionPattern{
			Pattern:      p.Pattern,
			InverseMatch: p.InverseMatch,
		})
	}
	return res
}

func validateConditionPatterns(patterns []ConditionPattern) error {
	for _, name := range patterns {
		if err := name.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Task stores the state for a scheduled task
type Task struct {
	Name     string `json:"name"`
	UpdateAt int64  `json:"updated_at"`
	Version  int64  `json:"version"`
}
