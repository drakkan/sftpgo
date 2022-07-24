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

package dataprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
)

var (
	supportedEventActions = []int{ActionTypeHTTP, ActionTypeCommand, ActionTypeEmail, ActionTypeBackup,
		ActionTypeUserQuotaReset, ActionTypeFolderQuotaReset, ActionTypeTransferQuotaReset}
)

func isActionTypeValid(action int) bool {
	return util.Contains(supportedEventActions, action)
}

func getActionTypeAsString(action int) string {
	switch action {
	case ActionTypeHTTP:
		return "HTTP"
	case ActionTypeEmail:
		return "Email"
	case ActionTypeBackup:
		return "Backup"
	case ActionTypeUserQuotaReset:
		return "User quota reset"
	case ActionTypeFolderQuotaReset:
		return "Folder quota reset"
	case ActionTypeTransferQuotaReset:
		return "Transfer quota reset"
	default:
		return "Command"
	}
}

// Supported event triggers
const (
	// Filesystem events such as upload, download, mkdir ...
	EventTriggerFsEvent = iota + 1
	// Provider events such as add, update, delete
	EventTriggerProviderEvent
	EventTriggerSchedule
)

var (
	supportedEventTriggers = []int{EventTriggerFsEvent, EventTriggerProviderEvent, EventTriggerSchedule}
)

func isEventTriggerValid(trigger int) bool {
	return util.Contains(supportedEventTriggers, trigger)
}

func getTriggerTypeAsString(trigger int) string {
	switch trigger {
	case EventTriggerFsEvent:
		return "Filesystem event"
	case EventTriggerProviderEvent:
		return "Provider event"
	default:
		return "Schedule"
	}
}

// TODO: replace the copied strings with shared constants
var (
	// SupportedFsEvents defines the supported filesystem events
	SupportedFsEvents = []string{"upload", "download", "delete", "rename", "mkdir", "rmdir", "ssh_cmd"}
	// SupportedProviderEvents defines the supported provider events
	SupportedProviderEvents = []string{operationAdd, operationUpdate, operationDelete}
	// SupportedRuleConditionProtocols defines the supported protcols for rule conditions
	SupportedRuleConditionProtocols = []string{"SFTP", "SCP", "SSH", "FTP", "DAV", "HTTP", "HTTPShare",
		"OIDC"}
	// SupporteRuleConditionProviderObjects defines the supported provider objects for rule conditions
	SupporteRuleConditionProviderObjects = []string{actionObjectUser, actionObjectGroup, actionObjectAdmin,
		actionObjectAPIKey, actionObjectShare, actionObjectEventRule, actionObjectEventAction}
	// SupportedHTTPActionMethods defines the supported methods for HTTP actions
	SupportedHTTPActionMethods = []string{http.MethodPost, http.MethodGet, http.MethodPut}
)

// enum mappings
var (
	EventActionTypes  []EnumMapping
	EventTriggerTypes []EnumMapping
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

// EventActionHTTPConfig defines the configuration for an HTTP event target
type EventActionHTTPConfig struct {
	Endpoint        string      `json:"endpoint"`
	Username        string      `json:"username,omitempty"`
	Password        *kms.Secret `json:"password,omitempty"`
	Headers         []KeyValue  `json:"headers,omitempty"`
	Timeout         int         `json:"timeout"`
	SkipTLSVerify   bool        `json:"skip_tls_verify,omitempty"`
	Method          string      `json:"method"`
	QueryParameters []KeyValue  `json:"query_parameters,omitempty"`
	Body            string      `json:"post_body,omitempty"`
}

func (c *EventActionHTTPConfig) validate(additionalData string) error {
	if c.Endpoint == "" {
		return util.NewValidationError("HTTP endpoint is required")
	}
	if !util.IsStringPrefixInSlice(c.Endpoint, []string{"http://", "https://"}) {
		return util.NewValidationError("invalid HTTP endpoint schema: http and https are supported")
	}
	if c.Timeout < 1 || c.Timeout > 120 {
		return util.NewValidationError(fmt.Sprintf("invalid HTTP timeout %d", c.Timeout))
	}
	for _, kv := range c.Headers {
		if kv.Key == "" || kv.Value == "" {
			return util.NewValidationError("invalid HTTP headers")
		}
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
		if kv.Key == "" || kv.Value == "" {
			return util.NewValidationError("invalid HTTP query parameters")
		}
	}
	return nil
}

func (c *EventActionHTTPConfig) getEndpoint(replacer *strings.Replacer) (string, error) {
	if len(c.QueryParameters) > 0 {
		u, err := url.Parse(c.Endpoint)
		if err != nil {
			return "", fmt.Errorf("invalid endpoint: %w", err)
		}
		q := u.Query()

		for _, keyVal := range c.QueryParameters {
			q.Add(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
		}

		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	return c.Endpoint, nil
}

func (c *EventActionHTTPConfig) getHTTPClient() *http.Client {
	client := &http.Client{
		Timeout: time.Duration(c.Timeout) * time.Second,
	}
	if c.SkipTLSVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			transport.TLSClientConfig = &tls.Config{
				NextProtos:         []string{"http/1.1", "h2"},
				InsecureSkipVerify: true,
			}
		}
		client.Transport = transport
	}
	return client
}

func (c *EventActionHTTPConfig) execute(params EventParams) error {
	if !c.Password.IsEmpty() {
		if err := c.Password.TryDecrypt(); err != nil {
			return fmt.Errorf("unable to decrypt password: %w", err)
		}
	}
	addObjectData := false
	if params.Object != nil {
		if !addObjectData {
			if strings.Contains(c.Body, "{{ObjectData}}") {
				addObjectData = true
			}
		}
	}

	replacements := params.getStringReplacements(addObjectData)
	replacer := strings.NewReplacer(replacements...)
	endpoint, err := c.getEndpoint(replacer)
	if err != nil {
		return err
	}

	var body io.Reader
	if c.Body != "" && c.Method != http.MethodGet {
		body = bytes.NewBufferString(replaceWithReplacer(c.Body, replacer))
	}
	req, err := http.NewRequest(c.Method, endpoint, body)
	if err != nil {
		return err
	}
	if c.Username != "" {
		req.SetBasicAuth(replaceWithReplacer(c.Username, replacer), c.Password.GetAdditionalData())
	}
	for _, keyVal := range c.Headers {
		req.Header.Set(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
	}
	client := c.getHTTPClient()
	defer client.CloseIdleConnections()

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		eventManagerLog(logger.LevelDebug, "unable to send http notification, endpoint: %s, elapsed: %s, err: %v",
			endpoint, time.Since(startTime), err)
		return err
	}
	defer resp.Body.Close()

	eventManagerLog(logger.LevelDebug, "http notification sent, endopoint: %s, elapsed: %s, status code: %d",
		endpoint, time.Since(startTime), resp.StatusCode)
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// EventActionCommandConfig defines the configuration for a command event target
type EventActionCommandConfig struct {
	Cmd     string     `json:"cmd"`
	Timeout int        `json:"timeout"`
	EnvVars []KeyValue `json:"env_vars"`
}

func (c *EventActionCommandConfig) validate() error {
	if c.Cmd == "" {
		return util.NewValidationError("command is required")
	}
	if !filepath.IsAbs(c.Cmd) {
		return util.NewValidationError("invalid command, it must be an absolute path")
	}
	if c.Timeout < 1 || c.Timeout > 120 {
		return util.NewValidationError(fmt.Sprintf("invalid command action timeout %d", c.Timeout))
	}
	for _, kv := range c.EnvVars {
		if kv.Key == "" || kv.Value == "" {
			return util.NewValidationError("invalid command env vars")
		}
	}
	return nil
}

func (c *EventActionCommandConfig) getEnvVars(params EventParams) []string {
	envVars := make([]string, 0, len(c.EnvVars))
	addObjectData := false
	if params.Object != nil {
		for _, k := range c.EnvVars {
			if strings.Contains(k.Value, "{{ObjectData}}") {
				addObjectData = true
				break
			}
		}
	}
	replacements := params.getStringReplacements(addObjectData)
	replacer := strings.NewReplacer(replacements...)
	for _, keyVal := range c.EnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", keyVal.Key, replaceWithReplacer(keyVal.Value, replacer)))
	}

	return envVars
}

func (c *EventActionCommandConfig) execute(params EventParams) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Cmd)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, c.getEnvVars(params)...)

	startTime := time.Now()
	err := cmd.Run()

	eventManagerLog(logger.LevelDebug, "executed command %q, elapsed: %s, error: %v",
		c.Cmd, time.Since(startTime), err)

	return err
}

// EventActionEmailConfig defines the configuration options for SMTP event actions
type EventActionEmailConfig struct {
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
}

// GetRecipientsAsString returns the list of recipients as comma separated string
func (o EventActionEmailConfig) GetRecipientsAsString() string {
	return strings.Join(o.Recipients, ",")
}

func (o *EventActionEmailConfig) validate() error {
	if len(o.Recipients) == 0 {
		return util.NewValidationError("at least one email recipient is required")
	}
	o.Recipients = util.RemoveDuplicates(o.Recipients, false)
	for _, r := range o.Recipients {
		if r == "" {
			return util.NewValidationError("invalid email recipients")
		}
	}
	if o.Subject == "" {
		return util.NewValidationError("email subject is required")
	}
	if o.Body == "" {
		return util.NewValidationError("email body is required")
	}
	return nil
}

func (o *EventActionEmailConfig) execute(params EventParams) error {
	addObjectData := false
	if params.Object != nil {
		if strings.Contains(o.Body, "{{ObjectData}}") {
			addObjectData = true
		}
	}
	replacements := params.getStringReplacements(addObjectData)
	replacer := strings.NewReplacer(replacements...)
	body := replaceWithReplacer(o.Body, replacer)
	subject := replaceWithReplacer(o.Subject, replacer)
	startTime := time.Now()
	err := smtp.SendEmail(o.Recipients, subject, body, smtp.EmailContentTypeTextPlain)
	eventManagerLog(logger.LevelDebug, "executed email notification action, elapsed: %s, error: %v",
		time.Since(startTime), err)
	return err
}

// BaseEventActionOptions defines the supported configuration options for a base event actions
type BaseEventActionOptions struct {
	HTTPConfig  EventActionHTTPConfig    `json:"http_config"`
	CmdConfig   EventActionCommandConfig `json:"cmd_config"`
	EmailConfig EventActionEmailConfig   `json:"email_config"`
}

func (o *BaseEventActionOptions) getACopy() BaseEventActionOptions {
	o.SetEmptySecretsIfNil()
	emailRecipients := make([]string, len(o.EmailConfig.Recipients))
	copy(emailRecipients, o.EmailConfig.Recipients)

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
		},
		CmdConfig: EventActionCommandConfig{
			Cmd:     o.CmdConfig.Cmd,
			Timeout: o.CmdConfig.Timeout,
			EnvVars: cloneKeyValues(o.CmdConfig.EnvVars),
		},
		EmailConfig: EventActionEmailConfig{
			Recipients: emailRecipients,
			Subject:    o.EmailConfig.Subject,
			Body:       o.EmailConfig.Body,
		},
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
		return o.HTTPConfig.validate(name)
	case ActionTypeCommand:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.EmailConfig = EventActionEmailConfig{}
		return o.CmdConfig.validate()
	case ActionTypeEmail:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		return o.EmailConfig.validate()
	default:
		o.HTTPConfig = EventActionHTTPConfig{}
		o.CmdConfig = EventActionCommandConfig{}
		o.EmailConfig = EventActionEmailConfig{}
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
		return util.NewValidationError("name is mandatory")
	}
	if !isActionTypeValid(a.Type) {
		return util.NewValidationError(fmt.Sprintf("invalid action type: %d", a.Type))
	}
	return a.Options.validate(a.Type, a.Name)
}

func (a *BaseEventAction) doUsersQuotaReset(conditions ConditionOptions) error {
	users, err := provider.dumpUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failedResets []string
	for _, user := range users {
		if !checkConditionPatterns(user.Username, conditions.Names) {
			eventManagerLog(logger.LevelDebug, "skipping scheduled quota reset for user %s, name conditions don't match",
				user.Username)
			continue
		}
		if !QuotaScans.AddUserQuotaScan(user.Username) {
			eventManagerLog(logger.LevelError, "another quota scan is already in progress for user %s", user.Username)
			failedResets = append(failedResets, user.Username)
			continue
		}
		numFiles, size, err := user.ScanQuota()
		QuotaScans.RemoveUserQuotaScan(user.Username)
		if err != nil {
			eventManagerLog(logger.LevelError, "error scanning quota for user %s: %v", user.Username, err)
			failedResets = append(failedResets, user.Username)
			continue
		}
		err = UpdateUserQuota(&user, numFiles, size, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating quota for user %s: %v", user.Username, err)
			failedResets = append(failedResets, user.Username)
			continue
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("quota reset failed for users: %+v", failedResets)
	}
	return nil
}

func (a *BaseEventAction) doFoldersQuotaReset(conditions ConditionOptions) error {
	folders, err := provider.dumpFolders()
	if err != nil {
		return fmt.Errorf("unable to get folders: %w", err)
	}
	var failedResets []string
	for _, folder := range folders {
		if !checkConditionPatterns(folder.Name, conditions.Names) {
			eventManagerLog(logger.LevelDebug, "skipping scheduled quota reset for folder %s, name conditions don't match",
				folder.Name)
			continue
		}
		if !QuotaScans.AddVFolderQuotaScan(folder.Name) {
			eventManagerLog(logger.LevelError, "another quota scan is already in progress for folder %s", folder.Name)
			failedResets = append(failedResets, folder.Name)
			continue
		}
		f := vfs.VirtualFolder{
			BaseVirtualFolder: folder,
			VirtualPath:       "/",
		}
		numFiles, size, err := f.ScanQuota()
		QuotaScans.RemoveVFolderQuotaScan(folder.Name)
		if err != nil {
			eventManagerLog(logger.LevelError, "error scanning quota for folder %s: %v", folder.Name, err)
			failedResets = append(failedResets, folder.Name)
			continue
		}
		err = UpdateVirtualFolderQuota(&folder, numFiles, size, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating quota for folder %s: %v", folder.Name, err)
			failedResets = append(failedResets, folder.Name)
			continue
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("quota reset failed for folders: %+v", failedResets)
	}
	return nil
}

func (a *BaseEventAction) doTransferQuotaReset(conditions ConditionOptions) error {
	users, err := provider.dumpUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failedResets []string
	for _, user := range users {
		if !checkConditionPatterns(user.Username, conditions.Names) {
			eventManagerLog(logger.LevelDebug, "skipping scheduled transfer quota reset for user %s, name conditions don't match",
				user.Username)
			continue
		}
		err = UpdateUserTransferQuota(&user, 0, 0, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating transfer quota for user %s: %v", user.Username, err)
			failedResets = append(failedResets, user.Username)
			continue
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("transfer quota reset failed for users: %+v", failedResets)
	}
	return nil
}

func (a *BaseEventAction) execute(params EventParams, conditions ConditionOptions) error {
	switch a.Type {
	case ActionTypeHTTP:
		return a.Options.HTTPConfig.execute(params)
	case ActionTypeCommand:
		return a.Options.CmdConfig.execute(params)
	case ActionTypeEmail:
		return a.Options.EmailConfig.execute(params)
	case ActionTypeBackup:
		return config.doBackup()
	case ActionTypeUserQuotaReset:
		return a.doUsersQuotaReset(conditions)
	case ActionTypeFolderQuotaReset:
		return a.doFoldersQuotaReset(conditions)
	case ActionTypeTransferQuotaReset:
		return a.doTransferQuotaReset(conditions)
	default:
		return fmt.Errorf("unsupported action type: %d", a.Type)
	}
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
			return util.NewValidationError("sync execution is not supported for failure actions")
		}
	}
	if trigger != EventTriggerFsEvent || !util.Contains(fsEvents, "upload") {
		if a.Options.ExecuteSync {
			return util.NewValidationError("sync execution is only supported for upload event")
		}
	}
	return nil
}

// ConditionPattern defines a pattern for condition filters
type ConditionPattern struct {
	Pattern      string `json:"pattern,omitempty"`
	InverseMatch bool   `json:"inverse_match,omitempty"`
}

func (p *ConditionPattern) match(name string) bool {
	matched, err := path.Match(p.Pattern, name)
	if err != nil {
		eventManagerLog(logger.LevelError, "pattern matching error %q, err: %v", p.Pattern, err)
		return false
	}
	if p.InverseMatch {
		return !matched
	}
	return matched
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
		FsPaths:             cloneConditionPatterns(f.FsPaths),
		Protocols:           protocols,
		ProviderObjects:     providerObjects,
		MinFileSize:         f.MinFileSize,
		MaxFileSize:         f.MaxFileSize,
		ConcurrentExecution: f.ConcurrentExecution,
	}
}

func (f *ConditionOptions) validate() error {
	for _, name := range f.Names {
		if err := name.validate(); err != nil {
			return err
		}
	}
	for _, fsPath := range f.FsPaths {
		if err := fsPath.validate(); err != nil {
			return err
		}
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
			return util.NewValidationError(fmt.Sprintf("invalid max file size %d, it is lesser or equal than min file size %d",
				f.MaxFileSize, f.MinFileSize))
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

func (s *Schedule) getCronSpec() string {
	return fmt.Sprintf("0 %s %s %s %s", s.Hours, s.DayOfMonth, s.Month, s.DayOfWeek)
}

func (s *Schedule) validate() error {
	_, err := cron.ParseStandard(s.getCronSpec())
	if err != nil {
		return util.NewValidationError(fmt.Sprintf("invalid schedule, hour: %q, day of month: %q, month: %q, day of week: %q",
			s.Hours, s.DayOfMonth, s.Month, s.DayOfWeek))
	}
	return nil
}

// EventConditions defines the conditions for an event rule
type EventConditions struct {
	// Only one between FsEvents, ProviderEvents and Schedule is allowed
	FsEvents       []string         `json:"fs_events,omitempty"`
	ProviderEvents []string         `json:"provider_events,omitempty"`
	Schedules      []Schedule       `json:"schedules,omitempty"`
	Options        ConditionOptions `json:"options"`
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
		Options:        c.Options.getACopy(),
	}
}

// ProviderEventMatch returns true if the specified provider event match
func (c *EventConditions) ProviderEventMatch(params EventParams) bool {
	if !util.Contains(c.ProviderEvents, params.Event) {
		return false
	}
	if !checkConditionPatterns(params.Name, c.Options.Names) {
		return false
	}
	if len(c.Options.ProviderObjects) > 0 && !util.Contains(c.Options.ProviderObjects, params.ObjectType) {
		return false
	}
	return true
}

// FsEventMatch returns true if the specified filesystem event match
func (c *EventConditions) FsEventMatch(params EventParams) bool {
	if !util.Contains(c.FsEvents, params.Event) {
		return false
	}
	if !checkConditionPatterns(params.Name, c.Options.Names) {
		return false
	}
	if !checkConditionPatterns(params.VirtualPath, c.Options.FsPaths) {
		if !checkConditionPatterns(params.ObjectName, c.Options.FsPaths) {
			return false
		}
	}
	if len(c.Options.Protocols) > 0 && !util.Contains(c.Options.Protocols, params.Protocol) {
		return false
	}
	if params.Event == "upload" || params.Event == "download" {
		if c.Options.MinFileSize > 0 {
			if params.FileSize < c.Options.MinFileSize {
				return false
			}
		}
		if c.Options.MaxFileSize > 0 {
			if params.FileSize > c.Options.MaxFileSize {
				return false
			}
		}
	}
	return true
}

func (c *EventConditions) validate(trigger int) error {
	switch trigger {
	case EventTriggerFsEvent:
		c.ProviderEvents = nil
		c.Schedules = nil
		c.Options.ProviderObjects = nil
		if len(c.FsEvents) == 0 {
			return util.NewValidationError("at least one filesystem event is required")
		}
		for _, ev := range c.FsEvents {
			if !util.Contains(SupportedFsEvents, ev) {
				return util.NewValidationError(fmt.Sprintf("unsupported fs event: %q", ev))
			}
		}
	case EventTriggerProviderEvent:
		c.FsEvents = nil
		c.Schedules = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		if len(c.ProviderEvents) == 0 {
			return util.NewValidationError("at least one provider event is required")
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
		if len(c.Schedules) == 0 {
			return util.NewValidationError("at least one schedule is required")
		}
		for _, schedule := range c.Schedules {
			if err := schedule.validate(); err != nil {
				return err
			}
		}
	default:
		c.FsEvents = nil
		c.ProviderEvents = nil
		c.Options.FsPaths = nil
		c.Options.Protocols = nil
		c.Options.MinFileSize = 0
		c.Options.MaxFileSize = 0
		c.Schedules = nil
	}

	return c.Options.validate()
}

// EventRule defines the trigger, conditions and actions for an event
type EventRule struct {
	// Data provider unique identifier
	ID int64 `json:"id"`
	// Rule name
	Name string `json:"name"`
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
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		Trigger:     r.Trigger,
		Conditions:  r.Conditions.getACopy(),
		Actions:     actions,
		DeletedAt:   r.DeletedAt,
	}
}

func (r *EventRule) guardFromConcurrentExecution() bool {
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

func (r *EventRule) validate() error {
	if r.Name == "" {
		return util.NewValidationError("name is mandatory")
	}
	if !isEventTriggerValid(r.Trigger) {
		return util.NewValidationError(fmt.Sprintf("invalid event rule trigger: %d", r.Trigger))
	}
	if err := r.Conditions.validate(r.Trigger); err != nil {
		return err
	}
	if len(r.Actions) == 0 {
		return util.NewValidationError("at least one action is required")
	}
	actionNames := make(map[string]bool)
	actionOrders := make(map[int]bool)
	failureActions := 0
	for idx := range r.Actions {
		if r.Actions[idx].Name == "" {
			return util.NewValidationError(fmt.Sprintf("invalid action at position %d, name not specified", idx))
		}
		if actionNames[r.Actions[idx].Name] {
			return util.NewValidationError(fmt.Sprintf("duplicated action %q", r.Actions[idx].Name))
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
		actionNames[r.Actions[idx].Name] = true
		actionOrders[r.Actions[idx].Order] = true
	}
	if len(r.Actions) == failureActions {
		return util.NewValidationError("at least a non-failure action is required")
	}
	return nil
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

// Task stores the state for a scheduled task
type Task struct {
	Name     string `json:"name"`
	UpdateAt int64  `json:"updated_at"`
	Version  int64  `json:"version"`
}
