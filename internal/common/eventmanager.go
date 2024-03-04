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

package common

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/klauspost/compress/zip"
	"github.com/robfig/cron/v3"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/wneessen/go-mail"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	ipBlockedEventName       = "IP Blocked"
	maxAttachmentsSize       = int64(10 * 1024 * 1024)
	objDataPlaceholder       = "{{ObjectData}}"
	objDataPlaceholderString = "{{ObjectDataString}}"
)

// Supported IDP login events
const (
	IDPLoginUser  = "IDP login user"
	IDPLoginAdmin = "IDP login admin"
)

var (
	// eventManager handle the supported event rules actions
	eventManager          eventRulesContainer
	multipartQuoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")
)

func init() {
	eventManager = eventRulesContainer{
		schedulesMapping: make(map[string][]cron.EntryID),
		// arbitrary maximum number of concurrent asynchronous tasks,
		// each task could execute multiple actions
		concurrencyGuard: make(chan struct{}, 200),
	}
	dataprovider.SetEventRulesCallbacks(eventManager.loadRules, eventManager.RemoveRule,
		func(operation, executor, ip, objectType, objectName, role string, object plugin.Renderer) {
			p := EventParams{
				Name:       executor,
				ObjectName: objectName,
				Event:      operation,
				Status:     1,
				ObjectType: objectType,
				IP:         ip,
				Role:       role,
				Timestamp:  time.Now().UnixNano(),
				Object:     object,
			}
			if u, ok := object.(*dataprovider.User); ok {
				p.Email = u.Email
			} else if a, ok := object.(*dataprovider.Admin); ok {
				p.Email = a.Email
			}
			eventManager.handleProviderEvent(p)
		})
}

// HandleCertificateEvent checks and executes action rules for certificate events
func HandleCertificateEvent(params EventParams) {
	eventManager.handleCertificateEvent(params)
}

// HandleIDPLoginEvent executes actions defined for a successful login from an Identity Provider
func HandleIDPLoginEvent(params EventParams, customFields *map[string]any) (*dataprovider.User, *dataprovider.Admin, error) {
	return eventManager.handleIDPLoginEvent(params, customFields)
}

// eventRulesContainer stores event rules by trigger
type eventRulesContainer struct {
	sync.RWMutex
	lastLoad          atomic.Int64
	FsEvents          []dataprovider.EventRule
	ProviderEvents    []dataprovider.EventRule
	Schedules         []dataprovider.EventRule
	IPBlockedEvents   []dataprovider.EventRule
	CertificateEvents []dataprovider.EventRule
	IPDLoginEvents    []dataprovider.EventRule
	schedulesMapping  map[string][]cron.EntryID
	concurrencyGuard  chan struct{}
}

func (r *eventRulesContainer) addAsyncTask() {
	activeHooks.Add(1)
	r.concurrencyGuard <- struct{}{}
}

func (r *eventRulesContainer) removeAsyncTask() {
	activeHooks.Add(-1)
	<-r.concurrencyGuard
}

func (r *eventRulesContainer) getLastLoadTime() int64 {
	return r.lastLoad.Load()
}

func (r *eventRulesContainer) setLastLoadTime(modTime int64) {
	r.lastLoad.Store(modTime)
}

// RemoveRule deletes the rule with the specified name
func (r *eventRulesContainer) RemoveRule(name string) {
	r.Lock()
	defer r.Unlock()

	r.removeRuleInternal(name)
	eventManagerLog(logger.LevelDebug, "event rules updated after delete, fs events: %d, provider events: %d, schedules: %d",
		len(r.FsEvents), len(r.ProviderEvents), len(r.Schedules))
}

func (r *eventRulesContainer) removeRuleInternal(name string) {
	for idx := range r.FsEvents {
		if r.FsEvents[idx].Name == name {
			lastIdx := len(r.FsEvents) - 1
			r.FsEvents[idx] = r.FsEvents[lastIdx]
			r.FsEvents = r.FsEvents[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from fs events", name)
			return
		}
	}
	for idx := range r.ProviderEvents {
		if r.ProviderEvents[idx].Name == name {
			lastIdx := len(r.ProviderEvents) - 1
			r.ProviderEvents[idx] = r.ProviderEvents[lastIdx]
			r.ProviderEvents = r.ProviderEvents[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from provider events", name)
			return
		}
	}
	for idx := range r.IPBlockedEvents {
		if r.IPBlockedEvents[idx].Name == name {
			lastIdx := len(r.IPBlockedEvents) - 1
			r.IPBlockedEvents[idx] = r.IPBlockedEvents[lastIdx]
			r.IPBlockedEvents = r.IPBlockedEvents[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from IP blocked events", name)
			return
		}
	}
	for idx := range r.CertificateEvents {
		if r.CertificateEvents[idx].Name == name {
			lastIdx := len(r.CertificateEvents) - 1
			r.CertificateEvents[idx] = r.CertificateEvents[lastIdx]
			r.CertificateEvents = r.CertificateEvents[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from certificate events", name)
			return
		}
	}
	for idx := range r.IPDLoginEvents {
		if r.IPDLoginEvents[idx].Name == name {
			lastIdx := len(r.IPDLoginEvents) - 1
			r.IPDLoginEvents[idx] = r.IPDLoginEvents[lastIdx]
			r.IPDLoginEvents = r.IPDLoginEvents[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from IDP login events", name)
			return
		}
	}
	for idx := range r.Schedules {
		if r.Schedules[idx].Name == name {
			if schedules, ok := r.schedulesMapping[name]; ok {
				for _, entryID := range schedules {
					eventManagerLog(logger.LevelDebug, "removing scheduled entry id %d for rule %q", entryID, name)
					eventScheduler.Remove(entryID)
				}
				delete(r.schedulesMapping, name)
			}

			lastIdx := len(r.Schedules) - 1
			r.Schedules[idx] = r.Schedules[lastIdx]
			r.Schedules = r.Schedules[:lastIdx]
			eventManagerLog(logger.LevelDebug, "removed rule %q from scheduled events", name)
			return
		}
	}
}

func (r *eventRulesContainer) addUpdateRuleInternal(rule dataprovider.EventRule) {
	r.removeRuleInternal(rule.Name)
	if rule.DeletedAt > 0 {
		deletedAt := util.GetTimeFromMsecSinceEpoch(rule.DeletedAt)
		if deletedAt.Add(30 * time.Minute).Before(time.Now()) {
			eventManagerLog(logger.LevelDebug, "removing rule %q deleted at %s", rule.Name, deletedAt)
			go dataprovider.RemoveEventRule(rule) //nolint:errcheck
		}
		return
	}
	if rule.Status != 1 || rule.Trigger == dataprovider.EventTriggerOnDemand {
		return
	}
	switch rule.Trigger {
	case dataprovider.EventTriggerFsEvent:
		r.FsEvents = append(r.FsEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to fs events", rule.Name)
	case dataprovider.EventTriggerProviderEvent:
		r.ProviderEvents = append(r.ProviderEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to provider events", rule.Name)
	case dataprovider.EventTriggerIPBlocked:
		r.IPBlockedEvents = append(r.IPBlockedEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to IP blocked events", rule.Name)
	case dataprovider.EventTriggerCertificate:
		r.CertificateEvents = append(r.CertificateEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to certificate events", rule.Name)
	case dataprovider.EventTriggerIDPLogin:
		r.IPDLoginEvents = append(r.IPDLoginEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to IDP login events", rule.Name)
	case dataprovider.EventTriggerSchedule:
		for _, schedule := range rule.Conditions.Schedules {
			cronSpec := schedule.GetCronSpec()
			job := &eventCronJob{
				ruleName: dataprovider.ConvertName(rule.Name),
			}
			entryID, err := eventScheduler.AddJob(cronSpec, job)
			if err != nil {
				eventManagerLog(logger.LevelError, "unable to add scheduled rule %q, cron string %q: %v", rule.Name, cronSpec, err)
				return
			}
			r.schedulesMapping[rule.Name] = append(r.schedulesMapping[rule.Name], entryID)
			eventManagerLog(logger.LevelDebug, "schedule for rule %q added, id: %d, cron string %q, active scheduling rules: %d",
				rule.Name, entryID, cronSpec, len(r.schedulesMapping))
		}
		r.Schedules = append(r.Schedules, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to scheduled events", rule.Name)
	default:
		eventManagerLog(logger.LevelError, "unsupported trigger: %d", rule.Trigger)
	}
}

func (r *eventRulesContainer) loadRules() {
	eventManagerLog(logger.LevelDebug, "loading updated rules")
	modTime := util.GetTimeAsMsSinceEpoch(time.Now())
	rules, err := dataprovider.GetRecentlyUpdatedRules(r.getLastLoadTime())
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to load event rules: %v", err)
		return
	}
	eventManagerLog(logger.LevelDebug, "recently updated event rules loaded: %d", len(rules))

	if len(rules) > 0 {
		r.Lock()
		defer r.Unlock()

		for _, rule := range rules {
			r.addUpdateRuleInternal(rule)
		}
	}
	eventManagerLog(logger.LevelDebug, "event rules updated, fs events: %d, provider events: %d, schedules: %d, ip blocked events: %d, certificate events: %d, IDP login events: %d",
		len(r.FsEvents), len(r.ProviderEvents), len(r.Schedules), len(r.IPBlockedEvents), len(r.CertificateEvents), len(r.IPDLoginEvents))

	r.setLastLoadTime(modTime)
}

func (*eventRulesContainer) checkIPDLoginEventMatch(conditions *dataprovider.EventConditions, params *EventParams) bool {
	switch conditions.IDPLoginEvent {
	case dataprovider.IDPLoginUser:
		if params.Event != IDPLoginUser {
			return false
		}
	case dataprovider.IDPLoginAdmin:
		if params.Event != IDPLoginAdmin {
			return false
		}
	}
	return checkEventConditionPatterns(params.Name, conditions.Options.Names)
}

func (*eventRulesContainer) checkProviderEventMatch(conditions *dataprovider.EventConditions, params *EventParams) bool {
	if !util.Contains(conditions.ProviderEvents, params.Event) {
		return false
	}
	if !checkEventConditionPatterns(params.Name, conditions.Options.Names) {
		return false
	}
	if !checkEventConditionPatterns(params.Role, conditions.Options.RoleNames) {
		return false
	}
	if len(conditions.Options.ProviderObjects) > 0 && !util.Contains(conditions.Options.ProviderObjects, params.ObjectType) {
		return false
	}
	return true
}

func (*eventRulesContainer) checkFsEventMatch(conditions *dataprovider.EventConditions, params *EventParams) bool {
	if !util.Contains(conditions.FsEvents, params.Event) {
		return false
	}
	if !checkEventConditionPatterns(params.Name, conditions.Options.Names) {
		return false
	}
	if !checkEventConditionPatterns(params.Role, conditions.Options.RoleNames) {
		return false
	}
	if !checkEventGroupConditionPatterns(params.Groups, conditions.Options.GroupNames) {
		return false
	}
	if !checkEventConditionPatterns(params.VirtualPath, conditions.Options.FsPaths) {
		return false
	}
	if len(conditions.Options.Protocols) > 0 && !util.Contains(conditions.Options.Protocols, params.Protocol) {
		return false
	}
	if params.Event == operationUpload || params.Event == operationDownload {
		if conditions.Options.MinFileSize > 0 {
			if params.FileSize < conditions.Options.MinFileSize {
				return false
			}
		}
		if conditions.Options.MaxFileSize > 0 {
			if params.FileSize > conditions.Options.MaxFileSize {
				return false
			}
		}
	}
	return true
}

// hasFsRules returns true if there are any rules for filesystem event triggers
func (r *eventRulesContainer) hasFsRules() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.FsEvents) > 0
}

// handleFsEvent executes the rules actions defined for the specified event.
// The boolean parameter indicates whether a sync action was executed
func (r *eventRulesContainer) handleFsEvent(params EventParams) (bool, error) {
	if params.Protocol == protocolEventAction {
		return false, nil
	}
	r.RLock()

	var rulesWithSyncActions, rulesAsync []dataprovider.EventRule
	for _, rule := range r.FsEvents {
		if r.checkFsEventMatch(&rule.Conditions, &params) {
			if err := rule.CheckActionsConsistency(""); err != nil {
				eventManagerLog(logger.LevelWarn, "rule %q skipped: %v, event %q",
					rule.Name, err, params.Event)
				continue
			}
			hasSyncActions := false
			for _, action := range rule.Actions {
				if action.Options.ExecuteSync {
					hasSyncActions = true
					break
				}
			}
			if hasSyncActions {
				rulesWithSyncActions = append(rulesWithSyncActions, rule)
			} else {
				rulesAsync = append(rulesAsync, rule)
			}
		}
	}

	r.RUnlock()

	params.sender = params.Name
	params.addUID()
	if len(rulesAsync) > 0 {
		go executeAsyncRulesActions(rulesAsync, params)
	}

	if len(rulesWithSyncActions) > 0 {
		return true, executeSyncRulesActions(rulesWithSyncActions, params)
	}
	return false, nil
}

func (r *eventRulesContainer) handleIDPLoginEvent(params EventParams, customFields *map[string]any) (*dataprovider.User,
	*dataprovider.Admin, error,
) {
	r.RLock()

	var rulesWithSyncActions, rulesAsync []dataprovider.EventRule
	for _, rule := range r.IPDLoginEvents {
		if r.checkIPDLoginEventMatch(&rule.Conditions, &params) {
			if err := rule.CheckActionsConsistency(""); err != nil {
				eventManagerLog(logger.LevelWarn, "rule %q skipped: %v, event %q",
					rule.Name, err, params.Event)
				continue
			}
			hasSyncActions := false
			for _, action := range rule.Actions {
				if action.Options.ExecuteSync {
					hasSyncActions = true
					break
				}
			}
			if hasSyncActions {
				rulesWithSyncActions = append(rulesWithSyncActions, rule)
			} else {
				rulesAsync = append(rulesAsync, rule)
			}
		}
	}

	r.RUnlock()

	if len(rulesAsync) == 0 && len(rulesWithSyncActions) == 0 {
		return nil, nil, nil
	}

	params.addIDPCustomFields(customFields)
	if len(rulesWithSyncActions) > 1 {
		var ruleNames []string
		for _, r := range rulesWithSyncActions {
			ruleNames = append(ruleNames, r.Name)
		}
		return nil, nil, fmt.Errorf("more than one account check action rules matches: %q", strings.Join(ruleNames, ","))
	}

	params.addUID()
	if len(rulesAsync) > 0 {
		go executeAsyncRulesActions(rulesAsync, params)
	}

	if len(rulesWithSyncActions) > 0 {
		return executeIDPAccountCheckRule(rulesWithSyncActions[0], params)
	}
	return nil, nil, nil
}

// username is populated for user objects
func (r *eventRulesContainer) handleProviderEvent(params EventParams) {
	r.RLock()
	defer r.RUnlock()

	var rules []dataprovider.EventRule
	for _, rule := range r.ProviderEvents {
		if r.checkProviderEventMatch(&rule.Conditions, &params) {
			if err := rule.CheckActionsConsistency(params.ObjectType); err == nil {
				rules = append(rules, rule)
			} else {
				eventManagerLog(logger.LevelWarn, "rule %q skipped: %v, event %q object type %q",
					rule.Name, err, params.Event, params.ObjectType)
			}
		}
	}

	if len(rules) > 0 {
		params.sender = params.ObjectName
		go executeAsyncRulesActions(rules, params)
	}
}

func (r *eventRulesContainer) handleIPBlockedEvent(params EventParams) {
	r.RLock()
	defer r.RUnlock()

	if len(r.IPBlockedEvents) == 0 {
		return
	}
	var rules []dataprovider.EventRule
	for _, rule := range r.IPBlockedEvents {
		if err := rule.CheckActionsConsistency(""); err == nil {
			rules = append(rules, rule)
		} else {
			eventManagerLog(logger.LevelWarn, "rule %q skipped: %v, event %q",
				rule.Name, err, params.Event)
		}
	}

	if len(rules) > 0 {
		go executeAsyncRulesActions(rules, params)
	}
}

func (r *eventRulesContainer) handleCertificateEvent(params EventParams) {
	r.RLock()
	defer r.RUnlock()

	if len(r.CertificateEvents) == 0 {
		return
	}
	var rules []dataprovider.EventRule
	for _, rule := range r.CertificateEvents {
		if err := rule.CheckActionsConsistency(""); err == nil {
			rules = append(rules, rule)
		} else {
			eventManagerLog(logger.LevelWarn, "rule %q skipped: %v, event %q",
				rule.Name, err, params.Event)
		}
	}

	if len(rules) > 0 {
		go executeAsyncRulesActions(rules, params)
	}
}

type executedRetentionCheck struct {
	Username   string
	ActionName string
	Results    []folderRetentionCheckResult
}

// EventParams defines the supported event parameters
type EventParams struct {
	Name                  string
	Groups                []sdk.GroupMapping
	Event                 string
	Status                int
	VirtualPath           string
	FsPath                string
	VirtualTargetPath     string
	FsTargetPath          string
	ObjectName            string
	Extension             string
	ObjectType            string
	FileSize              int64
	Elapsed               int64
	Protocol              string
	IP                    string
	Role                  string
	Email                 string
	Timestamp             int64
	UID                   string
	IDPCustomFields       *map[string]string
	Object                plugin.Renderer
	Metadata              map[string]string
	sender                string
	updateStatusFromError bool
	errors                []string
	retentionChecks       []executedRetentionCheck
}

func (p *EventParams) getACopy() *EventParams {
	params := *p
	params.errors = make([]string, len(p.errors))
	copy(params.errors, p.errors)
	retentionChecks := make([]executedRetentionCheck, 0, len(p.retentionChecks))
	for _, c := range p.retentionChecks {
		executedCheck := executedRetentionCheck{
			Username:   c.Username,
			ActionName: c.ActionName,
		}
		executedCheck.Results = make([]folderRetentionCheckResult, len(c.Results))
		copy(executedCheck.Results, c.Results)
		retentionChecks = append(retentionChecks, executedCheck)
	}
	params.retentionChecks = retentionChecks
	if p.IDPCustomFields != nil {
		fields := make(map[string]string)
		for k, v := range *p.IDPCustomFields {
			fields[k] = v
		}
		params.IDPCustomFields = &fields
	}
	if len(params.Metadata) > 0 {
		metadata := make(map[string]string)
		for k, v := range p.Metadata {
			metadata[k] = v
		}
		params.Metadata = metadata
	}

	return &params
}

func (p *EventParams) addIDPCustomFields(customFields *map[string]any) {
	if customFields == nil || len(*customFields) == 0 {
		return
	}

	fields := make(map[string]string)
	for k, v := range *customFields {
		switch val := v.(type) {
		case string:
			fields[k] = val
		}
	}
	p.IDPCustomFields = &fields
}

// AddError adds a new error to the event params and update the status if needed
func (p *EventParams) AddError(err error) {
	if err == nil {
		return
	}
	if p.updateStatusFromError && p.Status == 1 {
		p.Status = 2
	}
	p.errors = append(p.errors, err.Error())
}

func (p *EventParams) addUID() {
	if p.UID == "" {
		p.UID = util.GenerateUniqueID()
	}
}

func (p *EventParams) setBackupParams(backupPath string) {
	if p.sender != "" {
		return
	}
	p.sender = dataprovider.ActionExecutorSystem
	p.FsPath = backupPath
	p.ObjectName = filepath.Base(backupPath)
	p.VirtualPath = "/" + p.ObjectName
	p.Timestamp = time.Now().UnixNano()
	info, err := os.Stat(backupPath)
	if err == nil {
		p.FileSize = info.Size()
	}
}

func (p *EventParams) getStatusString() string {
	switch p.Status {
	case 1:
		return "OK"
	default:
		return "KO"
	}
}

// getUsers returns users with group settings not applied
func (p *EventParams) getUsers() ([]dataprovider.User, error) {
	if p.sender == "" {
		dump, err := dataprovider.DumpData([]string{dataprovider.DumpScopeUsers})
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to get users: %+v", err)
			return nil, errors.New("unable to get users")
		}
		return dump.Users, nil
	}
	user, err := p.getUserFromSender()
	if err != nil {
		return nil, err
	}
	return []dataprovider.User{user}, nil
}

func (p *EventParams) getUserFromSender() (dataprovider.User, error) {
	if p.sender == dataprovider.ActionExecutorSystem {
		return dataprovider.User{
			BaseUser: sdk.BaseUser{
				Status:   1,
				Username: p.sender,
				HomeDir:  dataprovider.GetBackupsPath(),
				Permissions: map[string][]string{
					"/": {dataprovider.PermAny},
				},
			},
		}, nil
	}
	user, err := dataprovider.UserExists(p.sender, "")
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to get user %q: %+v", p.sender, err)
		return user, fmt.Errorf("error getting user %q", p.sender)
	}
	return user, nil
}

func (p *EventParams) getFolders() ([]vfs.BaseVirtualFolder, error) {
	if p.sender == "" {
		dump, err := dataprovider.DumpData([]string{dataprovider.DumpScopeFolders})
		return dump.Folders, err
	}
	folder, err := dataprovider.GetFolderByName(p.sender)
	if err != nil {
		return nil, fmt.Errorf("error getting folder %q: %w", p.sender, err)
	}
	return []vfs.BaseVirtualFolder{folder}, nil
}

func (p *EventParams) getCompressedDataRetentionReport() ([]byte, error) {
	if len(p.retentionChecks) == 0 {
		return nil, errors.New("no data retention report available")
	}
	var b bytes.Buffer
	if _, err := p.writeCompressedDataRetentionReports(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (p *EventParams) writeCompressedDataRetentionReports(w io.Writer) (int64, error) {
	var n int64
	wr := zip.NewWriter(w)

	for _, check := range p.retentionChecks {
		data, err := getCSVRetentionReport(check.Results)
		if err != nil {
			return n, fmt.Errorf("unable to get CSV report: %w", err)
		}
		dataSize := int64(len(data))
		n += dataSize
		// we suppose a 3:1 compression ratio
		if n > (maxAttachmentsSize * 3) {
			eventManagerLog(logger.LevelError, "unable to get retention report, size too large: %s",
				util.ByteCountIEC(n))
			return n, fmt.Errorf("unable to get retention report, size too large: %s", util.ByteCountIEC(n))
		}

		fh := &zip.FileHeader{
			Name:     fmt.Sprintf("%s-%s.csv", check.ActionName, check.Username),
			Method:   zip.Deflate,
			Modified: time.Now().UTC(),
		}
		f, err := wr.CreateHeader(fh)
		if err != nil {
			return n, fmt.Errorf("unable to create zip header for file %q: %w", fh.Name, err)
		}
		_, err = io.CopyN(f, bytes.NewBuffer(data), dataSize)
		if err != nil {
			return n, fmt.Errorf("unable to write content to zip file %q: %w", fh.Name, err)
		}
	}
	if err := wr.Close(); err != nil {
		return n, fmt.Errorf("unable to close zip writer: %w", err)
	}
	return n, nil
}

func (p *EventParams) getRetentionReportsAsMailAttachment() (*mail.File, error) {
	if len(p.retentionChecks) == 0 {
		return nil, errors.New("no data retention report available")
	}
	return &mail.File{
		Name:   "retention-reports.zip",
		Header: make(map[string][]string),
		Writer: p.writeCompressedDataRetentionReports,
	}, nil
}

func (*EventParams) getStringReplacement(val string, jsonEscaped bool) string {
	if jsonEscaped {
		return util.JSONEscape(val)
	}
	return val
}

func (p *EventParams) getStringReplacements(addObjectData, jsonEscaped bool) []string {
	replacements := []string{
		"{{Name}}", p.getStringReplacement(p.Name, jsonEscaped),
		"{{Event}}", p.Event,
		"{{Status}}", fmt.Sprintf("%d", p.Status),
		"{{VirtualPath}}", p.getStringReplacement(p.VirtualPath, jsonEscaped),
		"{{FsPath}}", p.getStringReplacement(p.FsPath, jsonEscaped),
		"{{VirtualTargetPath}}", p.getStringReplacement(p.VirtualTargetPath, jsonEscaped),
		"{{FsTargetPath}}", p.getStringReplacement(p.FsTargetPath, jsonEscaped),
		"{{ObjectName}}", p.getStringReplacement(p.ObjectName, jsonEscaped),
		"{{ObjectType}}", p.ObjectType,
		"{{FileSize}}", strconv.FormatInt(p.FileSize, 10),
		"{{Elapsed}}", strconv.FormatInt(p.Elapsed, 10),
		"{{Protocol}}", p.Protocol,
		"{{IP}}", p.IP,
		"{{Role}}", p.getStringReplacement(p.Role, jsonEscaped),
		"{{Email}}", p.getStringReplacement(p.Email, jsonEscaped),
		"{{Timestamp}}", strconv.FormatInt(p.Timestamp, 10),
		"{{StatusString}}", p.getStatusString(),
		"{{UID}}", p.getStringReplacement(p.UID, jsonEscaped),
		"{{Ext}}", p.getStringReplacement(p.Extension, jsonEscaped),
	}
	if p.VirtualPath != "" {
		replacements = append(replacements, "{{VirtualDirPath}}", p.getStringReplacement(path.Dir(p.VirtualPath), jsonEscaped))
	}
	if p.VirtualTargetPath != "" {
		replacements = append(replacements, "{{VirtualTargetDirPath}}", p.getStringReplacement(path.Dir(p.VirtualTargetPath), jsonEscaped))
		replacements = append(replacements, "{{TargetName}}", p.getStringReplacement(path.Base(p.VirtualTargetPath), jsonEscaped))
	}
	if len(p.errors) > 0 {
		replacements = append(replacements, "{{ErrorString}}", p.getStringReplacement(strings.Join(p.errors, ", "), jsonEscaped))
	} else {
		replacements = append(replacements, "{{ErrorString}}", "")
	}
	replacements = append(replacements, objDataPlaceholder, "{}")
	replacements = append(replacements, objDataPlaceholderString, "")
	if addObjectData {
		data, err := p.Object.RenderAsJSON(p.Event != operationDelete)
		if err == nil {
			dataString := string(data)
			replacements[len(replacements)-3] = p.getStringReplacement(dataString, false)
			replacements[len(replacements)-1] = p.getStringReplacement(dataString, true)
		}
	}
	if p.IDPCustomFields != nil {
		for k, v := range *p.IDPCustomFields {
			replacements = append(replacements, fmt.Sprintf("{{IDPField%s}}", k), p.getStringReplacement(v, jsonEscaped))
		}
	}
	replacements = append(replacements, "{{Metadata}}", "{}")
	replacements = append(replacements, "{{MetadataString}}", "")
	if len(p.Metadata) > 0 {
		data, err := json.Marshal(p.Metadata)
		if err == nil {
			dataString := string(data)
			replacements[len(replacements)-3] = p.getStringReplacement(dataString, false)
			replacements[len(replacements)-1] = p.getStringReplacement(dataString, true)
		}
	}
	return replacements
}

func getCSVRetentionReport(results []folderRetentionCheckResult) ([]byte, error) {
	var b bytes.Buffer
	csvWriter := csv.NewWriter(&b)
	err := csvWriter.Write([]string{"path", "retention (hours)", "deleted files", "deleted size (bytes)",
		"elapsed (ms)", "info", "error"})
	if err != nil {
		return nil, err
	}

	for _, result := range results {
		err = csvWriter.Write([]string{result.Path, strconv.Itoa(result.Retention), strconv.Itoa(result.DeletedFiles),
			strconv.FormatInt(result.DeletedSize, 10), strconv.FormatInt(result.Elapsed.Milliseconds(), 10),
			result.Info, result.Error})
		if err != nil {
			return nil, err
		}
	}

	csvWriter.Flush()
	err = csvWriter.Error()
	return b.Bytes(), err
}

func closeWriterAndUpdateQuota(w io.WriteCloser, conn *BaseConnection, virtualSourcePath, virtualTargetPath string,
	numFiles int, truncatedSize int64, errTransfer error, operation string, startTime time.Time,
) error {
	var fsDstPath string
	var errDstFs error
	errWrite := w.Close()
	targetPath := virtualSourcePath
	if virtualTargetPath != "" {
		targetPath = virtualTargetPath
		var fsDst vfs.Fs
		fsDst, fsDstPath, errDstFs = conn.GetFsAndResolvedPath(virtualTargetPath)
		if errTransfer != nil && errDstFs == nil {
			// try to remove a partial file on error. If this fails, we can't do anything
			errRemove := fsDst.Remove(fsDstPath, false)
			conn.Log(logger.LevelDebug, "removing partial file %q after write error, result: %v", virtualTargetPath, errRemove)
		}
	}
	info, err := conn.doStatInternal(targetPath, 0, false, false)
	if err == nil {
		updateUserQuotaAfterFileWrite(conn, targetPath, numFiles, info.Size()-truncatedSize)
		var fsSrcPath string
		var errSrcFs error
		if virtualSourcePath != "" {
			_, fsSrcPath, errSrcFs = conn.GetFsAndResolvedPath(virtualSourcePath)
		}
		if errSrcFs == nil && errDstFs == nil {
			elapsed := time.Since(startTime).Nanoseconds() / 1000000
			if errTransfer == nil {
				errTransfer = errWrite
			}
			if operation == operationCopy {
				logger.CommandLog(copyLogSender, fsSrcPath, fsDstPath, conn.User.Username, "", conn.ID, conn.protocol, -1, -1,
					"", "", "", info.Size(), conn.localAddr, conn.remoteAddr, elapsed)
			}
			ExecuteActionNotification(conn, operation, fsSrcPath, virtualSourcePath, fsDstPath, virtualTargetPath, "", info.Size(), errTransfer, elapsed, nil) //nolint:errcheck
		}
	} else {
		eventManagerLog(logger.LevelWarn, "unable to update quota after writing %q: %v", targetPath, err)
	}
	if errTransfer != nil {
		return errTransfer
	}
	return errWrite
}

func updateUserQuotaAfterFileWrite(conn *BaseConnection, virtualPath string, numFiles int, fileSize int64) {
	vfolder, err := conn.User.GetVirtualFolderForPath(path.Dir(virtualPath))
	if err != nil {
		dataprovider.UpdateUserQuota(&conn.User, numFiles, fileSize, false) //nolint:errcheck
		return
	}
	dataprovider.UpdateVirtualFolderQuota(&vfolder.BaseVirtualFolder, numFiles, fileSize, false) //nolint:errcheck
	if vfolder.IsIncludedInUserQuota() {
		dataprovider.UpdateUserQuota(&conn.User, numFiles, fileSize, false) //nolint:errcheck
	}
}

func checkWriterPermsAndQuota(conn *BaseConnection, virtualPath string, numFiles int, expectedSize, truncatedSize int64) error {
	if numFiles == 0 {
		if !conn.User.HasPerm(dataprovider.PermOverwrite, path.Dir(virtualPath)) {
			return conn.GetPermissionDeniedError()
		}
	} else {
		if !conn.User.HasPerm(dataprovider.PermUpload, path.Dir(virtualPath)) {
			return conn.GetPermissionDeniedError()
		}
	}
	q, _ := conn.HasSpace(numFiles > 0, false, virtualPath)
	if !q.HasSpace {
		return conn.GetQuotaExceededError()
	}
	if expectedSize != -1 {
		sizeDiff := expectedSize - truncatedSize
		if sizeDiff > 0 {
			remainingSize := q.GetRemainingSize()
			if remainingSize > 0 && remainingSize < sizeDiff {
				return conn.GetQuotaExceededError()
			}
		}
	}
	return nil
}

func getFileWriter(conn *BaseConnection, virtualPath string, expectedSize int64) (io.WriteCloser, int, int64, func(), error) {
	fs, fsPath, err := conn.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	var truncatedSize, fileSize int64
	numFiles := 1
	isFileOverwrite := false

	info, err := fs.Lstat(fsPath)
	if err == nil {
		fileSize = info.Size()
		if info.IsDir() {
			return nil, numFiles, truncatedSize, nil, fmt.Errorf("cannot write to a directory: %q", virtualPath)
		}
		if info.Mode().IsRegular() {
			isFileOverwrite = true
			truncatedSize = fileSize
		}
		numFiles = 0
	}
	if err != nil && !fs.IsNotExist(err) {
		return nil, numFiles, truncatedSize, nil, conn.GetFsError(fs, err)
	}
	if err := checkWriterPermsAndQuota(conn, virtualPath, numFiles, expectedSize, truncatedSize); err != nil {
		return nil, numFiles, truncatedSize, nil, err
	}
	f, w, cancelFn, err := fs.Create(fsPath, 0, conn.GetCreateChecks(virtualPath, numFiles == 1, false))
	if err != nil {
		return nil, numFiles, truncatedSize, nil, conn.GetFsError(fs, err)
	}
	vfs.SetPathPermissions(fs, fsPath, conn.User.GetUID(), conn.User.GetGID())

	if isFileOverwrite {
		if vfs.HasTruncateSupport(fs) || vfs.IsCryptOsFs(fs) {
			updateUserQuotaAfterFileWrite(conn, virtualPath, numFiles, -fileSize)
			truncatedSize = 0
		}
	}
	if cancelFn == nil {
		cancelFn = func() {}
	}
	if f != nil {
		return f, numFiles, truncatedSize, cancelFn, nil
	}
	return w, numFiles, truncatedSize, cancelFn, nil
}

func addZipEntry(wr *zipWriterWrapper, conn *BaseConnection, entryPath, baseDir string, recursion int) error {
	if entryPath == wr.Name {
		// skip the archive itself
		return nil
	}
	if recursion >= util.MaxRecursion {
		eventManagerLog(logger.LevelError, "unable to add zip entry %q, recursion too deep: %v", entryPath, recursion)
		return util.ErrRecursionTooDeep
	}
	recursion++
	info, err := conn.DoStat(entryPath, 1, false)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to add zip entry %q, stat error: %v", entryPath, err)
		return err
	}
	entryName, err := getZipEntryName(entryPath, baseDir)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to get zip entry name: %v", err)
		return err
	}
	if _, ok := wr.Entries[entryName]; ok {
		eventManagerLog(logger.LevelInfo, "skipping duplicate zip entry %q, is dir %t", entryPath, info.IsDir())
		return nil
	}
	wr.Entries[entryName] = true
	if info.IsDir() {
		_, err = wr.Writer.CreateHeader(&zip.FileHeader{
			Name:     entryName + "/",
			Method:   zip.Deflate,
			Modified: info.ModTime(),
		})
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to create zip entry %q: %v", entryPath, err)
			return fmt.Errorf("unable to create zip entry %q: %w", entryPath, err)
		}
		lister, err := conn.ListDir(entryPath)
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to add zip entry %q, get dir lister error: %v", entryPath, err)
			return fmt.Errorf("unable to add zip entry %q: %w", entryPath, err)
		}
		defer lister.Close()

		for {
			contents, err := lister.Next(vfs.ListerBatchSize)
			finished := errors.Is(err, io.EOF)
			if err := lister.convertError(err); err != nil {
				eventManagerLog(logger.LevelError, "unable to add zip entry %q, read dir error: %v", entryPath, err)
				return fmt.Errorf("unable to add zip entry %q: %w", entryPath, err)
			}
			for _, info := range contents {
				fullPath := util.CleanPath(path.Join(entryPath, info.Name()))
				if err := addZipEntry(wr, conn, fullPath, baseDir, recursion); err != nil {
					eventManagerLog(logger.LevelError, "unable to add zip entry: %v", err)
					return err
				}
			}
			if finished {
				return nil
			}
		}
	}
	if !info.Mode().IsRegular() {
		// we only allow regular files
		eventManagerLog(logger.LevelInfo, "skipping zip entry for non regular file %q", entryPath)
		return nil
	}

	return addFileToZip(wr, conn, entryPath, entryName, info.ModTime())
}

func addFileToZip(wr *zipWriterWrapper, conn *BaseConnection, entryPath, entryName string, modTime time.Time) error {
	reader, cancelFn, err := getFileReader(conn, entryPath)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to add zip entry %q, cannot open file: %v", entryPath, err)
		return fmt.Errorf("unable to open %q: %w", entryPath, err)
	}
	defer cancelFn()
	defer reader.Close()

	f, err := wr.Writer.CreateHeader(&zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: modTime,
	})
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to create zip entry %q: %v", entryPath, err)
		return fmt.Errorf("unable to create zip entry %q: %w", entryPath, err)
	}
	_, err = io.Copy(f, reader)
	return err
}

func getZipEntryName(entryPath, baseDir string) (string, error) {
	if !strings.HasPrefix(entryPath, baseDir) {
		return "", fmt.Errorf("entry path %q is outside base dir %q", entryPath, baseDir)
	}
	entryPath = strings.TrimPrefix(entryPath, baseDir)
	return strings.TrimPrefix(entryPath, "/"), nil
}

func getFileReader(conn *BaseConnection, virtualPath string) (io.ReadCloser, func(), error) {
	if !conn.User.HasPerm(dataprovider.PermDownload, path.Dir(virtualPath)) {
		return nil, nil, conn.GetPermissionDeniedError()
	}
	fs, fsPath, err := conn.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, nil, err
	}
	f, r, cancelFn, err := fs.Open(fsPath, 0)
	if err != nil {
		return nil, nil, conn.GetFsError(fs, err)
	}
	if cancelFn == nil {
		cancelFn = func() {}
	}

	if f != nil {
		return f, cancelFn, nil
	}
	return r, cancelFn, nil
}

func writeFileContent(conn *BaseConnection, virtualPath string, w io.Writer) error {
	reader, cancelFn, err := getFileReader(conn, virtualPath)
	if err != nil {
		return err
	}

	defer cancelFn()
	defer reader.Close()

	_, err = io.Copy(w, reader)
	return err
}

func getFileContentFn(conn *BaseConnection, virtualPath string, size int64) func(w io.Writer) (int64, error) {
	return func(w io.Writer) (int64, error) {
		reader, cancelFn, err := getFileReader(conn, virtualPath)
		if err != nil {
			return 0, err
		}

		defer cancelFn()
		defer reader.Close()

		return io.CopyN(w, reader, size)
	}
}

func getMailAttachments(conn *BaseConnection, attachments []string, replacer *strings.Replacer) ([]*mail.File, error) {
	var files []*mail.File
	totalSize := int64(0)

	for _, virtualPath := range replacePathsPlaceholders(attachments, replacer) {
		info, err := conn.DoStat(virtualPath, 0, false)
		if err != nil {
			return nil, fmt.Errorf("unable to get info for file %q, user %q: %w", virtualPath, conn.User.Username, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("cannot attach non regular file %q", virtualPath)
		}
		totalSize += info.Size()
		if totalSize > maxAttachmentsSize {
			return nil, fmt.Errorf("unable to send files as attachment, size too large: %s", util.ByteCountIEC(totalSize))
		}
		files = append(files, &mail.File{
			Name:   path.Base(virtualPath),
			Header: make(map[string][]string),
			Writer: getFileContentFn(conn, virtualPath, info.Size()),
		})
	}
	return files, nil
}

func replaceWithReplacer(input string, replacer *strings.Replacer) string {
	if !strings.Contains(input, "{{") {
		return input
	}
	return replacer.Replace(input)
}

func checkEventConditionPattern(p dataprovider.ConditionPattern, name string) bool {
	var matched bool
	var err error
	if strings.Contains(p.Pattern, "**") {
		matched, err = doublestar.Match(p.Pattern, name)
	} else {
		matched, err = path.Match(p.Pattern, name)
	}
	if err != nil {
		eventManagerLog(logger.LevelError, "pattern matching error %q, err: %v", p.Pattern, err)
		return false
	}
	if p.InverseMatch {
		return !matched
	}
	return matched
}

func checkUserConditionOptions(user *dataprovider.User, conditions *dataprovider.ConditionOptions) bool {
	if !checkEventConditionPatterns(user.Username, conditions.Names) {
		return false
	}
	if !checkEventConditionPatterns(user.Role, conditions.RoleNames) {
		return false
	}
	if !checkEventGroupConditionPatterns(user.Groups, conditions.GroupNames) {
		return false
	}
	return true
}

// checkConditionPatterns returns false if patterns are defined and no match is found
func checkEventConditionPatterns(name string, patterns []dataprovider.ConditionPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	matches := false
	for _, p := range patterns {
		// assume, that multiple InverseMatches are set
		if p.InverseMatch {
			if checkEventConditionPattern(p, name) {
				matches = true
			} else {
				return false
			}
		} else if checkEventConditionPattern(p, name) {
			return true
		}
	}
	return matches
}

func checkEventGroupConditionPatterns(groups []sdk.GroupMapping, patterns []dataprovider.ConditionPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	matches := false
	for _, group := range groups {
		for _, p := range patterns {
			// assume, that multiple InverseMatches are set
			if p.InverseMatch {
				if checkEventConditionPattern(p, group.Name) {
					matches = true
				} else {
					return false
				}
			} else {
				if checkEventConditionPattern(p, group.Name) {
					return true
				}
			}
		}
	}
	return matches
}

func getHTTPRuleActionEndpoint(c *dataprovider.EventActionHTTPConfig, replacer *strings.Replacer) (string, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint: %w", err)
	}
	if strings.Contains(u.Path, "{{") {
		pathComponents := strings.Split(u.Path, "/")
		for idx := range pathComponents {
			part := replaceWithReplacer(pathComponents[idx], replacer)
			if part != pathComponents[idx] {
				pathComponents[idx] = url.PathEscape(part)
			}
		}
		u.Path = ""
		u = u.JoinPath(pathComponents...)
	}
	if len(c.QueryParameters) > 0 {
		q := u.Query()

		for _, keyVal := range c.QueryParameters {
			q.Add(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
		}

		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func writeHTTPPart(m *multipart.Writer, part dataprovider.HTTPPart, h textproto.MIMEHeader,
	conn *BaseConnection, replacer *strings.Replacer, params *EventParams, addObjectData bool,
) error {
	partWriter, err := m.CreatePart(h)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to create part %q, err: %v", part.Name, err)
		return err
	}
	if part.Body != "" {
		cType := h.Get("Content-Type")
		if strings.Contains(strings.ToLower(cType), "application/json") {
			replacements := params.getStringReplacements(addObjectData, true)
			jsonReplacer := strings.NewReplacer(replacements...)
			_, err = partWriter.Write([]byte(replaceWithReplacer(part.Body, jsonReplacer)))
		} else {
			_, err = partWriter.Write([]byte(replaceWithReplacer(part.Body, replacer)))
		}
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to write part %q, err: %v", part.Name, err)
			return err
		}
		return nil
	}
	if part.Filepath == dataprovider.RetentionReportPlaceHolder {
		data, err := params.getCompressedDataRetentionReport()
		if err != nil {
			return err
		}
		_, err = partWriter.Write(data)
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to write part %q, err: %v", part.Name, err)
			return err
		}
		return nil
	}
	err = writeFileContent(conn, util.CleanPath(replacer.Replace(part.Filepath)), partWriter)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to write file part %q, err: %v", part.Name, err)
		return err
	}
	return nil
}

func getHTTPRuleActionBody(c *dataprovider.EventActionHTTPConfig, replacer *strings.Replacer,
	cancel context.CancelFunc, user dataprovider.User, params *EventParams, addObjectData bool,
) (io.Reader, string, error) {
	var body io.Reader
	if c.Method == http.MethodGet {
		return body, "", nil
	}
	if c.Body != "" {
		if c.Body == dataprovider.RetentionReportPlaceHolder {
			data, err := params.getCompressedDataRetentionReport()
			if err != nil {
				return body, "", err
			}
			return bytes.NewBuffer(data), "", nil
		}
		if c.HasJSONBody() {
			replacements := params.getStringReplacements(addObjectData, true)
			jsonReplacer := strings.NewReplacer(replacements...)
			return bytes.NewBufferString(replaceWithReplacer(c.Body, jsonReplacer)), "", nil
		}
		return bytes.NewBufferString(replaceWithReplacer(c.Body, replacer)), "", nil
	}
	if len(c.Parts) > 0 {
		r, w := io.Pipe()
		m := multipart.NewWriter(w)

		var conn *BaseConnection
		if user.Username != "" {
			var err error
			user, err = getUserForEventAction(user)
			if err != nil {
				return body, "", err
			}
			connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
			err = user.CheckFsRoot(connectionID)
			if err != nil {
				user.CloseFs() //nolint:errcheck
				return body, "", fmt.Errorf("error getting multipart file/s, unable to check root fs for user %q: %w",
					user.Username, err)
			}
			conn = NewBaseConnection(connectionID, protocolEventAction, "", "", user)
		}

		go func() {
			defer w.Close()
			defer user.CloseFs() //nolint:errcheck

			for _, part := range c.Parts {
				h := make(textproto.MIMEHeader)
				if part.Body != "" {
					h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"`, multipartQuoteEscaper.Replace(part.Name)))
				} else {
					h.Set("Content-Disposition",
						fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
							multipartQuoteEscaper.Replace(part.Name),
							multipartQuoteEscaper.Replace((path.Base(replaceWithReplacer(part.Filepath, replacer))))))
					contentType := mime.TypeByExtension(path.Ext(part.Filepath))
					if contentType == "" {
						contentType = "application/octet-stream"
					}
					h.Set("Content-Type", contentType)
				}
				for _, keyVal := range part.Headers {
					h.Set(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
				}
				if err := writeHTTPPart(m, part, h, conn, replacer, params, addObjectData); err != nil {
					cancel()
					return
				}
			}
			m.Close()
		}()

		return r, m.FormDataContentType(), nil
	}
	return body, "", nil
}

func setHTTPReqHeaders(req *http.Request, c *dataprovider.EventActionHTTPConfig, replacer *strings.Replacer,
	contentType string,
) {
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Username != "" || c.Password.GetPayload() != "" {
		req.SetBasicAuth(replaceWithReplacer(c.Username, replacer), c.Password.GetPayload())
	}
	for _, keyVal := range c.Headers {
		req.Header.Set(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
	}
}

func executeHTTPRuleAction(c dataprovider.EventActionHTTPConfig, params *EventParams) error {
	if err := c.TryDecryptPassword(); err != nil {
		return err
	}
	addObjectData := false
	if params.Object != nil {
		addObjectData = c.HasObjectData()
	}

	replacements := params.getStringReplacements(addObjectData, false)
	replacer := strings.NewReplacer(replacements...)
	endpoint, err := getHTTPRuleActionEndpoint(&c, replacer)
	if err != nil {
		return err
	}

	ctx, cancel := c.GetContext()
	defer cancel()

	var user dataprovider.User
	if c.HasMultipartFiles() {
		user, err = params.getUserFromSender()
		if err != nil {
			return err
		}
	}
	body, contentType, err := getHTTPRuleActionBody(&c, replacer, cancel, user, params, addObjectData)
	if err != nil {
		return err
	}
	if body != nil {
		rc, ok := body.(io.ReadCloser)
		if ok {
			defer rc.Close()
		}
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, endpoint, body)
	if err != nil {
		return err
	}
	setHTTPReqHeaders(req, &c, replacer, contentType)

	client := c.GetHTTPClient()
	defer client.CloseIdleConnections()

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		eventManagerLog(logger.LevelDebug, "unable to send http notification, endpoint: %s, elapsed: %s, err: %v",
			endpoint, time.Since(startTime), err)
		return fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	eventManagerLog(logger.LevelDebug, "http notification sent, endpoint: %s, elapsed: %s, status code: %d",
		endpoint, time.Since(startTime), resp.StatusCode)
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		if rb, err := io.ReadAll(io.LimitReader(resp.Body, 2048)); err == nil {
			eventManagerLog(logger.LevelDebug, "error notification response from endpoint %q: %s", endpoint, string(rb))
		}
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func executeCommandRuleAction(c dataprovider.EventActionCommandConfig, params *EventParams) error {
	addObjectData := false
	if params.Object != nil {
		for _, k := range c.EnvVars {
			if strings.Contains(k.Value, objDataPlaceholder) || strings.Contains(k.Value, objDataPlaceholderString) {
				addObjectData = true
				break
			}
		}
	}
	replacements := params.getStringReplacements(addObjectData, false)
	replacer := strings.NewReplacer(replacements...)

	args := make([]string, 0, len(c.Args))
	for _, arg := range c.Args {
		args = append(args, replaceWithReplacer(arg, replacer))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Cmd, args...)
	cmd.Env = []string{}
	for _, keyVal := range c.EnvVars {
		if keyVal.Value == "$" {
			val := os.Getenv(keyVal.Key)
			if val == "" {
				eventManagerLog(logger.LevelDebug, "empty value for environment variable %q", keyVal.Key)
			}
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", keyVal.Key, val))
		} else {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", keyVal.Key, replaceWithReplacer(keyVal.Value, replacer)))
		}
	}

	startTime := time.Now()
	err := cmd.Run()

	eventManagerLog(logger.LevelDebug, "executed command %q, elapsed: %s, error: %v",
		c.Cmd, time.Since(startTime), err)

	return err
}

func getEmailAddressesWithReplacer(addrs []string, replacer *strings.Replacer) []string {
	if len(addrs) == 0 {
		return nil
	}
	recipients := make([]string, 0, len(addrs))
	for _, recipient := range addrs {
		rcpt := replaceWithReplacer(recipient, replacer)
		if rcpt != "" {
			recipients = append(recipients, rcpt)
		}
	}
	return recipients
}

func executeEmailRuleAction(c dataprovider.EventActionEmailConfig, params *EventParams) error {
	addObjectData := false
	if params.Object != nil {
		if strings.Contains(c.Body, objDataPlaceholder) || strings.Contains(c.Body, objDataPlaceholderString) {
			addObjectData = true
		}
	}
	replacements := params.getStringReplacements(addObjectData, false)
	replacer := strings.NewReplacer(replacements...)
	body := replaceWithReplacer(c.Body, replacer)
	subject := replaceWithReplacer(c.Subject, replacer)
	recipients := getEmailAddressesWithReplacer(c.Recipients, replacer)
	bcc := getEmailAddressesWithReplacer(c.Bcc, replacer)
	startTime := time.Now()
	var files []*mail.File
	fileAttachments := make([]string, 0, len(c.Attachments))
	for _, attachment := range c.Attachments {
		if attachment == dataprovider.RetentionReportPlaceHolder {
			f, err := params.getRetentionReportsAsMailAttachment()
			if err != nil {
				return err
			}
			files = append(files, f)
			continue
		}
		fileAttachments = append(fileAttachments, attachment)
	}
	if len(fileAttachments) > 0 {
		user, err := params.getUserFromSender()
		if err != nil {
			return err
		}
		user, err = getUserForEventAction(user)
		if err != nil {
			return err
		}
		connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
		err = user.CheckFsRoot(connectionID)
		defer user.CloseFs() //nolint:errcheck
		if err != nil {
			return fmt.Errorf("error getting email attachments, unable to check root fs for user %q: %w", user.Username, err)
		}
		conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
		res, err := getMailAttachments(conn, fileAttachments, replacer)
		if err != nil {
			return err
		}
		files = append(files, res...)
	}
	err := smtp.SendEmail(recipients, bcc, subject, body, smtp.EmailContentType(c.ContentType), files...)
	eventManagerLog(logger.LevelDebug, "executed email notification action, elapsed: %s, error: %v",
		time.Since(startTime), err)
	if err != nil {
		return fmt.Errorf("unable to send email: %w", err)
	}
	return nil
}

func getUserForEventAction(user dataprovider.User) (dataprovider.User, error) {
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to get group for user %q: %+v", user.Username, err)
		return dataprovider.User{}, fmt.Errorf("unable to get groups for user %q", user.Username)
	}
	user.UploadDataTransfer = 0
	user.UploadBandwidth = 0
	user.DownloadBandwidth = 0
	user.Filters.DisableFsChecks = false
	user.Filters.FilePatterns = nil
	user.Filters.BandwidthLimits = nil
	for k := range user.Permissions {
		user.Permissions[k] = []string{dataprovider.PermAny}
	}
	return user, nil
}

func replacePathsPlaceholders(paths []string, replacer *strings.Replacer) []string {
	results := make([]string, 0, len(paths))
	for _, p := range paths {
		results = append(results, util.CleanPath(replaceWithReplacer(p, replacer)))
	}
	return util.RemoveDuplicates(results, false)
}

func executeDeleteFileFsAction(conn *BaseConnection, item string, info os.FileInfo) error {
	fs, fsPath, err := conn.GetFsAndResolvedPath(item)
	if err != nil {
		return err
	}
	return conn.RemoveFile(fs, fsPath, item, info)
}

func executeDeleteFsActionForUser(deletes []string, replacer *strings.Replacer, user dataprovider.User) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("delete error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	for _, item := range replacePathsPlaceholders(deletes, replacer) {
		info, err := conn.DoStat(item, 0, false)
		if err != nil {
			if conn.IsNotExistError(err) {
				continue
			}
			return fmt.Errorf("unable to check item to delete %q, user %q: %w", item, user.Username, err)
		}
		if info.IsDir() {
			if err = conn.RemoveDir(item); err != nil {
				return fmt.Errorf("unable to remove dir %q, user %q: %w", item, user.Username, err)
			}
		} else {
			if err = executeDeleteFileFsAction(conn, item, info); err != nil {
				return fmt.Errorf("unable to remove file %q, user %q: %w", item, user.Username, err)
			}
		}
		eventManagerLog(logger.LevelDebug, "item %q removed for user %q", item, user.Username)
	}
	return nil
}

func executeDeleteFsRuleAction(deletes []string, replacer *strings.Replacer,
	conditions dataprovider.ConditionOptions, params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs delete for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeDeleteFsActionForUser(deletes, replacer, user); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs delete failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no delete executed")
		return errors.New("no delete executed")
	}
	return nil
}

func executeMkDirsFsActionForUser(dirs []string, replacer *strings.Replacer, user dataprovider.User) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("mkdir error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	for _, item := range replacePathsPlaceholders(dirs, replacer) {
		if err = conn.CheckParentDirs(path.Dir(item)); err != nil {
			return fmt.Errorf("unable to check parent dirs for %q, user %q: %w", item, user.Username, err)
		}
		if err = conn.createDirIfMissing(item); err != nil {
			return fmt.Errorf("unable to create dir %q, user %q: %w", item, user.Username, err)
		}
		eventManagerLog(logger.LevelDebug, "directory %q created for user %q", item, user.Username)
	}
	return nil
}

func executeMkdirFsRuleAction(dirs []string, replacer *strings.Replacer,
	conditions dataprovider.ConditionOptions, params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs mkdir for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeMkDirsFsActionForUser(dirs, replacer, user); err != nil {
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs mkdir failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no mkdir executed")
		return errors.New("no mkdir executed")
	}
	return nil
}

func executeRenameFsActionForUser(renames []dataprovider.KeyValue, replacer *strings.Replacer,
	user dataprovider.User,
) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("rename error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	for _, item := range renames {
		source := util.CleanPath(replaceWithReplacer(item.Key, replacer))
		target := util.CleanPath(replaceWithReplacer(item.Value, replacer))
		if err = conn.renameInternal(source, target, true); err != nil {
			return fmt.Errorf("unable to rename %q->%q, user %q: %w", source, target, user.Username, err)
		}
		eventManagerLog(logger.LevelDebug, "rename %q->%q ok, user %q", source, target, user.Username)
	}
	return nil
}

func executeCopyFsActionForUser(copy []dataprovider.KeyValue, replacer *strings.Replacer,
	user dataprovider.User,
) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("copy error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	for _, item := range copy {
		source := util.CleanPath(replaceWithReplacer(item.Key, replacer))
		target := util.CleanPath(replaceWithReplacer(item.Value, replacer))
		if strings.HasSuffix(item.Key, "/") {
			source += "/"
		}
		if strings.HasSuffix(item.Value, "/") {
			target += "/"
		}
		if err = conn.Copy(source, target); err != nil {
			return fmt.Errorf("unable to copy %q->%q, user %q: %w", source, target, user.Username, err)
		}
		eventManagerLog(logger.LevelDebug, "copy %q->%q ok, user %q", source, target, user.Username)
	}
	return nil
}

func executeExistFsActionForUser(exist []string, replacer *strings.Replacer,
	user dataprovider.User,
) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("existence check error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	for _, item := range replacePathsPlaceholders(exist, replacer) {
		if _, err = conn.DoStat(item, 0, false); err != nil {
			return fmt.Errorf("error checking existence for path %q, user %q: %w", item, user.Username, err)
		}
		eventManagerLog(logger.LevelDebug, "path %q exists for user %q", item, user.Username)
	}
	return nil
}

func executeRenameFsRuleAction(renames []dataprovider.KeyValue, replacer *strings.Replacer,
	conditions dataprovider.ConditionOptions, params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs rename for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeRenameFsActionForUser(renames, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs rename failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no rename executed")
		return errors.New("no rename executed")
	}
	return nil
}

func executeCopyFsRuleAction(copy []dataprovider.KeyValue, replacer *strings.Replacer,
	conditions dataprovider.ConditionOptions, params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	var executed int
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs copy for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeCopyFsActionForUser(copy, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs copy failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no copy executed")
		return errors.New("no copy executed")
	}
	return nil
}

func getArchiveBaseDir(paths []string) string {
	var parentDirs []string
	for _, p := range paths {
		parentDirs = append(parentDirs, path.Dir(p))
	}
	parentDirs = util.RemoveDuplicates(parentDirs, false)
	baseDir := "/"
	if len(parentDirs) == 1 {
		baseDir = parentDirs[0]
	}
	return baseDir
}

func getSizeForPath(conn *BaseConnection, p string, info os.FileInfo) (int64, error) {
	if info.IsDir() {
		var dirSize int64
		lister, err := conn.ListDir(p)
		if err != nil {
			return 0, err
		}
		defer lister.Close()
		for {
			entries, err := lister.Next(vfs.ListerBatchSize)
			finished := errors.Is(err, io.EOF)
			if err != nil && !finished {
				return 0, err
			}
			for _, entry := range entries {
				size, err := getSizeForPath(conn, path.Join(p, entry.Name()), entry)
				if err != nil {
					return 0, err
				}
				dirSize += size
			}
			if finished {
				return dirSize, nil
			}
		}
	}
	if info.Mode().IsRegular() {
		return info.Size(), nil
	}
	return 0, nil
}

func estimateZipSize(conn *BaseConnection, zipPath string, paths []string) (int64, error) {
	q, _ := conn.HasSpace(false, false, zipPath)
	if q.HasSpace && q.GetRemainingSize() > 0 {
		var size int64
		for _, item := range paths {
			info, err := conn.DoStat(item, 1, false)
			if err != nil {
				return size, err
			}
			itemSize, err := getSizeForPath(conn, item, info)
			if err != nil {
				return size, err
			}
			size += itemSize
		}
		eventManagerLog(logger.LevelDebug, "archive paths %v, archive name %q, size: %d", paths, zipPath, size)
		// we assume the zip size will be half of the real size
		return size / 2, nil
	}
	return -1, nil
}

func executeCompressFsActionForUser(c dataprovider.EventActionFsCompress, replacer *strings.Replacer,
	user dataprovider.User,
) error {
	user, err := getUserForEventAction(user)
	if err != nil {
		return err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return fmt.Errorf("compress error, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	name := util.CleanPath(replaceWithReplacer(c.Name, replacer))
	conn.CheckParentDirs(path.Dir(name)) //nolint:errcheck
	paths := make([]string, 0, len(c.Paths))
	for idx := range c.Paths {
		p := util.CleanPath(replaceWithReplacer(c.Paths[idx], replacer))
		if p == name {
			return fmt.Errorf("cannot compress the archive to create: %q", name)
		}
		paths = append(paths, p)
	}
	paths = util.RemoveDuplicates(paths, false)
	estimatedSize, err := estimateZipSize(conn, name, paths)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to estimate size for archive %q: %v", name, err)
		return fmt.Errorf("unable to estimate archive size: %w", err)
	}
	writer, numFiles, truncatedSize, cancelFn, err := getFileWriter(conn, name, estimatedSize)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to create archive %q: %v", name, err)
		return fmt.Errorf("unable to create archive: %w", err)
	}
	defer cancelFn()

	baseDir := getArchiveBaseDir(paths)
	eventManagerLog(logger.LevelDebug, "creating archive %q for paths %+v", name, paths)

	zipWriter := &zipWriterWrapper{
		Name:    name,
		Writer:  zip.NewWriter(writer),
		Entries: make(map[string]bool),
	}
	startTime := time.Now()
	for _, item := range paths {
		if err := addZipEntry(zipWriter, conn, item, baseDir, 0); err != nil {
			closeWriterAndUpdateQuota(writer, conn, name, "", numFiles, truncatedSize, err, operationUpload, startTime) //nolint:errcheck
			return err
		}
	}
	if err := zipWriter.Writer.Close(); err != nil {
		eventManagerLog(logger.LevelError, "unable to close zip file %q: %v", name, err)
		closeWriterAndUpdateQuota(writer, conn, name, "", numFiles, truncatedSize, err, operationUpload, startTime) //nolint:errcheck
		return fmt.Errorf("unable to close zip file %q: %w", name, err)
	}
	return closeWriterAndUpdateQuota(writer, conn, name, "", numFiles, truncatedSize, err, operationUpload, startTime)
}

func executeExistFsRuleAction(exist []string, replacer *strings.Replacer, conditions dataprovider.ConditionOptions,
	params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs exist for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeExistFsActionForUser(exist, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs existence check failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no existence check executed")
		return errors.New("no existence check executed")
	}
	return nil
}

func executeCompressFsRuleAction(c dataprovider.EventActionFsCompress, replacer *strings.Replacer,
	conditions dataprovider.ConditionOptions, params *EventParams,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping fs compress for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeCompressFsActionForUser(c, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs compress failed for users: %s", strings.Join(failures, ","))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no file/folder compressed")
		return errors.New("no file/folder compressed")
	}
	return nil
}

func executeFsRuleAction(c dataprovider.EventActionFilesystemConfig, conditions dataprovider.ConditionOptions,
	params *EventParams,
) error {
	addObjectData := false
	replacements := params.getStringReplacements(addObjectData, false)
	replacer := strings.NewReplacer(replacements...)
	switch c.Type {
	case dataprovider.FilesystemActionRename:
		return executeRenameFsRuleAction(c.Renames, replacer, conditions, params)
	case dataprovider.FilesystemActionDelete:
		return executeDeleteFsRuleAction(c.Deletes, replacer, conditions, params)
	case dataprovider.FilesystemActionMkdirs:
		return executeMkdirFsRuleAction(c.MkDirs, replacer, conditions, params)
	case dataprovider.FilesystemActionExist:
		return executeExistFsRuleAction(c.Exist, replacer, conditions, params)
	case dataprovider.FilesystemActionCompress:
		return executeCompressFsRuleAction(c.Compress, replacer, conditions, params)
	case dataprovider.FilesystemActionCopy:
		return executeCopyFsRuleAction(c.Copy, replacer, conditions, params)
	default:
		return fmt.Errorf("unsupported filesystem action %d", c.Type)
	}
}

func executeQuotaResetForUser(user *dataprovider.User) error {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		eventManagerLog(logger.LevelError, "skipping scheduled quota reset for user %s, cannot apply group settings: %v",
			user.Username, err)
		return err
	}
	if !QuotaScans.AddUserQuotaScan(user.Username, user.Role) {
		eventManagerLog(logger.LevelError, "another quota scan is already in progress for user %q", user.Username)
		return fmt.Errorf("another quota scan is in progress for user %q", user.Username)
	}
	defer QuotaScans.RemoveUserQuotaScan(user.Username)

	numFiles, size, err := user.ScanQuota()
	if err != nil {
		eventManagerLog(logger.LevelError, "error scanning quota for user %q: %v", user.Username, err)
		return fmt.Errorf("error scanning quota for user %q: %w", user.Username, err)
	}
	err = dataprovider.UpdateUserQuota(user, numFiles, size, true)
	if err != nil {
		eventManagerLog(logger.LevelError, "error updating quota for user %q: %v", user.Username, err)
		return fmt.Errorf("error updating quota for user %q: %w", user.Username, err)
	}
	return nil
}

func executeUsersQuotaResetRuleAction(conditions dataprovider.ConditionOptions, params *EventParams) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping quota reset for user %q, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeQuotaResetForUser(&user); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("quota reset failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no user quota reset executed")
		return errors.New("no user quota reset executed")
	}
	return nil
}

func executeFoldersQuotaResetRuleAction(conditions dataprovider.ConditionOptions, params *EventParams) error {
	folders, err := params.getFolders()
	if err != nil {
		return fmt.Errorf("unable to get folders: %w", err)
	}
	var failures []string
	executed := 0
	for _, folder := range folders {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" && !checkEventConditionPatterns(folder.Name, conditions.Names) {
			eventManagerLog(logger.LevelDebug, "skipping scheduled quota reset for folder %s, name conditions don't match",
				folder.Name)
			continue
		}
		if !QuotaScans.AddVFolderQuotaScan(folder.Name) {
			eventManagerLog(logger.LevelError, "another quota scan is already in progress for folder %q", folder.Name)
			params.AddError(fmt.Errorf("another quota scan is already in progress for folder %q", folder.Name))
			failures = append(failures, folder.Name)
			continue
		}
		executed++
		f := vfs.VirtualFolder{
			BaseVirtualFolder: folder,
			VirtualPath:       "/",
		}
		numFiles, size, err := f.ScanQuota()
		QuotaScans.RemoveVFolderQuotaScan(folder.Name)
		if err != nil {
			eventManagerLog(logger.LevelError, "error scanning quota for folder %q: %v", folder.Name, err)
			params.AddError(fmt.Errorf("error scanning quota for folder %q: %w", folder.Name, err))
			failures = append(failures, folder.Name)
			continue
		}
		err = dataprovider.UpdateVirtualFolderQuota(&folder, numFiles, size, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating quota for folder %q: %v", folder.Name, err)
			params.AddError(fmt.Errorf("error updating quota for folder %q: %w", folder.Name, err))
			failures = append(failures, folder.Name)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("quota reset failed for folders: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no folder quota reset executed")
		return errors.New("no folder quota reset executed")
	}
	return nil
}

func executeTransferQuotaResetRuleAction(conditions dataprovider.ConditionOptions, params *EventParams) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled transfer quota reset for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		err = dataprovider.UpdateUserTransferQuota(&user, 0, 0, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating transfer quota for user %q: %v", user.Username, err)
			params.AddError(fmt.Errorf("error updating transfer quota for user %q: %w", user.Username, err))
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("transfer quota reset failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no transfer quota reset executed")
		return errors.New("no transfer quota reset executed")
	}
	return nil
}

func executeDataRetentionCheckForUser(user dataprovider.User, folders []dataprovider.FolderRetention,
	params *EventParams, actionName string,
) error {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		eventManagerLog(logger.LevelError, "skipping scheduled retention check for user %s, cannot apply group settings: %v",
			user.Username, err)
		return err
	}
	check := RetentionCheck{
		Folders: folders,
	}
	c := RetentionChecks.Add(check, &user)
	if c == nil {
		eventManagerLog(logger.LevelError, "another retention check is already in progress for user %q", user.Username)
		return fmt.Errorf("another retention check is in progress for user %q", user.Username)
	}
	defer func() {
		params.retentionChecks = append(params.retentionChecks, executedRetentionCheck{
			Username:   user.Username,
			ActionName: actionName,
			Results:    c.results,
		})
	}()
	if err := c.Start(); err != nil {
		eventManagerLog(logger.LevelError, "error checking retention for user %q: %v", user.Username, err)
		return fmt.Errorf("error checking retention for user %q: %w", user.Username, err)
	}
	return nil
}

func executeDataRetentionCheckRuleAction(config dataprovider.EventActionDataRetentionConfig,
	conditions dataprovider.ConditionOptions, params *EventParams, actionName string,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled retention check for user %s, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeDataRetentionCheckForUser(user, config.Folders, params, actionName); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("retention check failed for users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no retention check executed")
		return errors.New("no retention check executed")
	}
	return nil
}

func executeUserExpirationCheckRuleAction(conditions dataprovider.ConditionOptions, params *EventParams) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	var executed int
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping expiration check for user %q, condition options don't match",
					user.Username)
				continue
			}
		}
		executed++
		if user.ExpirationDate > 0 {
			expDate := util.GetTimeFromMsecSinceEpoch(user.ExpirationDate)
			if expDate.Before(time.Now()) {
				failures = append(failures, user.Username)
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("expired users: %s", strings.Join(failures, ", "))
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no user expiration check executed")
		return errors.New("no user expiration check executed")
	}
	return nil
}

func executeInactivityCheckForUser(user *dataprovider.User, config dataprovider.EventActionUserInactivity, when time.Time) error {
	if config.DeleteThreshold > 0 && (user.Status == 0 || config.DisableThreshold == 0) {
		if inactivityDays := user.InactivityDays(when); inactivityDays > config.DeleteThreshold {
			err := dataprovider.DeleteUser(user.Username, dataprovider.ActionExecutorSystem, "", "")
			eventManagerLog(logger.LevelInfo, "deleting inactive user %q, days of inactivity: %d/%d, err: %v",
				user.Username, inactivityDays, config.DeleteThreshold, err)
			if err != nil {
				return fmt.Errorf("unable to delete inactive user %q", user.Username)
			}
			return fmt.Errorf("inactive user %q deleted. Number of days of inactivity: %d", user.Username, inactivityDays)
		}
	}
	if config.DisableThreshold > 0 && user.Status > 0 {
		if inactivityDays := user.InactivityDays(when); inactivityDays > config.DisableThreshold {
			user.Status = 0
			err := dataprovider.UpdateUser(user, dataprovider.ActionExecutorSystem, "", "")
			eventManagerLog(logger.LevelInfo, "disabling inactive user %q, days of inactivity: %d/%d, err: %v",
				user.Username, inactivityDays, config.DisableThreshold, err)
			if err != nil {
				return fmt.Errorf("unable to disable inactive user %q", user.Username)
			}
			return fmt.Errorf("inactive user %q disabled. Number of days of inactivity: %d", user.Username, inactivityDays)
		}
	}

	return nil
}

func executeUserInactivityCheckRuleAction(config dataprovider.EventActionUserInactivity,
	conditions dataprovider.ConditionOptions,
	params *EventParams,
	when time.Time,
) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping inactivity check for user %q, condition options don't match",
					user.Username)
				continue
			}
		}
		if err = executeInactivityCheckForUser(&user, config, when); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("executed inactivity check actions for users: %s", strings.Join(failures, ", "))
	}

	return nil
}

func executePwdExpirationCheckForUser(user *dataprovider.User, config dataprovider.EventActionPasswordExpiration) error {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		eventManagerLog(logger.LevelError, "skipping password expiration check for user %q, cannot apply group settings: %v",
			user.Username, err)
		return err
	}
	if user.ExpirationDate > 0 {
		if expDate := util.GetTimeFromMsecSinceEpoch(user.ExpirationDate); expDate.Before(time.Now()) {
			eventManagerLog(logger.LevelDebug, "skipping password expiration check for expired user %q, expiration date: %s",
				user.Username, expDate)
			return nil
		}
	}
	if user.Filters.PasswordExpiration == 0 {
		eventManagerLog(logger.LevelDebug, "password expiration not set for user %q skipping check", user.Username)
		return nil
	}
	days := user.PasswordExpiresIn()
	if days > config.Threshold {
		eventManagerLog(logger.LevelDebug, "password for user %q expires in %d days, threshold %d, no need to notify",
			user.Username, days, config.Threshold)
		return nil
	}
	body := new(bytes.Buffer)
	data := make(map[string]any)
	data["Username"] = user.Username
	data["Days"] = days
	if err := smtp.RenderPasswordExpirationTemplate(body, data); err != nil {
		eventManagerLog(logger.LevelError, "unable to notify password expiration for user %s: %v",
			user.Username, err)
		return err
	}
	subject := "SFTPGo password expiration notification"
	startTime := time.Now()
	if err := smtp.SendEmail([]string{user.Email}, nil, subject, body.String(), smtp.EmailContentTypeTextHTML); err != nil {
		eventManagerLog(logger.LevelError, "unable to notify password expiration for user %s: %v, elapsed: %s",
			user.Username, err, time.Since(startTime))
		return err
	}
	eventManagerLog(logger.LevelDebug, "password expiration email sent to user %s, days: %d, elapsed: %s",
		user.Username, days, time.Since(startTime))
	return nil
}

func executePwdExpirationCheckRuleAction(config dataprovider.EventActionPasswordExpiration, conditions dataprovider.ConditionOptions,
	params *EventParams) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkUserConditionOptions(&user, &conditions) {
				eventManagerLog(logger.LevelDebug, "skipping password check for user %q, condition options don't match",
					user.Username)
				continue
			}
		}
		if err = executePwdExpirationCheckForUser(&user, config); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("password expiration check failed for users: %s", strings.Join(failures, ", "))
	}

	return nil
}

func executeAdminCheckAction(c *dataprovider.EventActionIDPAccountCheck, params *EventParams) (*dataprovider.Admin, error) {
	admin, err := dataprovider.AdminExists(params.Name)
	exists := err == nil
	if exists && c.Mode == 1 {
		return &admin, nil
	}
	if err != nil && !errors.Is(err, util.ErrNotFound) {
		return nil, err
	}

	replacements := params.getStringReplacements(false, true)
	replacer := strings.NewReplacer(replacements...)
	data := replaceWithReplacer(c.TemplateAdmin, replacer)

	var newAdmin dataprovider.Admin
	err = json.Unmarshal([]byte(data), &newAdmin)
	if err != nil {
		return nil, err
	}
	if newAdmin.Password == "" {
		newAdmin.Password = util.GenerateUniqueID()
	}
	if exists {
		eventManagerLog(logger.LevelDebug, "updating admin %q after IDP login", params.Name)
		err = dataprovider.UpdateAdmin(&newAdmin, dataprovider.ActionExecutorSystem, "", "")
	} else {
		eventManagerLog(logger.LevelDebug, "creating admin %q after IDP login", params.Name)
		err = dataprovider.AddAdmin(&newAdmin, dataprovider.ActionExecutorSystem, "", "")
	}
	return &newAdmin, err
}

func executeUserCheckAction(c *dataprovider.EventActionIDPAccountCheck, params *EventParams) (*dataprovider.User, error) {
	user, err := dataprovider.UserExists(params.Name, "")
	exists := err == nil
	if exists && c.Mode == 1 {
		err = user.LoadAndApplyGroupSettings()
		return &user, err
	}
	if err != nil && !errors.Is(err, util.ErrNotFound) {
		return nil, err
	}
	replacements := params.getStringReplacements(false, true)
	replacer := strings.NewReplacer(replacements...)
	data := replaceWithReplacer(c.TemplateUser, replacer)

	var newUser dataprovider.User
	err = json.Unmarshal([]byte(data), &newUser)
	if err != nil {
		return nil, err
	}
	if exists {
		eventManagerLog(logger.LevelDebug, "updating user %q after IDP login", params.Name)
		err = dataprovider.UpdateUser(&newUser, dataprovider.ActionExecutorSystem, "", "")
	} else {
		eventManagerLog(logger.LevelDebug, "creating user %q after IDP login", params.Name)
		err = dataprovider.AddUser(&newUser, dataprovider.ActionExecutorSystem, "", "")
	}
	if err != nil {
		return nil, err
	}
	u, err := dataprovider.GetUserWithGroupSettings(params.Name, "")
	return &u, err
}

func executeRuleAction(action dataprovider.BaseEventAction, params *EventParams,
	conditions dataprovider.ConditionOptions,
) error {
	var err error

	switch action.Type {
	case dataprovider.ActionTypeHTTP:
		err = executeHTTPRuleAction(action.Options.HTTPConfig, params)
	case dataprovider.ActionTypeCommand:
		err = executeCommandRuleAction(action.Options.CmdConfig, params)
	case dataprovider.ActionTypeEmail:
		err = executeEmailRuleAction(action.Options.EmailConfig, params)
	case dataprovider.ActionTypeBackup:
		var backupPath string
		backupPath, err = dataprovider.ExecuteBackup()
		if err == nil {
			params.setBackupParams(backupPath)
		}
	case dataprovider.ActionTypeUserQuotaReset:
		err = executeUsersQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeFolderQuotaReset:
		err = executeFoldersQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeTransferQuotaReset:
		err = executeTransferQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeDataRetentionCheck:
		err = executeDataRetentionCheckRuleAction(action.Options.RetentionConfig, conditions, params, action.Name)
	case dataprovider.ActionTypeFilesystem:
		err = executeFsRuleAction(action.Options.FsConfig, conditions, params)
	case dataprovider.ActionTypePasswordExpirationCheck:
		err = executePwdExpirationCheckRuleAction(action.Options.PwdExpirationConfig, conditions, params)
	case dataprovider.ActionTypeUserExpirationCheck:
		err = executeUserExpirationCheckRuleAction(conditions, params)
	case dataprovider.ActionTypeUserInactivityCheck:
		err = executeUserInactivityCheckRuleAction(action.Options.UserInactivityConfig, conditions, params, time.Now())
	default:
		err = fmt.Errorf("unsupported action type: %d", action.Type)
	}

	if err != nil {
		err = fmt.Errorf("action %q failed: %w", action.Name, err)
	}
	params.AddError(err)
	return err
}

func executeIDPAccountCheckRule(rule dataprovider.EventRule, params EventParams) (*dataprovider.User,
	*dataprovider.Admin, error,
) {
	for _, action := range rule.Actions {
		if action.Type == dataprovider.ActionTypeIDPAccountCheck {
			startTime := time.Now()
			var user *dataprovider.User
			var admin *dataprovider.Admin
			var err error
			var failedActions []string
			paramsCopy := params.getACopy()

			switch params.Event {
			case IDPLoginAdmin:
				admin, err = executeAdminCheckAction(&action.BaseEventAction.Options.IDPConfig, paramsCopy)
			case IDPLoginUser:
				user, err = executeUserCheckAction(&action.BaseEventAction.Options.IDPConfig, paramsCopy)
			default:
				err = fmt.Errorf("unsupported IDP login event: %q", params.Event)
			}
			if err != nil {
				paramsCopy.AddError(fmt.Errorf("unable to handle %q: %w", params.Event, err))
				eventManagerLog(logger.LevelError, "unable to handle IDP login event %q, err: %v", params.Event, err)
				failedActions = append(failedActions, action.Name)
			} else {
				eventManagerLog(logger.LevelDebug, "executed action %q for rule %q, elapsed %s",
					action.Name, rule.Name, time.Since(startTime))
			}
			// execute async actions if any, including failure actions
			go executeRuleAsyncActions(rule, paramsCopy, failedActions)
			return user, admin, err
		}
	}
	eventManagerLog(logger.LevelError, "no action executed for IDP login event %q, event rule: %q", params.Event, rule.Name)
	return nil, nil, errors.New("no action executed")
}

func executeSyncRulesActions(rules []dataprovider.EventRule, params EventParams) error {
	var errRes error

	for _, rule := range rules {
		var failedActions []string
		paramsCopy := params.getACopy()
		for _, action := range rule.Actions {
			if !action.Options.IsFailureAction && action.Options.ExecuteSync {
				startTime := time.Now()
				if err := executeRuleAction(action.BaseEventAction, paramsCopy, rule.Conditions.Options); err != nil {
					eventManagerLog(logger.LevelError, "unable to execute sync action %q for rule %q, elapsed %s, err: %v",
						action.Name, rule.Name, time.Since(startTime), err)
					failedActions = append(failedActions, action.Name)
					// we return the last error, it is ok for now
					errRes = err
					if action.Options.StopOnFailure {
						break
					}
				} else {
					eventManagerLog(logger.LevelDebug, "executed sync action %q for rule %q, elapsed: %s",
						action.Name, rule.Name, time.Since(startTime))
				}
			}
		}
		// execute async actions if any, including failure actions
		go executeRuleAsyncActions(rule, paramsCopy, failedActions)
	}

	return errRes
}

func executeAsyncRulesActions(rules []dataprovider.EventRule, params EventParams) {
	eventManager.addAsyncTask()
	defer eventManager.removeAsyncTask()

	params.addUID()
	for _, rule := range rules {
		executeRuleAsyncActions(rule, params.getACopy(), nil)
	}
}

func executeRuleAsyncActions(rule dataprovider.EventRule, params *EventParams, failedActions []string) {
	for _, action := range rule.Actions {
		if !action.Options.IsFailureAction && !action.Options.ExecuteSync {
			startTime := time.Now()
			if err := executeRuleAction(action.BaseEventAction, params, rule.Conditions.Options); err != nil {
				eventManagerLog(logger.LevelError, "unable to execute action %q for rule %q, elapsed %s, err: %v",
					action.Name, rule.Name, time.Since(startTime), err)
				failedActions = append(failedActions, action.Name)
				if action.Options.StopOnFailure {
					break
				}
			} else {
				eventManagerLog(logger.LevelDebug, "executed action %q for rule %q, elapsed %s",
					action.Name, rule.Name, time.Since(startTime))
			}
		}
	}
	if len(failedActions) > 0 {
		params.updateStatusFromError = false
		// execute failure actions
		for _, action := range rule.Actions {
			if action.Options.IsFailureAction {
				startTime := time.Now()
				if err := executeRuleAction(action.BaseEventAction, params, rule.Conditions.Options); err != nil {
					eventManagerLog(logger.LevelError, "unable to execute failure action %q for rule %q, elapsed %s, err: %v",
						action.Name, rule.Name, time.Since(startTime), err)
					if action.Options.StopOnFailure {
						break
					}
				} else {
					eventManagerLog(logger.LevelDebug, "executed failure action %q for rule %q, elapsed: %s",
						action.Name, rule.Name, time.Since(startTime))
				}
			}
		}
	}
}

type eventCronJob struct {
	ruleName string
}

func (j *eventCronJob) getTask(rule *dataprovider.EventRule) (dataprovider.Task, error) {
	if rule.GuardFromConcurrentExecution() {
		task, err := dataprovider.GetTaskByName(rule.Name)
		if err != nil {
			if errors.Is(err, util.ErrNotFound) {
				eventManagerLog(logger.LevelDebug, "adding task for rule %q", rule.Name)
				task = dataprovider.Task{
					Name:     rule.Name,
					UpdateAt: 0,
					Version:  0,
				}
				err = dataprovider.AddTask(rule.Name)
				if err != nil {
					eventManagerLog(logger.LevelWarn, "unable to add task for rule %q: %v", rule.Name, err)
					return task, err
				}
			} else {
				eventManagerLog(logger.LevelWarn, "unable to get task for rule %q: %v", rule.Name, err)
			}
		}
		return task, err
	}

	return dataprovider.Task{}, nil
}

func (j *eventCronJob) Run() {
	eventManagerLog(logger.LevelDebug, "executing scheduled rule %q", j.ruleName)
	rule, err := dataprovider.EventRuleExists(j.ruleName)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to load rule with name %q", j.ruleName)
		return
	}
	if err := rule.CheckActionsConsistency(""); err != nil {
		eventManagerLog(logger.LevelWarn, "scheduled rule %q skipped: %v", rule.Name, err)
		return
	}
	task, err := j.getTask(&rule)
	if err != nil {
		return
	}
	if task.Name != "" {
		updateInterval := 5 * time.Minute
		updatedAt := util.GetTimeFromMsecSinceEpoch(task.UpdateAt)
		if updatedAt.Add(updateInterval*2 + 1).After(time.Now()) {
			eventManagerLog(logger.LevelDebug, "task for rule %q too recent: %s, skip execution", rule.Name, updatedAt)
			return
		}
		err = dataprovider.UpdateTask(rule.Name, task.Version)
		if err != nil {
			eventManagerLog(logger.LevelInfo, "unable to update task timestamp for rule %q, skip execution, err: %v",
				rule.Name, err)
			return
		}
		ticker := time.NewTicker(updateInterval)
		done := make(chan bool)

		defer func() {
			done <- true
			ticker.Stop()
		}()

		go func(taskName string) {
			eventManagerLog(logger.LevelDebug, "update task %q timestamp worker started", taskName)
			for {
				select {
				case <-done:
					eventManagerLog(logger.LevelDebug, "update task %q timestamp worker finished", taskName)
					return
				case <-ticker.C:
					err := dataprovider.UpdateTaskTimestamp(taskName)
					eventManagerLog(logger.LevelInfo, "updated timestamp for task %q, err: %v", taskName, err)
				}
			}
		}(task.Name)

		executeAsyncRulesActions([]dataprovider.EventRule{rule}, EventParams{Status: 1, updateStatusFromError: true})
	} else {
		executeAsyncRulesActions([]dataprovider.EventRule{rule}, EventParams{Status: 1, updateStatusFromError: true})
	}
	eventManagerLog(logger.LevelDebug, "execution for scheduled rule %q finished", j.ruleName)
}

// RunOnDemandRule executes actions for a rule with on-demand trigger
func RunOnDemandRule(name string) error {
	eventManagerLog(logger.LevelDebug, "executing on demand rule %q", name)
	rule, err := dataprovider.EventRuleExists(name)
	if err != nil {
		eventManagerLog(logger.LevelDebug, "unable to load rule with name %q", name)
		return util.NewRecordNotFoundError(fmt.Sprintf("rule %q does not exist", name))
	}
	if rule.Trigger != dataprovider.EventTriggerOnDemand {
		eventManagerLog(logger.LevelDebug, "cannot run rule %q as on demand, trigger: %d", name, rule.Trigger)
		return util.NewValidationError(fmt.Sprintf("rule %q is not defined as on-demand", name))
	}
	if rule.Status != 1 {
		eventManagerLog(logger.LevelDebug, "on-demand rule %q is inactive", name)
		return util.NewValidationError(fmt.Sprintf("rule %q is inactive", name))
	}
	if err := rule.CheckActionsConsistency(""); err != nil {
		eventManagerLog(logger.LevelError, "on-demand rule %q has incompatible actions: %v", name, err)
		return util.NewValidationError(fmt.Sprintf("rule %q has incosistent actions", name))
	}
	eventManagerLog(logger.LevelDebug, "on-demand rule %q started", name)
	go executeAsyncRulesActions([]dataprovider.EventRule{rule}, EventParams{Status: 1, updateStatusFromError: true})
	return nil
}

type zipWriterWrapper struct {
	Name    string
	Entries map[string]bool
	Writer  *zip.Writer
}

func eventManagerLog(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, "eventmanager", "", format, v...)
}
