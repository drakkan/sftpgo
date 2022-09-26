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

package common

import (
	"bytes"
	"context"
	"encoding/csv"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zip"
	"github.com/robfig/cron/v3"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	mail "github.com/xhit/go-simple-mail/v2"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	ipBlockedEventName = "IP Blocked"
	maxAttachmentsSize = int64(10 * 1024 * 1024)
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
		func(operation, executor, ip, objectType, objectName string, object plugin.Renderer) {
			eventManager.handleProviderEvent(EventParams{
				Name:       executor,
				ObjectName: objectName,
				Event:      operation,
				Status:     1,
				ObjectType: objectType,
				IP:         ip,
				Timestamp:  time.Now().UnixNano(),
				Object:     object,
			})
		})
}

// HandleCertificateEvent checks and executes action rules for certificate events
func HandleCertificateEvent(params EventParams) {
	eventManager.handleCertificateEvent(params)
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
	schedulesMapping  map[string][]cron.EntryID
	concurrencyGuard  chan struct{}
}

func (r *eventRulesContainer) addAsyncTask() {
	r.concurrencyGuard <- struct{}{}
}

func (r *eventRulesContainer) removeAsyncTask() {
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
	eventManagerLog(logger.LevelDebug, "event rules updated, fs events: %d, provider events: %d, schedules: %d, ip blocked events: %d, certificate events: %d",
		len(r.FsEvents), len(r.ProviderEvents), len(r.Schedules), len(r.IPBlockedEvents), len(r.CertificateEvents))

	r.setLastLoadTime(modTime)
}

func (r *eventRulesContainer) checkProviderEventMatch(conditions dataprovider.EventConditions, params EventParams) bool {
	if !util.Contains(conditions.ProviderEvents, params.Event) {
		return false
	}
	if !checkEventConditionPatterns(params.Name, conditions.Options.Names) {
		return false
	}
	if len(conditions.Options.ProviderObjects) > 0 && !util.Contains(conditions.Options.ProviderObjects, params.ObjectType) {
		return false
	}
	return true
}

func (r *eventRulesContainer) checkFsEventMatch(conditions dataprovider.EventConditions, params EventParams) bool {
	if !util.Contains(conditions.FsEvents, params.Event) {
		return false
	}
	if !checkEventConditionPatterns(params.Name, conditions.Options.Names) {
		return false
	}
	if !checkEventGroupConditionPatters(params.Groups, conditions.Options.GroupNames) {
		return false
	}
	if !checkEventConditionPatterns(params.VirtualPath, conditions.Options.FsPaths) {
		if !checkEventConditionPatterns(params.ObjectName, conditions.Options.FsPaths) {
			return false
		}
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

// handleFsEvent executes the rules actions defined for the specified event
func (r *eventRulesContainer) handleFsEvent(params EventParams) error {
	if params.Protocol == protocolEventAction {
		return nil
	}
	r.RLock()

	var rulesWithSyncActions, rulesAsync []dataprovider.EventRule
	for _, rule := range r.FsEvents {
		if r.checkFsEventMatch(rule.Conditions, params) {
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
	if len(rulesAsync) > 0 {
		go executeAsyncRulesActions(rulesAsync, params)
	}

	if len(rulesWithSyncActions) > 0 {
		return executeSyncRulesActions(rulesWithSyncActions, params)
	}
	return nil
}

// username is populated for user objects
func (r *eventRulesContainer) handleProviderEvent(params EventParams) {
	r.RLock()
	defer r.RUnlock()

	var rules []dataprovider.EventRule
	for _, rule := range r.ProviderEvents {
		if r.checkProviderEventMatch(rule.Conditions, params) {
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
	ObjectType            string
	FileSize              int64
	Protocol              string
	IP                    string
	Timestamp             int64
	Object                plugin.Renderer
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

	return &params
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
		users, err := dataprovider.DumpUsers()
		if err != nil {
			eventManagerLog(logger.LevelError, "unable to get users: %+v", err)
			return users, errors.New("unable to get users")
		}
		return users, nil
	}
	user, err := p.getUserFromSender()
	if err != nil {
		return nil, err
	}
	return []dataprovider.User{user}, nil
}

func (p *EventParams) getUserFromSender() (dataprovider.User, error) {
	user, err := dataprovider.UserExists(p.sender)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to get user %q: %+v", p.sender, err)
		return user, fmt.Errorf("error getting user %q", p.sender)
	}
	return user, nil
}

func (p *EventParams) getFolders() ([]vfs.BaseVirtualFolder, error) {
	if p.sender == "" {
		return dataprovider.DumpFolders()
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
	wr := zip.NewWriter(&b)
	for _, check := range p.retentionChecks {
		if size := int64(len(b.Bytes())); size > maxAttachmentsSize {
			eventManagerLog(logger.LevelError, "unable to get retention report, size too large: %s", util.ByteCountIEC(size))
			return nil, fmt.Errorf("unable to get retention report, size too large: %s", util.ByteCountIEC(size))
		}
		data, err := getCSVRetentionReport(check.Results)
		if err != nil {
			return nil, fmt.Errorf("unable to get CSV report: %w", err)
		}
		fh := &zip.FileHeader{
			Name:     fmt.Sprintf("%s-%s.csv", check.ActionName, check.Username),
			Method:   zip.Deflate,
			Modified: time.Now().UTC(),
		}
		f, err := wr.CreateHeader(fh)
		if err != nil {
			return nil, fmt.Errorf("unable to create zip header for file %q: %w", fh.Name, err)
		}
		_, err = io.Copy(f, bytes.NewBuffer(data))
		if err != nil {
			return nil, fmt.Errorf("unable to write content to zip file %q: %w", fh.Name, err)
		}
	}
	if err := wr.Close(); err != nil {
		return nil, fmt.Errorf("unable to close zip writer: %w", err)
	}
	return b.Bytes(), nil
}

func (p *EventParams) getRetentionReportsAsMailAttachment() (mail.File, error) {
	var result mail.File
	data, err := p.getCompressedDataRetentionReport()
	if err != nil {
		return result, err
	}
	result.Name = "retention-reports.zip"
	result.Data = data
	return result, nil
}

func (p *EventParams) getStringReplacements(addObjectData bool) []string {
	replacements := []string{
		"{{Name}}", p.Name,
		"{{Event}}", p.Event,
		"{{Status}}", fmt.Sprintf("%d", p.Status),
		"{{VirtualPath}}", p.VirtualPath,
		"{{FsPath}}", p.FsPath,
		"{{VirtualTargetPath}}", p.VirtualTargetPath,
		"{{FsTargetPath}}", p.FsTargetPath,
		"{{ObjectName}}", p.ObjectName,
		"{{ObjectType}}", p.ObjectType,
		"{{FileSize}}", fmt.Sprintf("%d", p.FileSize),
		"{{Protocol}}", p.Protocol,
		"{{IP}}", p.IP,
		"{{Timestamp}}", fmt.Sprintf("%d", p.Timestamp),
		"{{StatusString}}", p.getStatusString(),
	}
	if len(p.errors) > 0 {
		replacements = append(replacements, "{{ErrorString}}", strings.Join(p.errors, ", "))
	} else {
		replacements = append(replacements, "{{ErrorString}}", "")
	}
	replacements = append(replacements, "{{ObjectData}}", "")
	if addObjectData {
		data, err := p.Object.RenderAsJSON(p.Event != operationDelete)
		if err == nil {
			replacements[len(replacements)-1] = string(data)
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

func getFileReader(conn *BaseConnection, virtualPath string) (io.ReadCloser, func(), error) {
	fs, fsPath, err := conn.GetFsAndResolvedPath(virtualPath)
	if err != nil {
		return nil, nil, err
	}
	f, r, cancelFn, err := fs.Open(fsPath, 0)
	if err != nil {
		return nil, nil, err
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

func getFileContent(conn *BaseConnection, virtualPath string, expectedSize int) ([]byte, error) {
	reader, cancelFn, err := getFileReader(conn, virtualPath)
	if err != nil {
		return nil, err
	}

	defer cancelFn()
	defer reader.Close()

	data := make([]byte, expectedSize)
	_, err = io.ReadFull(reader, data)
	return data, err
}

func getMailAttachments(user dataprovider.User, attachments []string, replacer *strings.Replacer) ([]mail.File, error) {
	var files []mail.File
	user, err := getUserForEventAction(user)
	if err != nil {
		return nil, err
	}
	connectionID := fmt.Sprintf("%s_%s", protocolEventAction, xid.New().String())
	err = user.CheckFsRoot(connectionID)
	defer user.CloseFs() //nolint:errcheck
	if err != nil {
		return nil, fmt.Errorf("error getting email attachments, unable to check root fs for user %q: %w", user.Username, err)
	}
	conn := NewBaseConnection(connectionID, protocolEventAction, "", "", user)
	totalSize := int64(0)
	for _, virtualPath := range attachments {
		virtualPath = util.CleanPath(replaceWithReplacer(virtualPath, replacer))
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
		data, err := getFileContent(conn, virtualPath, int(info.Size()))
		if err != nil {
			return nil, fmt.Errorf("unable to get content for file %q, user %q: %w", virtualPath, conn.User.Username, err)
		}
		files = append(files, mail.File{
			Name: path.Base(virtualPath),
			Data: data,
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

// checkConditionPatterns returns false if patterns are defined and no match is found
func checkEventConditionPatterns(name string, patterns []dataprovider.ConditionPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if checkEventConditionPattern(p, name) {
			return true
		}
	}

	return false
}

func checkEventGroupConditionPatters(groups []sdk.GroupMapping, patterns []dataprovider.ConditionPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, group := range groups {
		for _, p := range patterns {
			if checkEventConditionPattern(p, group.Name) {
				return true
			}
		}
	}

	return false
}

func getHTTPRuleActionEndpoint(c dataprovider.EventActionHTTPConfig, replacer *strings.Replacer) (string, error) {
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

func writeHTTPPart(m *multipart.Writer, part dataprovider.HTTPPart, h textproto.MIMEHeader,
	conn *BaseConnection, replacer *strings.Replacer, params *EventParams,
) error {
	partWriter, err := m.CreatePart(h)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to create part %q, err: %v", part.Name, err)
		return err
	}
	if part.Body != "" {
		_, err = partWriter.Write([]byte(replaceWithReplacer(part.Body, replacer)))
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

func getHTTPRuleActionBody(c dataprovider.EventActionHTTPConfig, replacer *strings.Replacer,
	cancel context.CancelFunc, user dataprovider.User, params *EventParams,
) (io.ReadCloser, string, error) {
	var body io.ReadCloser
	if c.Method == http.MethodGet {
		return body, "", nil
	}
	if c.Body != "" {
		if c.Body == dataprovider.RetentionReportPlaceHolder {
			data, err := params.getCompressedDataRetentionReport()
			if err != nil {
				return body, "", err
			}
			return io.NopCloser(bytes.NewBuffer(data)), "", nil
		}
		return io.NopCloser(bytes.NewBufferString(replaceWithReplacer(c.Body, replacer))), "", nil
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
							multipartQuoteEscaper.Replace(part.Name), multipartQuoteEscaper.Replace(path.Base(part.Filepath))))
					contentType := mime.TypeByExtension(path.Ext(part.Filepath))
					if contentType == "" {
						contentType = "application/octet-stream"
					}
					h.Set("Content-Type", contentType)
				}
				for _, keyVal := range part.Headers {
					h.Set(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
				}
				if err := writeHTTPPart(m, part, h, conn, replacer, params); err != nil {
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

func executeHTTPRuleAction(c dataprovider.EventActionHTTPConfig, params *EventParams) error {
	if err := c.TryDecryptPassword(); err != nil {
		return err
	}
	addObjectData := false
	if params.Object != nil {
		addObjectData = c.HasObjectData()
	}

	replacements := params.getStringReplacements(addObjectData)
	replacer := strings.NewReplacer(replacements...)
	endpoint, err := getHTTPRuleActionEndpoint(c, replacer)
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
	body, contentType, err := getHTTPRuleActionBody(c, replacer, cancel, user, params)
	if err != nil {
		return err
	}
	if body != nil {
		defer body.Close()
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, endpoint, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Username != "" {
		req.SetBasicAuth(replaceWithReplacer(c.Username, replacer), c.Password.GetPayload())
	}
	for _, keyVal := range c.Headers {
		req.Header.Set(keyVal.Key, replaceWithReplacer(keyVal.Value, replacer))
	}
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
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func executeCommandRuleAction(c dataprovider.EventActionCommandConfig, params *EventParams) error {
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
	args := make([]string, 0, len(c.Args))
	for _, arg := range c.Args {
		args = append(args, replaceWithReplacer(arg, replacer))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Cmd, args...)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)

	startTime := time.Now()
	err := cmd.Run()

	eventManagerLog(logger.LevelDebug, "executed command %q, elapsed: %s, error: %v",
		c.Cmd, time.Since(startTime), err)

	return err
}

func executeEmailRuleAction(c dataprovider.EventActionEmailConfig, params *EventParams) error {
	addObjectData := false
	if params.Object != nil {
		if strings.Contains(c.Body, "{{ObjectData}}") {
			addObjectData = true
		}
	}
	replacements := params.getStringReplacements(addObjectData)
	replacer := strings.NewReplacer(replacements...)
	body := replaceWithReplacer(c.Body, replacer)
	subject := replaceWithReplacer(c.Subject, replacer)
	startTime := time.Now()
	var files []mail.File
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
		res, err := getMailAttachments(user, fileAttachments, replacer)
		if err != nil {
			return err
		}
		files = append(files, res...)
	}
	err := smtp.SendEmail(c.Recipients, subject, body, smtp.EmailContentTypeTextPlain, files...)
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
	user.Filters.DisableFsChecks = false
	user.Filters.FilePatterns = nil
	for k := range user.Permissions {
		user.Permissions[k] = []string{dataprovider.PermAny}
	}
	return user, nil
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
	for _, item := range deletes {
		item = util.CleanPath(replaceWithReplacer(item, replacer))
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
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping fs delete for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping fs delete for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeDeleteFsActionForUser(deletes, replacer, user); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs delete failed for users: %+v", failures)
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
	for _, item := range dirs {
		item = util.CleanPath(replaceWithReplacer(item, replacer))
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
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping fs mkdir for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping fs mkdir for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeMkDirsFsActionForUser(dirs, replacer, user); err != nil {
			failures = append(failures, user.Username)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs mkdir failed for users: %+v", failures)
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
		if err = conn.Rename(source, target); err != nil {
			return fmt.Errorf("unable to rename %q->%q, user %q: %w", source, target, user.Username, err)
		}
		eventManagerLog(logger.LevelDebug, "rename %q->%q ok, user %q", source, target, user.Username)
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
	for _, item := range exist {
		item = util.CleanPath(replaceWithReplacer(item, replacer))
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
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping fs rename for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping fs rename for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeRenameFsActionForUser(renames, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs rename failed for users: %+v", failures)
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no rename executed")
		return errors.New("no rename executed")
	}
	return nil
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
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping fs exist for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping fs exist for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeExistFsActionForUser(exist, replacer, user); err != nil {
			failures = append(failures, user.Username)
			params.AddError(err)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fs existence check failed for users: %+v", failures)
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no existence check executed")
		return errors.New("no existence check executed")
	}
	return nil
}

func executeFsRuleAction(c dataprovider.EventActionFilesystemConfig, conditions dataprovider.ConditionOptions,
	params *EventParams,
) error {
	addObjectData := false
	replacements := params.getStringReplacements(addObjectData)
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
	default:
		return fmt.Errorf("unsupported filesystem action %d", c.Type)
	}
}

func executeQuotaResetForUser(user dataprovider.User) error {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		eventManagerLog(logger.LevelDebug, "skipping scheduled quota reset for user %s, cannot apply group settings: %v",
			user.Username, err)
		return err
	}
	if !QuotaScans.AddUserQuotaScan(user.Username) {
		eventManagerLog(logger.LevelError, "another quota scan is already in progress for user %q", user.Username)
		return fmt.Errorf("another quota scan is in progress for user %q", user.Username)
	}
	defer QuotaScans.RemoveUserQuotaScan(user.Username)

	numFiles, size, err := user.ScanQuota()
	if err != nil {
		eventManagerLog(logger.LevelError, "error scanning quota for user %q: %v", user.Username, err)
		return fmt.Errorf("error scanning quota for user %q: %w", user.Username, err)
	}
	err = dataprovider.UpdateUserQuota(&user, numFiles, size, true)
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
	var failedResets []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping quota reset for user %q, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping quota reset for user %q, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeQuotaResetForUser(user); err != nil {
			params.AddError(err)
			failedResets = append(failedResets, user.Username)
			continue
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("quota reset failed for users: %+v", failedResets)
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
	var failedResets []string
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
			failedResets = append(failedResets, folder.Name)
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
			failedResets = append(failedResets, folder.Name)
			continue
		}
		err = dataprovider.UpdateVirtualFolderQuota(&folder, numFiles, size, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating quota for folder %q: %v", folder.Name, err)
			params.AddError(fmt.Errorf("error updating quota for folder %q: %w", folder.Name, err))
			failedResets = append(failedResets, folder.Name)
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("quota reset failed for folders: %+v", failedResets)
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
	var failedResets []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled transfer quota reset for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled transfer quota reset for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		err = dataprovider.UpdateUserTransferQuota(&user, 0, 0, true)
		if err != nil {
			eventManagerLog(logger.LevelError, "error updating transfer quota for user %q: %v", user.Username, err)
			params.AddError(fmt.Errorf("error updating transfer quota for user %q: %w", user.Username, err))
			failedResets = append(failedResets, user.Username)
		}
	}
	if len(failedResets) > 0 {
		return fmt.Errorf("transfer quota reset failed for users: %+v", failedResets)
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
		eventManagerLog(logger.LevelDebug, "skipping scheduled retention check for user %s, cannot apply group settings: %v",
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
	var failedChecks []string
	executed := 0
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled retention check for user %s, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping scheduled retention check for user %s, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeDataRetentionCheckForUser(user, config.Folders, params, actionName); err != nil {
			failedChecks = append(failedChecks, user.Username)
			params.AddError(err)
			continue
		}
	}
	if len(failedChecks) > 0 {
		return fmt.Errorf("retention check failed for users: %+v", failedChecks)
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no retention check executed")
		return errors.New("no retention check executed")
	}
	return nil
}

func executeMetadataCheckForUser(user dataprovider.User) error {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		eventManagerLog(logger.LevelDebug, "skipping scheduled quota reset for user %s, cannot apply group settings: %v",
			user.Username, err)
		return err
	}
	if !ActiveMetadataChecks.Add(user.Username) {
		eventManagerLog(logger.LevelError, "another metadata check is already in progress for user %q", user.Username)
		return fmt.Errorf("another metadata check is in progress for user %q", user.Username)
	}
	defer ActiveMetadataChecks.Remove(user.Username)

	if err := user.CheckMetadataConsistency(); err != nil {
		eventManagerLog(logger.LevelError, "error checking metadata consistence for user %q: %v", user.Username, err)
		return fmt.Errorf("error checking metadata consistence for user %q: %w", user.Username, err)
	}
	return nil
}

func executeMetadataCheckRuleAction(conditions dataprovider.ConditionOptions, params *EventParams) error {
	users, err := params.getUsers()
	if err != nil {
		return fmt.Errorf("unable to get users: %w", err)
	}
	var failures []string
	var executed int
	for _, user := range users {
		// if sender is set, the conditions have already been evaluated
		if params.sender == "" {
			if !checkEventConditionPatterns(user.Username, conditions.Names) {
				eventManagerLog(logger.LevelDebug, "skipping metadata check for user %q, name conditions don't match",
					user.Username)
				continue
			}
			if !checkEventGroupConditionPatters(user.Groups, conditions.GroupNames) {
				eventManagerLog(logger.LevelDebug, "skipping metadata check for user %q, group name conditions don't match",
					user.Username)
				continue
			}
		}
		executed++
		if err = executeMetadataCheckForUser(user); err != nil {
			params.AddError(err)
			failures = append(failures, user.Username)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("metadata check failed for users: %+v", failures)
	}
	if executed == 0 {
		eventManagerLog(logger.LevelError, "no metadata check executed")
		return errors.New("no metadata check executed")
	}
	return nil
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
		err = dataprovider.ExecuteBackup()
	case dataprovider.ActionTypeUserQuotaReset:
		err = executeUsersQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeFolderQuotaReset:
		err = executeFoldersQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeTransferQuotaReset:
		err = executeTransferQuotaResetRuleAction(conditions, params)
	case dataprovider.ActionTypeDataRetentionCheck:
		err = executeDataRetentionCheckRuleAction(action.Options.RetentionConfig, conditions, params, action.Name)
	case dataprovider.ActionTypeMetadataCheck:
		err = executeMetadataCheckRuleAction(conditions, params)
	case dataprovider.ActionTypeFilesystem:
		err = executeFsRuleAction(action.Options.FsConfig, conditions, params)
	default:
		err = fmt.Errorf("unsupported action type: %d", action.Type)
	}

	if err != nil {
		err = fmt.Errorf("action %q failed: %w", action.Name, err)
	}
	params.AddError(err)
	return err
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

func (j *eventCronJob) getTask(rule dataprovider.EventRule) (dataprovider.Task, error) {
	if rule.GuardFromConcurrentExecution() {
		task, err := dataprovider.GetTaskByName(rule.Name)
		if _, ok := err.(*util.RecordNotFoundError); ok {
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
	if err = rule.CheckActionsConsistency(""); err != nil {
		eventManagerLog(logger.LevelWarn, "scheduled rule %q skipped: %v", rule.Name, err)
		return
	}
	task, err := j.getTask(rule)
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

func eventManagerLog(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, "eventmanager", "", format, v...)
}
