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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	// EventManager handle the supported event rules actions
	EventManager EventRulesContainer
)

func init() {
	EventManager = EventRulesContainer{
		schedulesMapping: make(map[string][]cron.EntryID),
	}
}

// EventRulesContainer stores event rules by trigger
type EventRulesContainer struct {
	sync.RWMutex
	FsEvents         []EventRule
	ProviderEvents   []EventRule
	Schedules        []EventRule
	schedulesMapping map[string][]cron.EntryID
	lastLoad         int64
}

func (r *EventRulesContainer) getLastLoadTime() int64 {
	return atomic.LoadInt64(&r.lastLoad)
}

func (r *EventRulesContainer) setLastLoadTime(modTime int64) {
	atomic.StoreInt64(&r.lastLoad, modTime)
}

// RemoveRule deletes the rule with the specified name
func (r *EventRulesContainer) RemoveRule(name string) {
	r.Lock()
	defer r.Unlock()

	r.removeRuleInternal(name)
	eventManagerLog(logger.LevelDebug, "event rules updated after delete, fs events: %d, provider events: %d, schedules: %d",
		len(r.FsEvents), len(r.ProviderEvents), len(r.Schedules))
}

func (r *EventRulesContainer) removeRuleInternal(name string) {
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
	for idx := range r.Schedules {
		if r.Schedules[idx].Name == name {
			if schedules, ok := r.schedulesMapping[name]; ok {
				for _, entryID := range schedules {
					eventManagerLog(logger.LevelDebug, "removing scheduled entry id %d for rule %q", entryID, name)
					scheduler.Remove(entryID)
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

func (r *EventRulesContainer) addUpdateRuleInternal(rule EventRule) {
	r.removeRuleInternal(rule.Name)
	if rule.DeletedAt > 0 {
		deletedAt := util.GetTimeFromMsecSinceEpoch(rule.DeletedAt)
		if deletedAt.Add(30 * time.Minute).Before(time.Now()) {
			eventManagerLog(logger.LevelDebug, "removing rule %q deleted at %s", rule.Name, deletedAt)
			go provider.deleteEventRule(rule, false) //nolint:errcheck
		}
		return
	}
	switch rule.Trigger {
	case EventTriggerFsEvent:
		r.FsEvents = append(r.FsEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to fs events", rule.Name)
	case EventTriggerProviderEvent:
		r.ProviderEvents = append(r.ProviderEvents, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to provider events", rule.Name)
	case EventTriggerSchedule:
		r.Schedules = append(r.Schedules, rule)
		eventManagerLog(logger.LevelDebug, "added rule %q to scheduled events", rule.Name)
		for _, schedule := range rule.Conditions.Schedules {
			cronSpec := schedule.getCronSpec()
			job := &cronJob{
				ruleName: ConvertName(rule.Name),
			}
			entryID, err := scheduler.AddJob(cronSpec, job)
			if err != nil {
				eventManagerLog(logger.LevelError, "unable to add scheduled rule %q: %v", rule.Name, err)
			} else {
				r.schedulesMapping[rule.Name] = append(r.schedulesMapping[rule.Name], entryID)
				eventManagerLog(logger.LevelDebug, "scheduled rule %q added, id: %d, active scheduling rules: %d",
					rule.Name, entryID, len(r.schedulesMapping))
			}
		}
	default:
		eventManagerLog(logger.LevelError, "unsupported trigger: %d", rule.Trigger)
	}
}

func (r *EventRulesContainer) loadRules() {
	eventManagerLog(logger.LevelDebug, "loading updated rules")
	modTime := util.GetTimeAsMsSinceEpoch(time.Now())
	rules, err := provider.getRecentlyUpdatedRules(r.getLastLoadTime())
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
	eventManagerLog(logger.LevelDebug, "event rules updated, fs events: %d, provider events: %d, schedules: %d",
		len(r.FsEvents), len(r.ProviderEvents), len(r.Schedules))

	r.setLastLoadTime(modTime)
}

// HasFsRules returns true if there are any rules for filesystem event triggers
func (r *EventRulesContainer) HasFsRules() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.FsEvents) > 0
}

func (r *EventRulesContainer) hasProviderEvents() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.ProviderEvents) > 0
}

// HandleFsEvent executes the rules actions defined for the specified event
func (r *EventRulesContainer) HandleFsEvent(params EventParams) error {
	r.RLock()

	var rulesWithSyncActions, rulesAsync []EventRule
	for _, rule := range r.FsEvents {
		if rule.Conditions.FsEventMatch(params) {
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

	if len(rulesAsync) > 0 {
		go executeAsyncActions(rulesAsync, params)
	}

	if len(rulesWithSyncActions) > 0 {
		return executeSyncActions(rulesWithSyncActions, params)
	}
	return nil
}

func (r *EventRulesContainer) handleProviderEvent(params EventParams) {
	r.RLock()
	defer r.RUnlock()

	var rules []EventRule
	for _, rule := range r.ProviderEvents {
		if rule.Conditions.ProviderEventMatch(params) {
			rules = append(rules, rule)
		}
	}

	go executeAsyncActions(rules, params)
}

// EventParams defines the supported event parameters
type EventParams struct {
	Name              string
	Event             string
	Status            int
	VirtualPath       string
	FsPath            string
	VirtualTargetPath string
	FsTargetPath      string
	ObjectName        string
	ObjectType        string
	FileSize          int64
	Protocol          string
	IP                string
	Timestamp         int64
	Object            plugin.Renderer
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
	}
	if addObjectData {
		data, err := p.Object.RenderAsJSON(p.Event != operationDelete)
		if err == nil {
			replacements = append(replacements, "{{ObjectData}}", string(data))
		}
	}
	return replacements
}

func replaceWithReplacer(input string, replacer *strings.Replacer) string {
	if !strings.Contains(input, "{{") {
		return input
	}
	return replacer.Replace(input)
}

// checkConditionPatterns returns false if patterns are defined and no match is found
func checkConditionPatterns(name string, patterns []ConditionPattern) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p.match(name) {
			return true
		}
	}

	return false
}

func executeSyncActions(rules []EventRule, params EventParams) error {
	var errRes error

	for _, rule := range rules {
		var failedActions []string
		for _, action := range rule.Actions {
			if !action.Options.IsFailureAction && action.Options.ExecuteSync {
				startTime := time.Now()
				if err := action.execute(params, rule.Conditions.Options); err != nil {
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
		go executeRuleAsyncActions(rule, params, failedActions)
	}

	return errRes
}

func executeAsyncActions(rules []EventRule, params EventParams) {
	for _, rule := range rules {
		executeRuleAsyncActions(rule, params, nil)
	}
}

func executeRuleAsyncActions(rule EventRule, params EventParams, failedActions []string) {
	for _, action := range rule.Actions {
		if !action.Options.IsFailureAction && !action.Options.ExecuteSync {
			startTime := time.Now()
			if err := action.execute(params, rule.Conditions.Options); err != nil {
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
		if len(failedActions) > 0 {
			// execute failure actions
			for _, action := range rule.Actions {
				if action.Options.IsFailureAction {
					startTime := time.Now()
					if err := action.execute(params, rule.Conditions.Options); err != nil {
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
}

type cronJob struct {
	ruleName string
}

func (j *cronJob) getTask(rule EventRule) (Task, error) {
	if rule.guardFromConcurrentExecution() {
		task, err := provider.getTaskByName(rule.Name)
		if _, ok := err.(*util.RecordNotFoundError); ok {
			eventManagerLog(logger.LevelDebug, "adding task for rule %q", rule.Name)
			task = Task{
				Name:     rule.Name,
				UpdateAt: 0,
				Version:  0,
			}
			err = provider.addTask(rule.Name)
			if err != nil {
				eventManagerLog(logger.LevelWarn, "unable to add task for rule %q: %v", rule.Name, err)
				return task, err
			}
		} else {
			eventManagerLog(logger.LevelWarn, "unable to get task for rule %q: %v", rule.Name, err)
		}
		return task, err
	}

	return Task{}, nil
}

func (j *cronJob) Run() {
	eventManagerLog(logger.LevelDebug, "executing scheduled rule %q", j.ruleName)
	rule, err := provider.eventRuleExists(j.ruleName)
	if err != nil {
		eventManagerLog(logger.LevelError, "unable to load rule with name %q", j.ruleName)
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
		err = provider.updateTask(rule.Name, task.Version)
		if err != nil {
			eventManagerLog(logger.LevelInfo, "unable to update task timestamp for rule %q, skip execution, err: %v",
				rule.Name, err)
			return
		}
		ticker := time.NewTicker(updateInterval)
		done := make(chan bool)

		go func(taskName string) {
			eventManagerLog(logger.LevelDebug, "update task %q timestamp worker started", taskName)
			for {
				select {
				case <-done:
					eventManagerLog(logger.LevelDebug, "update task %q timestamp worker finished", taskName)
					return
				case <-ticker.C:
					err := provider.updateTaskTimestamp(taskName)
					eventManagerLog(logger.LevelInfo, "updated timestamp for task %q, err: %v", taskName, err)
				}
			}
		}(task.Name)

		executeRuleAsyncActions(rule, EventParams{}, nil)

		done <- true
		ticker.Stop()
	} else {
		executeRuleAsyncActions(rule, EventParams{}, nil)
	}
	eventManagerLog(logger.LevelDebug, "execution for scheduled rule %q finished", j.ruleName)
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

func eventManagerLog(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, "eventmanager", "", format, v...)
}
