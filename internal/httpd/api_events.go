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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sftpgo/sdk/plugin/eventsearcher"
	"github.com/sftpgo/sdk/plugin/notifier"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getCommonSearchParamsFromRequest(r *http.Request) (eventsearcher.CommonSearchParams, error) {
	c := eventsearcher.CommonSearchParams{}
	c.Limit = 100

	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			return c, util.NewValidationError(fmt.Sprintf("invalid limit: %v", err))
		}
		if limit < 1 || limit > 1000 {
			return c, util.NewValidationError(fmt.Sprintf("limit is out of the 1-1000 range: %v", limit))
		}
		c.Limit = limit
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order := r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			return c, util.NewValidationError(fmt.Sprintf("invalid order %q", order))
		}
		if order == dataprovider.OrderASC {
			c.Order = 1
		}
	}
	if _, ok := r.URL.Query()["start_timestamp"]; ok {
		ts, err := strconv.ParseInt(r.URL.Query().Get("start_timestamp"), 10, 64)
		if err != nil {
			return c, util.NewValidationError(fmt.Sprintf("invalid start_timestamp: %v", err))
		}
		c.StartTimestamp = ts
	}
	if _, ok := r.URL.Query()["end_timestamp"]; ok {
		ts, err := strconv.ParseInt(r.URL.Query().Get("end_timestamp"), 10, 64)
		if err != nil {
			return c, util.NewValidationError(fmt.Sprintf("invalid end_timestamp: %v", err))
		}
		c.EndTimestamp = ts
	}
	c.Username = r.URL.Query().Get("username")
	c.IP = r.URL.Query().Get("ip")
	c.InstanceIDs = getCommaSeparatedQueryParam(r, "instance_ids")
	c.FromID = r.URL.Query().Get("from_id")

	return c, nil
}

func getFsSearchParamsFromRequest(r *http.Request) (eventsearcher.FsEventSearch, error) {
	var err error
	s := eventsearcher.FsEventSearch{}
	s.CommonSearchParams, err = getCommonSearchParamsFromRequest(r)
	if err != nil {
		return s, err
	}
	s.FsProvider = -1
	if _, ok := r.URL.Query()["fs_provider"]; ok {
		provider := r.URL.Query().Get("fs_provider")
		val, err := strconv.Atoi(provider)
		if err != nil {
			return s, util.NewValidationError(fmt.Sprintf("invalid fs_provider: %v", provider))
		}
		s.FsProvider = val
	}
	s.Actions = getCommaSeparatedQueryParam(r, "actions")
	s.SSHCmd = r.URL.Query().Get("ssh_cmd")
	s.Bucket = r.URL.Query().Get("bucket")
	s.Endpoint = r.URL.Query().Get("endpoint")
	s.Protocols = getCommaSeparatedQueryParam(r, "protocols")
	statuses := getCommaSeparatedQueryParam(r, "statuses")
	for _, status := range statuses {
		val, err := strconv.ParseInt(status, 10, 32)
		if err != nil {
			return s, util.NewValidationError(fmt.Sprintf("invalid status: %v", status))
		}
		s.Statuses = append(s.Statuses, int32(val))
	}

	return s, nil
}

func getProviderSearchParamsFromRequest(r *http.Request) (eventsearcher.ProviderEventSearch, error) {
	var err error
	s := eventsearcher.ProviderEventSearch{}
	s.CommonSearchParams, err = getCommonSearchParamsFromRequest(r)
	if err != nil {
		return s, err
	}
	s.Actions = getCommaSeparatedQueryParam(r, "actions")
	s.ObjectName = r.URL.Query().Get("object_name")
	s.ObjectTypes = getCommaSeparatedQueryParam(r, "object_types")
	return s, nil
}

func getLogSearchParamsFromRequest(r *http.Request) (eventsearcher.LogEventSearch, error) {
	var err error
	s := eventsearcher.LogEventSearch{}
	s.CommonSearchParams, err = getCommonSearchParamsFromRequest(r)
	if err != nil {
		return s, err
	}
	s.Protocols = getCommaSeparatedQueryParam(r, "protocols")
	events := getCommaSeparatedQueryParam(r, "events")
	for _, ev := range events {
		evType, err := strconv.ParseInt(ev, 10, 32)
		if err == nil {
			s.Events = append(s.Events, int32(evType))
		}
	}

	return s, nil
}

func searchFsEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	filters, err := getFsSearchParamsFromRequest(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	filters.Role = getRoleFilterForEventSearch(r, claims.Role)

	if getBoolQueryParam(r, "csv_export") {
		filters.Limit = 100
		if err := exportFsEvents(w, &filters); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}

	data, err := plugin.Handler.SearchFsEvents(&filters)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func searchProviderEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	var filters eventsearcher.ProviderEventSearch
	if filters, err = getProviderSearchParamsFromRequest(r); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	filters.Role = getRoleFilterForEventSearch(r, claims.Role)
	filters.OmitObjectData = getBoolQueryParam(r, "omit_object_data")

	if getBoolQueryParam(r, "csv_export") {
		filters.Limit = 100
		filters.OmitObjectData = true
		if err := exportProviderEvents(w, &filters); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}

	data, err := plugin.Handler.SearchProviderEvents(&filters)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func searchLogEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	var filters eventsearcher.LogEventSearch
	if filters, err = getLogSearchParamsFromRequest(r); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	filters.Role = getRoleFilterForEventSearch(r, claims.Role)

	if getBoolQueryParam(r, "csv_export") {
		filters.Limit = 100
		if err := exportLogEvents(w, &filters); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}

	data, err := plugin.Handler.SearchLogEvents(&filters)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func exportFsEvents(w http.ResponseWriter, filters *eventsearcher.FsEventSearch) error {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=fslogs-%s.csv", time.Now().Format("2006-01-02T15-04-05")))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Accept-Ranges", "none")
	w.WriteHeader(http.StatusOK)

	csvWriter := csv.NewWriter(w)
	ev := fsEvent{}
	err := csvWriter.Write(ev.getCSVHeader())
	if err != nil {
		return err
	}
	results := make([]fsEvent, 0, filters.Limit)
	for {
		data, err := plugin.Handler.SearchFsEvents(filters)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &results); err != nil {
			return err
		}
		for _, event := range results {
			if err := csvWriter.Write(event.getCSVData()); err != nil {
				return err
			}
		}
		if len(results) == 0 || len(results) < filters.Limit {
			break
		}
		filters.StartTimestamp = results[len(results)-1].Timestamp
		filters.FromID = results[len(results)-1].ID
		results = nil
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func exportProviderEvents(w http.ResponseWriter, filters *eventsearcher.ProviderEventSearch) error {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=providerlogs-%s.csv", time.Now().Format("2006-01-02T15-04-05")))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Accept-Ranges", "none")
	w.WriteHeader(http.StatusOK)

	ev := providerEvent{}
	csvWriter := csv.NewWriter(w)
	err := csvWriter.Write(ev.getCSVHeader())
	if err != nil {
		return err
	}
	results := make([]providerEvent, 0, filters.Limit)
	for {
		data, err := plugin.Handler.SearchProviderEvents(filters)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &results); err != nil {
			return err
		}
		for _, event := range results {
			if err := csvWriter.Write(event.getCSVData()); err != nil {
				return err
			}
		}
		if len(results) < filters.Limit || len(results) == 0 {
			break
		}
		filters.FromID = results[len(results)-1].ID
		filters.StartTimestamp = results[len(results)-1].Timestamp
		results = nil
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func exportLogEvents(w http.ResponseWriter, filters *eventsearcher.LogEventSearch) error {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=logs-%s.csv", time.Now().Format("2006-01-02T15-04-05")))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Accept-Ranges", "none")
	w.WriteHeader(http.StatusOK)

	ev := logEvent{}
	csvWriter := csv.NewWriter(w)
	err := csvWriter.Write(ev.getCSVHeader())
	if err != nil {
		return err
	}
	results := make([]logEvent, 0, filters.Limit)
	for {
		data, err := plugin.Handler.SearchLogEvents(filters)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &results); err != nil {
			return err
		}
		for _, event := range results {
			if err := csvWriter.Write(event.getCSVData()); err != nil {
				return err
			}
		}
		if len(results) == 0 || len(results) < filters.Limit {
			break
		}
		filters.StartTimestamp = results[len(results)-1].Timestamp
		filters.FromID = results[len(results)-1].ID
		results = nil
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func getRoleFilterForEventSearch(r *http.Request, defaultValue string) string {
	if defaultValue != "" {
		return defaultValue
	}
	return r.URL.Query().Get("role")
}

type fsEvent struct {
	ID                string `json:"id"`
	Timestamp         int64  `json:"timestamp"`
	Action            string `json:"action"`
	Username          string `json:"username"`
	FsPath            string `json:"fs_path"`
	FsTargetPath      string `json:"fs_target_path,omitempty"`
	VirtualPath       string `json:"virtual_path"`
	VirtualTargetPath string `json:"virtual_target_path,omitempty"`
	SSHCmd            string `json:"ssh_cmd,omitempty"`
	FileSize          int64  `json:"file_size,omitempty"`
	Elapsed           int64  `json:"elapsed,omitempty"`
	Status            int    `json:"status"`
	Protocol          string `json:"protocol"`
	IP                string `json:"ip,omitempty"`
	SessionID         string `json:"session_id"`
	FsProvider        int    `json:"fs_provider"`
	Bucket            string `json:"bucket,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	OpenFlags         int    `json:"open_flags,omitempty"`
	Role              string `json:"role,omitempty"`
	InstanceID        string `json:"instance_id,omitempty"`
}

func (e *fsEvent) getCSVHeader() []string {
	return []string{"Time", "Action", "Path", "Size", "Elapsed", "Status", "User", "Protocol",
		"IP", "SSH command"}
}

func (e *fsEvent) getCSVData() []string {
	timestamp := time.Unix(0, e.Timestamp).UTC()
	var pathInfo strings.Builder
	pathInfo.Write([]byte(e.VirtualPath))
	if e.VirtualTargetPath != "" {
		pathInfo.WriteString(" => ")
		pathInfo.WriteString(e.VirtualTargetPath)
	}
	var status string
	switch e.Status {
	case 1:
		status = "OK"
	case 2:
		status = "KO"
	case 3:
		status = "Quota exceeded"
	}
	var fileSize string
	if e.FileSize > 0 {
		fileSize = util.ByteCountIEC(e.FileSize)
	}
	var elapsed string
	if e.Elapsed > 0 {
		elapsed = (time.Duration(e.Elapsed) * time.Millisecond).String()
	}
	return []string{timestamp.Format(time.RFC3339Nano), e.Action, pathInfo.String(),
		fileSize, elapsed, status, e.Username, e.Protocol, e.IP, e.SSHCmd}
}

type providerEvent struct {
	ID         string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Action     string `json:"action"`
	Username   string `json:"username"`
	IP         string `json:"ip,omitempty"`
	ObjectType string `json:"object_type"`
	ObjectName string `json:"object_name"`
	ObjectData []byte `json:"object_data"`
	Role       string `json:"role,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
}

func (e *providerEvent) getCSVHeader() []string {
	return []string{"Time", "Action", "Object Type", "Object Name", "User", "IP"}
}

func (e *providerEvent) getCSVData() []string {
	timestamp := time.Unix(0, e.Timestamp).UTC()
	return []string{timestamp.Format(time.RFC3339Nano), e.Action, e.ObjectType, e.ObjectName,
		e.Username, e.IP}
}

type logEvent struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Event     int    `json:"event"`
	Protocol  string `json:"protocol"`
	Username  string `json:"username,omitempty"`
	IP        string `json:"ip,omitempty"`
	Message   string `json:"message,omitempty"`
	Role      string `json:"role,omitempty"`
}

func (e *logEvent) getCSVHeader() []string {
	return []string{"Time", "Event", "Protocol", "User", "IP", "Message"}
}

func (e *logEvent) getCSVData() []string {
	timestamp := time.Unix(0, e.Timestamp).UTC()
	return []string{timestamp.Format(time.RFC3339Nano), getLogEventString(notifier.LogEventType(e.Event)),
		e.Protocol, e.Username, e.IP, e.Message}
}

func getLogEventString(event notifier.LogEventType) string {
	switch event {
	case notifier.LogEventTypeLoginFailed:
		return "Login failed"
	case notifier.LogEventTypeLoginNoUser:
		return "Login with non-existent user"
	case notifier.LogEventTypeNoLoginTried:
		return "No login tried"
	case notifier.LogEventTypeNotNegotiated:
		return "Algorithm negotiation failed"
	default:
		return ""
	}
}
