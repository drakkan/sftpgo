package httpd

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/sdk/plugin"
	"github.com/drakkan/sftpgo/v2/util"
)

type commonEventSearchParams struct {
	StartTimestamp int64
	EndTimestamp   int64
	Actions        []string
	Username       string
	IP             string
	InstanceIDs    []string
	ExcludeIDs     []string
	Limit          int
	Order          int
}

func (c *commonEventSearchParams) fromRequest(r *http.Request) error {
	c.Limit = 100

	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("invalid limit: %v", err))
		}
		if limit < 1 || limit > 1000 {
			return util.NewValidationError(fmt.Sprintf("limit is out of the 1-1000 range: %v", limit))
		}
		c.Limit = limit
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order := r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			return util.NewValidationError(fmt.Sprintf("invalid order %#v", order))
		}
		if order == dataprovider.OrderASC {
			c.Order = 1
		}
	}
	if _, ok := r.URL.Query()["start_timestamp"]; ok {
		ts, err := strconv.ParseInt(r.URL.Query().Get("start_timestamp"), 10, 64)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("invalid start_timestamp: %v", err))
		}
		c.StartTimestamp = ts
	}
	if _, ok := r.URL.Query()["end_timestamp"]; ok {
		ts, err := strconv.ParseInt(r.URL.Query().Get("end_timestamp"), 10, 64)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("invalid end_timestamp: %v", err))
		}
		c.EndTimestamp = ts
	}
	c.Actions = getCommaSeparatedQueryParam(r, "actions")
	c.Username = r.URL.Query().Get("username")
	c.IP = r.URL.Query().Get("ip")
	c.InstanceIDs = getCommaSeparatedQueryParam(r, "instance_ids")
	c.ExcludeIDs = getCommaSeparatedQueryParam(r, "exclude_ids")

	return nil
}

type fsEventSearchParams struct {
	commonEventSearchParams
	SSHCmd    string
	Protocols []string
	Statuses  []int32
}

func (s *fsEventSearchParams) fromRequest(r *http.Request) error {
	if err := s.commonEventSearchParams.fromRequest(r); err != nil {
		return err
	}
	s.IP = r.URL.Query().Get("ip")
	s.SSHCmd = r.URL.Query().Get("ssh_cmd")
	s.Protocols = getCommaSeparatedQueryParam(r, "protocols")
	statuses := getCommaSeparatedQueryParam(r, "statuses")
	for _, status := range statuses {
		val, err := strconv.Atoi(status)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("invalid status: %v", status))
		}
		s.Statuses = append(s.Statuses, int32(val))
	}

	return nil
}

type providerEventSearchParams struct {
	commonEventSearchParams
	ObjectName  string
	ObjectTypes []string
}

func (s *providerEventSearchParams) fromRequest(r *http.Request) error {
	if err := s.commonEventSearchParams.fromRequest(r); err != nil {
		return err
	}
	s.ObjectName = r.URL.Query().Get("object_name")
	s.ObjectTypes = getCommaSeparatedQueryParam(r, "object_types")

	return nil
}

func searchFsEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	params := fsEventSearchParams{}
	err := params.fromRequest(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	data, _, _, err := plugin.Handler.SearchFsEvents(params.StartTimestamp, params.EndTimestamp, params.Username,
		params.IP, params.SSHCmd, params.Actions, params.Protocols, params.InstanceIDs, params.ExcludeIDs,
		params.Statuses, params.Limit, params.Order)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data) //nolint:errcheck
}

func searchProviderEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	params := providerEventSearchParams{}
	err := params.fromRequest(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	data, _, _, err := plugin.Handler.SearchProviderEvents(params.StartTimestamp, params.EndTimestamp, params.Username,
		params.IP, params.ObjectName, params.Limit, params.Order, params.Actions, params.ObjectTypes, params.InstanceIDs,
		params.ExcludeIDs)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data) //nolint:errcheck
}
