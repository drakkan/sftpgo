package httpd

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/sftpgo/sdk/plugin/eventsearcher"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/util"
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
			return c, util.NewValidationError(fmt.Sprintf("invalid order %#v", order))
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
	c.Actions = getCommaSeparatedQueryParam(r, "actions")
	c.Username = r.URL.Query().Get("username")
	c.IP = r.URL.Query().Get("ip")
	c.InstanceIDs = getCommaSeparatedQueryParam(r, "instance_ids")
	c.ExcludeIDs = getCommaSeparatedQueryParam(r, "exclude_ids")

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
	s.IP = r.URL.Query().Get("ip")
	s.SSHCmd = r.URL.Query().Get("ssh_cmd")
	s.Bucket = r.URL.Query().Get("bucket")
	s.Endpoint = r.URL.Query().Get("endpoint")
	s.Protocols = getCommaSeparatedQueryParam(r, "protocols")
	statuses := getCommaSeparatedQueryParam(r, "statuses")
	for _, status := range statuses {
		val, err := strconv.Atoi(status)
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
	s.ObjectName = r.URL.Query().Get("object_name")
	s.ObjectTypes = getCommaSeparatedQueryParam(r, "object_types")
	return s, nil
}

func searchFsEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	filters, err := getFsSearchParamsFromRequest(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	data, _, _, err := plugin.Handler.SearchFsEvents(&filters)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data) //nolint:errcheck
}

func searchProviderEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	filters, err := getProviderSearchParamsFromRequest(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	data, _, _, err := plugin.Handler.SearchProviderEvents(&filters)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data) //nolint:errcheck
}
