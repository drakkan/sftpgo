package httpd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
)

func getBanTime(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	err := validateIPAddress(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	banStatus := make(map[string]*string)

	banTime := common.GetDefenderBanTime(ip)
	var banTimeString *string
	if banTime != nil {
		rfc3339String := banTime.UTC().Format(time.RFC3339)
		banTimeString = &rfc3339String
	}

	banStatus["date_time"] = banTimeString
	render.JSON(w, r, banStatus)
}

func getScore(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	err := validateIPAddress(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	scoreStatus := make(map[string]int)
	scoreStatus["score"] = common.GetDefenderScore(ip)

	render.JSON(w, r, scoreStatus)
}

func unban(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var postBody map[string]string
	err := render.DecodeJSON(r.Body, &postBody)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	ip := postBody["ip"]
	err = validateIPAddress(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	if common.Unban(ip) {
		sendAPIResponse(w, r, nil, "OK", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not found", http.StatusNotFound)
	}
}

func validateIPAddress(ip string) error {
	if ip == "" {
		return errors.New("ip address is required")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("ip address %#v is not valid", ip)
	}
	return nil
}
