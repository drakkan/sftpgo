package httpd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/util"
)

func getDefenderHosts(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	hosts, err := common.GetDefenderHosts()
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if hosts == nil {
		render.JSON(w, r, make([]dataprovider.DefenderEntry, 0))
		return
	}
	render.JSON(w, r, hosts)
}

func getDefenderHostByID(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	ip, err := getIPFromID(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	host, err := common.GetDefenderHost(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, host)
}

func deleteDefenderHostByID(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	ip, err := getIPFromID(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if !common.DeleteDefenderHost(ip) {
		sendAPIResponse(w, r, nil, "Not found", http.StatusNotFound)
		return
	}

	sendAPIResponse(w, r, nil, "OK", http.StatusOK)
}

func getBanTime(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	ip := r.URL.Query().Get("ip")
	err := validateIPAddress(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	banStatus := make(map[string]*string)

	banTime, err := common.GetDefenderBanTime(ip)
	if err != nil {
		if _, ok := err.(*util.RecordNotFoundError); ok {
			banTime = nil
		} else {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	}
	var banTimeString *string
	if banTime != nil {
		rfc3339String := banTime.UTC().Format(time.RFC3339)
		banTimeString = &rfc3339String
	}

	banStatus["date_time"] = banTimeString
	render.JSON(w, r, banStatus)
}

func getScore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	ip := r.URL.Query().Get("ip")
	err := validateIPAddress(ip)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	score, err := common.GetDefenderScore(ip)
	if err != nil {
		if _, ok := err.(*util.RecordNotFoundError); ok {
			score = 0
		} else {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
	}

	scoreStatus := make(map[string]int)
	scoreStatus["score"] = score

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

	if common.DeleteDefenderHost(ip) {
		sendAPIResponse(w, r, nil, "OK", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not found", http.StatusNotFound)
	}
}

func getIPFromID(r *http.Request) (string, error) {
	decoded, err := hex.DecodeString(getURLParam(r, "id"))
	if err != nil {
		return "", errors.New("invalid host id")
	}
	ip := string(decoded)
	err = validateIPAddress(ip)
	if err != nil {
		return "", err
	}
	return ip, nil
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
