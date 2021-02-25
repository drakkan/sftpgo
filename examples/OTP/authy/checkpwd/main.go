package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type userMapping struct {
	SFTPGoUsername string
	AuthyID        int64
	AuthyAPIKey    string
}

type checkPasswordResponse struct {
	// 0 KO, 1 OK, 2 partial success
	Status int `json:"status"`
	// for status == 2 this is the password that SFTPGo will check against the one stored
	// inside the data provider
	ToVerify string `json:"to_verify"`
}

var (
	mapping []userMapping
)

func init() {
	// this is for demo only, you probably want to get this mapping dynamically, for example using a database query
	mapping = append(mapping, userMapping{
		SFTPGoUsername: "<SFTPGo username>",
		AuthyID:        1234567,
		AuthyAPIKey:    "<your api key>",
	})
}

func printResponse(status int, toVerify string) {
	r := checkPasswordResponse{
		Status:   status,
		ToVerify: toVerify,
	}
	resp, _ := json.Marshal(r)
	fmt.Printf("%v\n", string(resp))
	if status > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func main() {
	// get credentials from env vars
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	password := os.Getenv("SFTPGO_AUTHD_PASSWORD")

	for _, m := range mapping {
		if m.SFTPGoUsername == username {
			// Authy token len is 7, we assume that we have the password followed by the token
			pwdLen := len(password)
			if pwdLen <= 7 {
				printResponse(0, "")
			}
			pwd := password[:pwdLen-7]
			authyToken := password[pwdLen-7:]
			// now verify the authy token and instruct SFTPGo to check the password if the token is OK
			url := fmt.Sprintf("https://api.authy.com/protected/json/verify/%v/%v", authyToken, m.AuthyID)
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				log.Fatal(err)
			}
			req.Header.Set("X-Authy-API-Key", m.AuthyAPIKey)
			httpClient := &http.Client{
				Timeout: 10 * time.Second,
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				printResponse(0, "")
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				// status code 200 is expected
				printResponse(0, "")
			}
			var authyResponse map[string]interface{}
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				printResponse(0, "")
			}
			err = json.Unmarshal(respBody, &authyResponse)
			if err != nil {
				printResponse(0, "")
			}
			if authyResponse["success"].(string) == "true" {
				printResponse(2, pwd)
			}
			printResponse(0, "")
			break
		}
	}

	// no mapping found
	printResponse(0, "")
}
