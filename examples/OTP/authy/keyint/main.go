package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type userMapping struct {
	SFTPGoUsername string
	AuthyID        int64
	AuthyAPIKey    string
}

type keyboardAuthHookResponse struct {
	Instruction string   `json:"instruction,omitempty"`
	Questions   []string `json:"questions,omitempty"`
	Echos       []bool   `json:"echos,omitempty"`
	AuthResult  int      `json:"auth_result"`
	CheckPwd    int      `json:"check_password,omitempty"`
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

func printAuthResponse(result int) {
	resp, _ := json.Marshal(keyboardAuthHookResponse{
		AuthResult: result,
	})
	fmt.Printf("%v\n", string(resp))
	if result == 1 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func main() {
	// get credentials from env vars
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	var userMap userMapping
	for _, m := range mapping {
		if m.SFTPGoUsername == username {
			userMap = m
			break
		}
	}

	if userMap.SFTPGoUsername != username {
		// no mapping found
		os.Exit(1)
	}

	checkPwdQuestion := keyboardAuthHookResponse{
		Instruction: "This is a sample keyboard authentication program that ask for your password + Authy token",
		Questions:   []string{"Your password: "},
		Echos:       []bool{false},
		CheckPwd:    1,
		AuthResult:  0,
	}

	q, _ := json.Marshal(checkPwdQuestion)
	fmt.Printf("%v\n", string(q))

	// in a real world app you probably want to use a read timeout
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if scanner.Err() != nil {
		printAuthResponse(-1)
	}
	response := scanner.Text()
	if response != "OK" {
		printAuthResponse(-1)
	}

	checkTokenQuestion := keyboardAuthHookResponse{
		Instruction: "",
		Questions:   []string{"Authy token: "},
		Echos:       []bool{false},
		CheckPwd:    0,
		AuthResult:  0,
	}

	q, _ = json.Marshal(checkTokenQuestion)
	fmt.Printf("%v\n", string(q))
	scanner.Scan()
	if scanner.Err() != nil {
		printAuthResponse(-1)
	}
	authyToken := scanner.Text()

	url := fmt.Sprintf("https://api.authy.com/protected/json/verify/%v/%v", authyToken, userMap.AuthyID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		printAuthResponse(-1)
	}
	req.Header.Set("X-Authy-API-Key", userMap.AuthyAPIKey)
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		printAuthResponse(-1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// status code 200 is expected
		printAuthResponse(-1)
	}
	var authyResponse map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		printAuthResponse(-1)
	}
	err = json.Unmarshal(respBody, &authyResponse)
	if err != nil {
		printAuthResponse(-1)
	}
	if authyResponse["success"].(string) == "true" {
		printAuthResponse(1)
	}
	printAuthResponse(-1)
}
