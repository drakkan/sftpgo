package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type userMapping struct {
	SFTPGoUsername string
	AuthyID        int64
	AuthyAPIKey    string
}

// we assume that the SFTPGo already exists, we only check the one time token.
// If you need to create the SFTPGo user more fields are needed here
type minimalSFTPGoUser struct {
	Status      int                 `json:"status,omitempty"`
	Username    string              `json:"username"`
	HomeDir     string              `json:"home_dir,omitempty"`
	Permissions map[string][]string `json:"permissions"`
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

func printResponse(username string) {
	u := minimalSFTPGoUser{
		Username: username,
		Status:   1,
		HomeDir:  filepath.Join(os.TempDir(), username),
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{"*"}
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
	if len(username) > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func main() {
	// get credentials from env vars
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	password := os.Getenv("SFTPGO_AUTHD_PASSWORD")
	if len(password) == 0 {
		// login method is not password
		printResponse("")
		return
	}

	for _, m := range mapping {
		if m.SFTPGoUsername == username {
			// mapping found we can now verify the token
			url := fmt.Sprintf("https://api.authy.com/protected/json/verify/%v/%v", password, m.AuthyID)
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
				printResponse("")
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				// status code 200 is expected
				printResponse("")
			}
			var authyResponse map[string]interface{}
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				printResponse("")
			}
			err = json.Unmarshal(respBody, &authyResponse)
			if err != nil {
				printResponse("")
			}
			if authyResponse["success"].(string) == "true" {
				printResponse(username)
			}
			printResponse("")
			break
		}
	}

	// no mapping found
	printResponse("")
}
