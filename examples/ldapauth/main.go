package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"
)

const (
	bindUsername = "cn=Directory Manager"
	bindPassword = "YOUR_ADMIN_PASSWORD_HERE"
	bindURL      = "ldap://192.168.1.103:389"
)

type userFilters struct {
	DeniedLoginMethods []string `json:"denied_login_methods,omitempty"`
}

type minimalSFTPGoUser struct {
	Status      int                 `json:"status,omitempty"`
	Username    string              `json:"username"`
	HomeDir     string              `json:"home_dir,omitempty"`
	UID         int                 `json:"uid,omitempty"`
	GID         int                 `json:"gid,omitempty"`
	Permissions map[string][]string `json:"permissions"`
	Filters     userFilters         `json:"filters"`
}

func exitError() {
	u := minimalSFTPGoUser{
		Username: "",
	}
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
	os.Exit(1)
}

func printSuccessResponse(username, homeDir string, uid, gid int) {
	u := minimalSFTPGoUser{
		Username: username,
		HomeDir:  homeDir,
		UID:      uid,
		GID:      gid,
		Status:   1,
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{"*"}
	// uncomment the next line to require publickey+password authentication
	//u.Filters.DeniedLoginMethods = []string{"publickey", "password", "keyboard-interactive", "publickey+keyboard-interactive"}
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
	os.Exit(0)
}

func main() {
	// get credentials from env vars
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	password := os.Getenv("SFTPGO_AUTHD_PASSWORD")
	publickey := os.Getenv("SFTPGO_AUTHD_PUBLIC_KEY")
	l, err := ldap.DialURL(bindURL)
	if err != nil {
		exitError()
	}
	defer l.Close()
	// bind to the ldap server with an account that can read users
	err = l.Bind(bindUsername, bindPassword)
	if err != nil {
		exitError()
	}

	// search the user trying to login and fetch some attributes, this search string is tested against 389ds using the default configuration
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=nsPerson)(uid=%s))", username),
		[]string{"dn", "homeDirectory", "uidNumber", "gidNumber", "nsSshPublicKey"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		exitError()
	}

	// we expect exactly one user
	if len(sr.Entries) != 1 {
		exitError()
	}

	if len(publickey) > 0 {
		// check public key
		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publickey))
		if err != nil {
			exitError()
		}
		authOk := false
		for _, k := range sr.Entries[0].GetAttributeValues("nsSshPublicKey") {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			// we skip an invalid public key stored inside the LDAP server
			if err != nil {
				continue
			}
			if bytes.Equal(key.Marshal(), userKey.Marshal()) {
				authOk = true
				break
			}
		}
		if !authOk {
			exitError()
		}
	} else {
		// bind to the LDAP server with the user dn and the given password to check the password
		userdn := sr.Entries[0].DN
		err = l.Bind(userdn, password)
		if err != nil {
			exitError()
		}
	}

	uid, err := strconv.Atoi(sr.Entries[0].GetAttributeValue("uidNumber"))
	if err != nil {
		exitError()
	}
	gid, err := strconv.Atoi(sr.Entries[0].GetAttributeValue("gidNumber"))
	if err != nil {
		exitError()
	}
	// return the authenticated user
	printSuccessResponse(username, sr.Entries[0].GetAttributeValue("homeDirectory"), uid, gid)
}
