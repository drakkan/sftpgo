package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"
)

const (
	rootDN       = "dc=example,dc=com"
	bindUsername = "cn=sftpgo," + rootDN
	bindURL      = "ldap:///" // That is, the server on the default port of localhost.
	passwordFile = "/etc/sftpgo/admin-password.txt" // make this file readable only by the server
	publicDir    = "/var/www/webdav/public"
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
	log.Printf("exitError\n")
	u := minimalSFTPGoUser{
		Username: "",
	}
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
	os.Exit(1)
}

func printSuccessResponse(username, homeDir string, uid, gid int, permissions []string) {
	u := minimalSFTPGoUser{
		Username: username,
		HomeDir:  homeDir,
		UID:      uid,
		GID:      gid,
		Status:   1,
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = permissions
	// uncomment the next line to require publickey+password authentication
	//u.Filters.DeniedLoginMethods = []string{"publickey", "password", "keyboard-interactive", "publickey+keyboard-interactive"}
	resp, _ := json.Marshal(u)
	log.Printf("%v\n", string(resp))
	fmt.Printf("%v\n", string(resp))
	os.Exit(0)
}

func main() {
	logWriter, err := syslog.New(syslog.LOG_NOTICE, "sftpgo")
	if err == nil {
		log.SetOutput(logWriter)
	}
	// get credentials from env vars
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	password := os.Getenv("SFTPGO_AUTHD_PASSWORD")
	publickey := os.Getenv("SFTPGO_AUTHD_PUBLIC_KEY")
	if strings.ToLower(username) == "anonymous" {
		printSuccessResponse("anonymous", publicDir, 0, 0, []string{"list", "download"})
		return
	}
	l, err := ldap.DialURL(bindURL)
	if err != nil {
		log.Printf("DialURL: %s\n", err.Error())
		exitError()
	}
	defer l.Close()
	// bind to the ldap server with an account that can read users
	bindPassword, err := os.ReadFile(passwordFile)
	if err != nil {
		log.Printf("ReadFile(%s): %s\n", passwordFile, err.Error())
		exitError()
	}
	err = l.Bind(bindUsername, string(bindPassword))
	if err != nil {
		log.Printf("Bind(%s): %s\n", bindUsername, err.Error())
		exitError()
	}

	// search the user trying to login and fetch some attributes, this search string is tested against 389ds using the default configuration
	log.Printf("username=%s\n", username)
	searchFilter := fmt.Sprintf("(uid=%s)", username)
	searchRequest := ldap.NewSearchRequest(
		"ou=people," + rootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "uid", "homeDirectory", "uidNumber", "gidNumber", "nsSshPublicKey"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Printf("Search(%s): %s\n", searchFilter, err.Error())
		exitError()
	}

	// we expect exactly one user
	if len(sr.Entries) != 1 {
		log.Printf("Search(%s): %d entries\n", searchFilter, len(sr.Entries))
		exitError()
	}

	if len(publickey) > 0 {
		// check public key
		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publickey))
		if err != nil {
			log.Printf("ParseAuthorizedKey(%s): %s\n", publickey, err.Error())
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
			log.Printf("publickey %s !authOk\n", publickey)
			exitError()
		}
	} else {
		// bind to the LDAP server with the user dn and the given password to check the password
		userdn := sr.Entries[0].DN
		// log.Printf("password=%s\n", password)
		err = l.Bind(userdn, password)
		if err != nil {
			log.Printf("Bind(%s): %s\n", userdn, err.Error())
			exitError()
		}
	}

	// People in the LDAP directory aren't necessarily Linux users;
	// so they might not have a uidNumber or gidNumber.
	uidNumber := sr.Entries[0].GetAttributeValue("uidNumber")
	uid, err := strconv.Atoi(uidNumber)
	if err != nil {
		//log.Printf("uid Atoi(%s) = %s\n", uidNumber, err.Error())
		uid = 0
	}
	gidNumber := sr.Entries[0].GetAttributeValue("gidNumber")
	gid, err := strconv.Atoi(gidNumber)
	if err != nil {
		//log.Printf("gid Atoi(%s) = %s\n", gidNumber, err.Error())
		gid = 0
	}
	homeDir := sr.Entries[0].GetAttributeValue("homeDirectory")
	if (len(homeDir) <= 0) {
		homeDir = publicDir // homeDir is a required attribute.
	}
	// return the authenticated user
	printSuccessResponse(sr.Entries[0].GetAttributeValue("uid"), homeDir, uid, gid, []string{"*"})
}
