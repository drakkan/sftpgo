// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	activeMetadataChecks metadataChecks
)

type metadataCheck struct {
	// Username to which the metadata check refers
	Username string `json:"username"`
	// check start time as unix timestamp in milliseconds
	StartTime int64 `json:"start_time"`
}

// metadataChecks holds the active metadata checks
type metadataChecks struct {
	sync.RWMutex
	checks []metadataCheck
}

func (c *metadataChecks) get() []metadataCheck {
	c.RLock()
	defer c.RUnlock()

	checks := make([]metadataCheck, len(c.checks))
	copy(checks, c.checks)

	return checks
}

func (c *metadataChecks) add(username string) bool {
	c.Lock()
	defer c.Unlock()

	for idx := range c.checks {
		if c.checks[idx].Username == username {
			return false
		}
	}

	c.checks = append(c.checks, metadataCheck{
		Username:  username,
		StartTime: util.GetTimeAsMsSinceEpoch(time.Now()),
	})

	return true
}

func (c *metadataChecks) remove(username string) bool {
	c.Lock()
	defer c.Unlock()

	for idx := range c.checks {
		if c.checks[idx].Username == username {
			lastIdx := len(c.checks) - 1
			c.checks[idx] = c.checks[lastIdx]
			c.checks = c.checks[:lastIdx]
			return true
		}
	}

	return false
}

func getMetadataChecks(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	render.JSON(w, r, activeMetadataChecks.get())
}

func startMetadataCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	user, err := dataprovider.GetUserWithGroupSettings(getURLParam(r, "username"))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !activeMetadataChecks.add(user.Username) {
		sendAPIResponse(w, r, err, fmt.Sprintf("Another check is already in progress for user %#v", user.Username),
			http.StatusConflict)
		return
	}
	go doMetadataCheck(user) //nolint:errcheck

	sendAPIResponse(w, r, err, "Check started", http.StatusAccepted)
}

func doMetadataCheck(user dataprovider.User) error {
	defer activeMetadataChecks.remove(user.Username)

	err := user.CheckMetadataConsistency()
	if err != nil {
		logger.Warn(logSender, "", "error checking metadata for user %#v: %v", user.Username, err)
		return err
	}
	logger.Debug(logSender, "", "metadata check completed for user: %#v", user.Username)
	return nil
}
