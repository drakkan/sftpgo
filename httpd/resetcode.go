package httpd

import (
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/util"
)

var (
	resetCodeLifespan = 10 * time.Minute
	resetCodes        sync.Map
)

type resetCode struct {
	Code      string
	Username  string
	IsAdmin   bool
	ExpiresAt time.Time
}

func (c *resetCode) isExpired() bool {
	return c.ExpiresAt.Before(time.Now().UTC())
}

func newResetCode(username string, isAdmin bool) *resetCode {
	return &resetCode{
		Code:      util.GenerateUniqueID(),
		Username:  username,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(resetCodeLifespan).UTC(),
	}
}

func cleanupExpiredResetCodes() {
	resetCodes.Range(func(key, value interface{}) bool {
		c, ok := value.(*resetCode)
		if !ok || c.isExpired() {
			resetCodes.Delete(key)
		}
		return true
	})
}
