package dataprovider

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_isLastActivityRelativelyRecent(t *testing.T) {
	tests := []struct {
		name         string
		lastActivity int64
		minDelay     time.Duration
		want         bool
	}{
		{
			"very recent activity", time.Now().Add(-time.Second).UnixMilli(), time.Minute * 10, false,
		},
		{
			"relatively recent activity", time.Now().Add(-time.Minute).UnixMilli(), time.Minute * 10, true,
		},
		{
			"not recent activity", time.Now().Add(-time.Hour).UnixMilli(), time.Minute * 10, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLastActivityRelativelyRecent(tt.lastActivity, tt.minDelay)
			assert.Equal(t, tt.want, got)
		})
	}
}
