package fsmeta

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnabledForBucket(t *testing.T) {
	EnabledRestore := Enabled
	CurrentBuckets := Buckets
	t.Cleanup(func() {
		Enabled = EnabledRestore
		Buckets = CurrentBuckets
	})

	Enabled = false
	Buckets = []string{`bucket1`}
	assert.False(t, EnabledForBucket(`bucket1`))
	assert.False(t, EnabledForBucket(`bucket2`))

	Enabled = true
	assert.True(t, EnabledForBucket(`bucket1`))
	assert.False(t, EnabledForBucket(`bucket2`))

	Buckets = nil
	assert.True(t, EnabledForBucket(`bucket1`))
	assert.True(t, EnabledForBucket(`bucket2`))
}
