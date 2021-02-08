package fsmeta

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSSLMode(t *testing.T) {
	assert.Equal(t, `disable`, getSSLMode(0))
	assert.Equal(t, `require`, getSSLMode(1))
	assert.Equal(t, `verify-ca`, getSSLMode(2))
	assert.Equal(t, `verify-full`, getSSLMode(3))
	assert.Equal(t, ``, getSSLMode(4))
}
