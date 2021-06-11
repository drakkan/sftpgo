package dataprovider

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminSetDefaults(t *testing.T) {
	a := &Admin{}
	a.setDefaults()

	assert.Equal(t, `admin`, a.Username)
	assert.Equal(t, `password`, a.Password)

	// set environment variables
	require.Nil(t, os.Setenv(`SFTPGO_DEFAULT_ADMIN_USERNAME`, `user1`))
	require.Nil(t, os.Setenv(`SFTPGO_DEFAULT_ADMIN_PASSWORD`, `pass1`))

	a2 := &Admin{}
	a2.setDefaults()

	assert.Equal(t, `admin`, a.Username)
	assert.Equal(t, `password`, a.Password)

	// clear environment variables
	require.Nil(t, os.Unsetenv(`SFTPGO_DEFAULT_ADMIN_USERNAME`))
	require.Nil(t, os.Unsetenv(`SFTPGO_DEFAULT_ADMIN_PASSWORD`))
}
