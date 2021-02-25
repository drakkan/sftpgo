package common

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicAuth(t *testing.T) {
	httpAuth, err := NewBasicAuthProvider("")
	require.NoError(t, err)
	require.False(t, httpAuth.IsEnabled())

	_, err = NewBasicAuthProvider("missing path")
	require.Error(t, err)

	authUserFile := filepath.Join(os.TempDir(), "http_users.txt")
	authUserData := []byte("test1:$2y$05$bcHSED7aO1cfLto6ZdDBOOKzlwftslVhtpIkRhAtSa4GuLmk5mola\n")
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)

	httpAuth, err = NewBasicAuthProvider(authUserFile)
	require.NoError(t, err)
	require.True(t, httpAuth.IsEnabled())
	require.False(t, httpAuth.ValidateCredentials("test1", "wrong1"))
	require.False(t, httpAuth.ValidateCredentials("test2", "password2"))
	require.True(t, httpAuth.ValidateCredentials("test1", "password1"))

	authUserData = append(authUserData, []byte("test2:$1$OtSSTL8b$bmaCqEksI1e7rnZSjsIDR1\n")...)
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)
	require.False(t, httpAuth.ValidateCredentials("test2", "wrong2"))
	require.True(t, httpAuth.ValidateCredentials("test2", "password2"))

	authUserData = append(authUserData, []byte("test2:$apr1$gLnIkRIf$Xr/6aJfmIrihP4b2N2tcs/\n")...)
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)
	require.False(t, httpAuth.ValidateCredentials("test2", "wrong2"))
	require.True(t, httpAuth.ValidateCredentials("test2", "password2"))

	authUserData = append(authUserData, []byte("test3:$apr1$gLnIkRIf$Xr/6aJfmIrihP4b2N2tcs/\n")...)
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)
	require.False(t, httpAuth.ValidateCredentials("test3", "password3"))

	authUserData = append(authUserData, []byte("test4:$invalid$gLnIkRIf$Xr/6$aJfmIr$ihP4b2N2tcs/\n")...)
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)
	require.False(t, httpAuth.ValidateCredentials("test4", "password3"))

	if runtime.GOOS != "windows" {
		authUserData = append(authUserData, []byte("test5:$apr1$gLnIkRIf$Xr/6aJfmIrihP4b2N2tcs/\n")...)
		err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
		require.NoError(t, err)
		err = os.Chmod(authUserFile, 0001)
		require.NoError(t, err)
		require.False(t, httpAuth.ValidateCredentials("test5", "password2"))
		err = os.Chmod(authUserFile, os.ModePerm)
		require.NoError(t, err)
	}
	authUserData = append(authUserData, []byte("\"foo\"bar\"\r\n")...)
	err = os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)
	require.False(t, httpAuth.ValidateCredentials("test2", "password2"))

	err = os.Remove(authUserFile)
	require.NoError(t, err)
}
