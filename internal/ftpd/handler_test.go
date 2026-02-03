package ftpd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
)

func TestNormalizeFTPPathLatin1(t *testing.T) {
	conn := &Connection{
		BaseConnection: common.NewBaseConnection("test-conn", common.ProtocolFTP, "127.0.0.1", "127.0.0.1",
			dataprovider.User{}),
	}
	latin1 := string([]byte{0x66, 0x6f, 0x6f, 0xe9, 0x2e, 0x74, 0x78, 0x74})

	normalized, err := conn.normalizeFTPPath(latin1)

	require.NoError(t, err)
	require.Equal(t, "fooé.txt", normalized)
}

func TestNormalizeFTPPathUTF8(t *testing.T) {
	conn := &Connection{
		BaseConnection: common.NewBaseConnection("test-conn", common.ProtocolFTP, "127.0.0.1", "127.0.0.1",
			dataprovider.User{}),
	}
	utf8Name := "déjà-vu.txt"

	normalized, err := conn.normalizeFTPPath(utf8Name)

	require.NoError(t, err)
	require.Equal(t, utf8Name, normalized)
}
