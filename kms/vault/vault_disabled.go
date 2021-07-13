// +build novaultkms

package vault

import (
	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-vaultkms")
}
