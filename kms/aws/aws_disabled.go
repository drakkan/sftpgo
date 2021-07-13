// +build noawskms

package aws

import (
	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-awskms")
}
