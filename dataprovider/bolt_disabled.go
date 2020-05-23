// +build nobolt

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/utils"
)

func init() {
	utils.AddFeature("-bolt")
}

func initializeBoltProvider(basePath string) error {
	return errors.New("bolt disabled at build time")
}
