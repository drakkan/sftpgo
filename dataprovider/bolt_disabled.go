//go:build nobolt
// +build nobolt

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-bolt")
}

func initializeBoltProvider(basePath string) error {
	return errors.New("bolt disabled at build time")
}
