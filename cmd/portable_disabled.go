//go:build noportable
// +build noportable

package cmd

import "github.com/drakkan/sftpgo/v2/version"

func init() {
	version.AddFeature("-portable")
}
