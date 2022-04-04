//go:build noportable
// +build noportable

package cmd

import "github.com/drakkan/sftpgo/version"

func init() {
	version.AddFeature("-portable")
}
