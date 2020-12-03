// +build linux

package config

import "github.com/spf13/viper"

// linux specific config search path
func setViperAdditionalConfigPaths(v *viper.Viper) {
	v.AddConfigPath("$HOME/.config/sftpgo")
	v.AddConfigPath("/etc/sftpgo")
}
