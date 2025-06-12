// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build linux

package config

import "github.com/spf13/viper"

// linux specific config search path
func setViperAdditionalConfigPaths() {
	viper.AddConfigPath("$HOME/.config/sftpgo")
	viper.AddConfigPath("/etc/sftpgo")
	viper.AddConfigPath("/usr/local/etc/sftpgo")
}
