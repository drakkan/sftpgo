// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Package command provides command configuration for SFTPGo hooks
package command

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	minTimeout     = 1
	maxTimeout     = 300
	defaultTimeout = 30
)

// Supported hook names
const (
	HookFsActions           = "fs_actions"
	HookProviderActions     = "provider_actions"
	HookStartup             = "startup"
	HookPostConnect         = "post_connect"
	HookPostDisconnect      = "post_disconnect"
	HookDataRetention       = "data_retention"
	HookCheckPassword       = "check_password"
	HookPreLogin            = "pre_login"
	HookPostLogin           = "post_login"
	HookExternalAuth        = "external_auth"
	HookKeyboardInteractive = "keyboard_interactive"
)

var (
	config         Config
	supportedHooks = []string{HookFsActions, HookProviderActions, HookStartup, HookPostConnect, HookPostDisconnect,
		HookDataRetention, HookCheckPassword, HookPreLogin, HookPostLogin, HookExternalAuth, HookKeyboardInteractive}
)

// Command define the configuration for a specific commands
type Command struct {
	// Path is the command path as defined in the hook configuration
	Path string `json:"path" mapstructure:"path"`
	// Timeout specifies a time limit, in seconds, for the command execution.
	// This value overrides the global timeout if set.
	// Do not use variables with the SFTPGO_ prefix to avoid conflicts with env
	// vars that SFTPGo sets
	Timeout int `json:"timeout" mapstructure:"timeout"`
	// Env defines additional environment variable for the command.
	// Each entry is of the form "key=value".
	// These values are added to the global environment variables if any
	Env []string `json:"env" mapstructure:"env"`
	// Args defines arguments to pass to the specified command
	Args []string `json:"args" mapstructure:"args"`
	// if not empty both command path and hook name must match
	Hook string `json:"hook" mapstructure:"hook"`
}

// Config defines the configuration for external commands such as
// program based hooks
type Config struct {
	// Timeout specifies a global time limit, in seconds, for the external commands execution
	Timeout int `json:"timeout" mapstructure:"timeout"`
	// Env defines additional environment variable for the commands.
	// Each entry is of the form "key=value".
	// Do not use variables with the SFTPGO_ prefix to avoid conflicts with env
	// vars that SFTPGo sets
	Env []string `json:"env" mapstructure:"env"`
	// Commands defines configuration for specific commands
	Commands []Command `json:"commands" mapstructure:"commands"`
}

func init() {
	config = Config{
		Timeout: defaultTimeout,
	}
}

// Initialize configures commands
func (c Config) Initialize() error {
	if c.Timeout < minTimeout || c.Timeout > maxTimeout {
		return fmt.Errorf("invalid timeout %v", c.Timeout)
	}
	for _, env := range c.Env {
		if len(strings.Split(env, "=")) != 2 {
			return fmt.Errorf("invalid env var %#v", env)
		}
	}
	for idx, cmd := range c.Commands {
		if cmd.Path == "" {
			return fmt.Errorf("invalid path %#v", cmd.Path)
		}
		if cmd.Timeout == 0 {
			c.Commands[idx].Timeout = c.Timeout
		} else {
			if cmd.Timeout < minTimeout || cmd.Timeout > maxTimeout {
				return fmt.Errorf("invalid timeout %v for command %#v", cmd.Timeout, cmd.Path)
			}
		}
		for _, env := range cmd.Env {
			if len(strings.Split(env, "=")) != 2 {
				return fmt.Errorf("invalid env var %#v for command %#v", env, cmd.Path)
			}
		}
		// don't validate args, we allow to pass empty arguments
		if cmd.Hook != "" {
			if !util.Contains(supportedHooks, cmd.Hook) {
				return fmt.Errorf("invalid hook name %q, supported values: %+v", cmd.Hook, supportedHooks)
			}
		}
	}
	config = c
	return nil
}

// GetConfig returns the configuration for the specified command
func GetConfig(command, hook string) (time.Duration, []string, []string) {
	env := os.Environ()
	var args []string
	timeout := time.Duration(config.Timeout) * time.Second
	env = append(env, config.Env...)
	for _, cmd := range config.Commands {
		if cmd.Path == command {
			if cmd.Hook == "" || cmd.Hook == hook {
				timeout = time.Duration(cmd.Timeout) * time.Second
				env = append(env, cmd.Env...)
				args = cmd.Args
				break
			}
		}
	}

	return timeout, env, args
}
