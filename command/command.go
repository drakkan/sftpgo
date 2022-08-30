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
)

const (
	minTimeout     = 1
	maxTimeout     = 300
	defaultTimeout = 30
)

var (
	config Config
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
	// Env defines additional environment variable for the commands.
	// Each entry is of the form "key=value".
	// These values are added to the global environment variables if any
	Env []string `json:"env" mapstructure:"env"`
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
	}
	config = c
	return nil
}

// GetConfig returns the configuration for the specified command
func GetConfig(command string) (time.Duration, []string) {
	env := os.Environ()
	timeout := time.Duration(config.Timeout) * time.Second
	env = append(env, config.Env...)
	for _, cmd := range config.Commands {
		if cmd.Path == command {
			timeout = time.Duration(cmd.Timeout) * time.Second
			env = append(env, cmd.Env...)
			break
		}
	}

	return timeout, env
}
