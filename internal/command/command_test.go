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

package command

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandConfig(t *testing.T) {
	require.Equal(t, defaultTimeout, config.Timeout)
	cfg := Config{
		Timeout: 10,
		Env:     []string{"a=b"},
	}
	err := cfg.Initialize()
	require.NoError(t, err)
	assert.Equal(t, cfg.Timeout, config.Timeout)
	assert.Equal(t, cfg.Env, config.Env)
	assert.Len(t, cfg.Commands, 0)
	timeout, env, args := GetConfig("cmd", "")
	assert.Equal(t, time.Duration(config.Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.Len(t, args, 0)

	cfg.Commands = []Command{
		{
			Path:    "cmd1",
			Timeout: 30,
			Env:     []string{"c=d"},
			Args:    []string{"1", "", "2"},
		},
		{
			Path:    "cmd2",
			Timeout: 0,
			Env:     []string{"e=f"},
		},
	}
	err = cfg.Initialize()
	require.NoError(t, err)
	assert.Equal(t, cfg.Timeout, config.Timeout)
	assert.Equal(t, cfg.Env, config.Env)
	if assert.Len(t, config.Commands, 2) {
		assert.Equal(t, cfg.Commands[0].Path, config.Commands[0].Path)
		assert.Equal(t, cfg.Commands[0].Timeout, config.Commands[0].Timeout)
		assert.Equal(t, cfg.Commands[0].Env, config.Commands[0].Env)
		assert.Equal(t, cfg.Commands[0].Args, config.Commands[0].Args)
		assert.Equal(t, cfg.Commands[1].Path, config.Commands[1].Path)
		assert.Equal(t, cfg.Timeout, config.Commands[1].Timeout)
		assert.Equal(t, cfg.Commands[1].Env, config.Commands[1].Env)
		assert.Equal(t, cfg.Commands[1].Args, config.Commands[1].Args)
	}
	timeout, env, args = GetConfig("cmd1", "")
	assert.Equal(t, time.Duration(config.Commands[0].Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.Contains(t, env, "c=d")
	assert.NotContains(t, env, "e=f")
	if assert.Len(t, args, 3) {
		assert.Equal(t, "1", args[0])
		assert.Empty(t, args[1])
		assert.Equal(t, "2", args[2])
	}
	timeout, env, args = GetConfig("cmd2", "")
	assert.Equal(t, time.Duration(config.Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.NotContains(t, env, "c=d")
	assert.Contains(t, env, "e=f")
	assert.Len(t, args, 0)

	cfg.Commands = []Command{
		{
			Path:    "cmd1",
			Timeout: 30,
			Env:     []string{"c=d"},
			Args:    []string{"1", "", "2"},
			Hook:    HookCheckPassword,
		},
		{
			Path:    "cmd1",
			Timeout: 0,
			Env:     []string{"e=f"},
			Hook:    HookExternalAuth,
		},
	}
	err = cfg.Initialize()
	require.NoError(t, err)
	timeout, env, args = GetConfig("cmd1", "")
	assert.Equal(t, time.Duration(config.Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.NotContains(t, env, "c=d")
	assert.NotContains(t, env, "e=f")
	assert.Len(t, args, 0)
	timeout, env, args = GetConfig("cmd1", HookCheckPassword)
	assert.Equal(t, time.Duration(config.Commands[0].Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.Contains(t, env, "c=d")
	assert.NotContains(t, env, "e=f")
	if assert.Len(t, args, 3) {
		assert.Equal(t, "1", args[0])
		assert.Empty(t, args[1])
		assert.Equal(t, "2", args[2])
	}
	timeout, env, args = GetConfig("cmd1", HookExternalAuth)
	assert.Equal(t, time.Duration(cfg.Timeout)*time.Second, timeout)
	assert.Contains(t, env, "a=b")
	assert.NotContains(t, env, "c=d")
	assert.Contains(t, env, "e=f")
	assert.Len(t, args, 0)
}

func TestConfigErrors(t *testing.T) {
	c := Config{}
	err := c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid timeout")
	}
	c.Timeout = 10
	c.Env = []string{"a"}
	err = c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid env var")
	}
	c.Env = nil
	c.Commands = []Command{
		{
			Path: "",
		},
	}
	err = c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid path")
	}
	c.Commands = []Command{
		{
			Path:    "path",
			Timeout: 10000,
		},
	}
	err = c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid timeout")
	}
	c.Commands = []Command{
		{
			Path:    "path",
			Timeout: 30,
			Env:     []string{"b"},
		},
	}
	err = c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid env var")
	}
	c.Commands = []Command{
		{
			Path:    "path",
			Timeout: 30,
			Env:     []string{"a=b"},
			Hook:    "invali",
		},
	}
	err = c.Initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid hook name")
	}
}
