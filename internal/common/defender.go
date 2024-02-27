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

package common

import (
	"fmt"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// HostEvent is the enumerable for the supported host events
type HostEvent string

// Supported host events
const (
	HostEventLoginFailed   HostEvent = "LoginFailed"
	HostEventUserNotFound  HostEvent = "UserNotFound"
	HostEventNoLoginTried  HostEvent = "NoLoginTried"
	HostEventLimitExceeded HostEvent = "LimitExceeded"
)

// Supported defender drivers
const (
	DefenderDriverMemory   = "memory"
	DefenderDriverProvider = "provider"
)

var (
	supportedDefenderDrivers = []string{DefenderDriverMemory, DefenderDriverProvider}
)

// Defender defines the interface that a defender must implements
type Defender interface {
	GetHosts() ([]dataprovider.DefenderEntry, error)
	GetHost(ip string) (dataprovider.DefenderEntry, error)
	AddEvent(ip, protocol string, event HostEvent) bool
	IsBanned(ip, protocol string) bool
	IsSafe(ip, protocol string) bool
	GetBanTime(ip string) (*time.Time, error)
	GetScore(ip string) (int, error)
	DeleteHost(ip string) bool
}

// DefenderConfig defines the "defender" configuration
type DefenderConfig struct {
	// Set to true to enable the defender
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// Defender implementation to use, we support "memory" and "provider".
	// Using "provider" as driver you can share the defender events among
	// multiple SFTPGo instances. For a single instance "memory" provider will
	// be much faster
	Driver string `json:"driver" mapstructure:"driver"`
	// BanTime is the number of minutes that a host is banned
	BanTime int `json:"ban_time" mapstructure:"ban_time"`
	// Percentage increase of the ban time if a banned host tries to connect again
	BanTimeIncrement int `json:"ban_time_increment" mapstructure:"ban_time_increment"`
	// Threshold value for banning a client
	Threshold int `json:"threshold" mapstructure:"threshold"`
	// Score for invalid login attempts, eg. non-existent user accounts
	ScoreInvalid int `json:"score_invalid" mapstructure:"score_invalid"`
	// Score for valid login attempts, eg. user accounts that exist
	ScoreValid int `json:"score_valid" mapstructure:"score_valid"`
	// Score for limit exceeded events, generated from the rate limiters or for max connections
	// per-host exceeded
	ScoreLimitExceeded int `json:"score_limit_exceeded" mapstructure:"score_limit_exceeded"`
	// ScoreNoAuth defines the score for clients disconnected without authentication
	// attempts
	ScoreNoAuth int `json:"score_no_auth" mapstructure:"score_no_auth"`
	// Defines the time window, in minutes, for tracking client errors.
	// A host is banned if it has exceeded the defined threshold during
	// the last observation time minutes
	ObservationTime int `json:"observation_time" mapstructure:"observation_time"`
	// The number of banned IPs and host scores kept in memory will vary between the
	// soft and hard limit for the "memory" driver. For the "provider" driver the
	// soft limit is ignored and the hard limit is used to limit the number of entries
	// to return when you request for the entire host list from the defender
	EntriesSoftLimit int `json:"entries_soft_limit" mapstructure:"entries_soft_limit"`
	EntriesHardLimit int `json:"entries_hard_limit" mapstructure:"entries_hard_limit"`
}

type baseDefender struct {
	config *DefenderConfig
	ipList *dataprovider.IPList
}

func (d *baseDefender) isBanned(ip, protocol string) bool {
	isListed, mode, err := d.ipList.IsListed(ip, protocol)
	if err != nil {
		return false
	}
	if isListed && mode == dataprovider.ListModeDeny {
		return true
	}

	return false
}

func (d *baseDefender) IsSafe(ip, protocol string) bool {
	isListed, mode, err := d.ipList.IsListed(ip, protocol)
	if err == nil && isListed && mode == dataprovider.ListModeAllow {
		return true
	}
	return false
}

func (d *baseDefender) getScore(event HostEvent) int {
	var score int

	switch event {
	case HostEventLoginFailed:
		score = d.config.ScoreValid
	case HostEventLimitExceeded:
		score = d.config.ScoreLimitExceeded
	case HostEventUserNotFound:
		score = d.config.ScoreInvalid
	case HostEventNoLoginTried:
		score = d.config.ScoreNoAuth
	}
	return score
}

// logEvent logs a defender event that changes a host's score
func (d *baseDefender) logEvent(ip, protocol string, event HostEvent, totalScore int) {
	// ignore events which do not change the host score
	eventScore := d.getScore(event)
	if eventScore == 0 {
		return
	}

	logger.GetLogger().Debug().
		Timestamp().
		Str("sender", "defender").
		Str("client_ip", ip).
		Str("protocol", protocol).
		Str("event", string(event)).
		Int("increase_score_by", eventScore).
		Int("score", totalScore).
		Send()
}

// logBan logs a host's ban due to a too high host score
func (d *baseDefender) logBan(ip, protocol string) {
	logger.GetLogger().Info().
		Timestamp().
		Str("sender", "defender").
		Str("client_ip", ip).
		Str("protocol", protocol).
		Str("event", "banned").
		Send()
}

type hostEvent struct {
	dateTime time.Time
	score    int
}

type hostScore struct {
	TotalScore int
	Events     []hostEvent
}

func (c *DefenderConfig) checkScores() error {
	if c.ScoreInvalid < 0 {
		c.ScoreInvalid = 0
	}
	if c.ScoreValid < 0 {
		c.ScoreValid = 0
	}
	if c.ScoreLimitExceeded < 0 {
		c.ScoreLimitExceeded = 0
	}
	if c.ScoreNoAuth < 0 {
		c.ScoreNoAuth = 0
	}
	if c.ScoreInvalid == 0 && c.ScoreValid == 0 && c.ScoreLimitExceeded == 0 && c.ScoreNoAuth == 0 {
		return fmt.Errorf("invalid defender configuration: all scores are disabled")
	}
	return nil
}

// validate returns an error if the configuration is invalid
func (c *DefenderConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if err := c.checkScores(); err != nil {
		return err
	}
	if c.ScoreInvalid >= c.Threshold {
		return fmt.Errorf("score_invalid %d cannot be greater than threshold %d", c.ScoreInvalid, c.Threshold)
	}
	if c.ScoreValid >= c.Threshold {
		return fmt.Errorf("score_valid %d cannot be greater than threshold %d", c.ScoreValid, c.Threshold)
	}
	if c.ScoreLimitExceeded >= c.Threshold {
		return fmt.Errorf("score_limit_exceeded %d cannot be greater than threshold %d", c.ScoreLimitExceeded, c.Threshold)
	}
	if c.ScoreNoAuth >= c.Threshold {
		return fmt.Errorf("score_no_auth %d cannot be greater than threshold %d", c.ScoreNoAuth, c.Threshold)
	}
	if c.BanTime <= 0 {
		return fmt.Errorf("invalid ban_time %v", c.BanTime)
	}
	if c.BanTimeIncrement <= 0 {
		return fmt.Errorf("invalid ban_time_increment %v", c.BanTimeIncrement)
	}
	if c.ObservationTime <= 0 {
		return fmt.Errorf("invalid observation_time %v", c.ObservationTime)
	}
	if c.EntriesSoftLimit <= 0 {
		return fmt.Errorf("invalid entries_soft_limit %v", c.EntriesSoftLimit)
	}
	if c.EntriesHardLimit <= c.EntriesSoftLimit {
		return fmt.Errorf("invalid entries_hard_limit %v must be > %v", c.EntriesHardLimit, c.EntriesSoftLimit)
	}

	return nil
}
