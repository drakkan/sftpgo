package common

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

// HostEvent is the enumerable for the supported host events
type HostEvent int

// Supported host events
const (
	HostEventLoginFailed HostEvent = iota
	HostEventUserNotFound
	HostEventNoLoginTried
	HostEventLimitExceeded
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
	AddEvent(ip string, event HostEvent)
	IsBanned(ip string) bool
	GetBanTime(ip string) (*time.Time, error)
	GetScore(ip string) (int, error)
	DeleteHost(ip string) bool
	Reload() error
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
	// Score for invalid login attempts, eg. non-existent user accounts or
	// client disconnected for inactivity without authentication attempts
	ScoreInvalid int `json:"score_invalid" mapstructure:"score_invalid"`
	// Score for valid login attempts, eg. user accounts that exist
	ScoreValid int `json:"score_valid" mapstructure:"score_valid"`
	// Score for limit exceeded events, generated from the rate limiters or for max connections
	// per-host exceeded
	ScoreLimitExceeded int `json:"score_limit_exceeded" mapstructure:"score_limit_exceeded"`
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
	// Path to a file containing a list of ip addresses and/or networks to never ban
	SafeListFile string `json:"safelist_file" mapstructure:"safelist_file"`
	// Path to a file containing a list of ip addresses and/or networks to always ban
	BlockListFile string `json:"blocklist_file" mapstructure:"blocklist_file"`
}

type baseDefender struct {
	config *DefenderConfig
	sync.RWMutex
	safeList  *HostList
	blockList *HostList
}

// Reload reloads block and safe lists
func (d *baseDefender) Reload() error {
	blockList, err := loadHostListFromFile(d.config.BlockListFile)
	if err != nil {
		return err
	}

	d.Lock()
	d.blockList = blockList
	d.Unlock()

	safeList, err := loadHostListFromFile(d.config.SafeListFile)
	if err != nil {
		return err
	}

	d.Lock()
	d.safeList = safeList
	d.Unlock()

	return nil
}

func (d *baseDefender) isBanned(ip string) bool {
	if d.blockList != nil && d.blockList.isListed(ip) {
		// permanent ban
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
	case HostEventUserNotFound, HostEventNoLoginTried:
		score = d.config.ScoreInvalid
	}
	return score
}

// HostListFile defines the structure expected for safe/block list files
type HostListFile struct {
	IPAddresses  []string `json:"addresses"`
	CIDRNetworks []string `json:"networks"`
}

// HostList defines the structure used to keep the HostListFile in memory
type HostList struct {
	IPAddresses map[string]bool
	Ranges      cidranger.Ranger
}

func (h *HostList) isListed(ip string) bool {
	if _, ok := h.IPAddresses[ip]; ok {
		return true
	}

	ok, err := h.Ranges.Contains(net.ParseIP(ip))
	if err != nil {
		return false
	}

	return ok
}

type hostEvent struct {
	dateTime time.Time
	score    int
}

type hostScore struct {
	TotalScore int
	Events     []hostEvent
}

// validate returns an error if the configuration is invalid
func (c *DefenderConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ScoreInvalid >= c.Threshold {
		return fmt.Errorf("score_invalid %v cannot be greater than threshold %v", c.ScoreInvalid, c.Threshold)
	}
	if c.ScoreValid >= c.Threshold {
		return fmt.Errorf("score_valid %v cannot be greater than threshold %v", c.ScoreValid, c.Threshold)
	}
	if c.ScoreLimitExceeded >= c.Threshold {
		return fmt.Errorf("score_limit_exceeded %v cannot be greater than threshold %v", c.ScoreLimitExceeded, c.Threshold)
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

func loadHostListFromFile(name string) (*HostList, error) {
	if name == "" {
		return nil, nil
	}
	if !util.IsFileInputValid(name) {
		return nil, fmt.Errorf("invalid host list file name %#v", name)
	}

	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}

	// opinionated max size, you should avoid big host lists
	if info.Size() > 1048576*5 { // 5MB
		return nil, fmt.Errorf("host list file %#v is too big: %v bytes", name, info.Size())
	}

	content, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("unable to read input file %#v: %v", name, err)
	}

	var hostList HostListFile

	err = json.Unmarshal(content, &hostList)
	if err != nil {
		return nil, err
	}

	if len(hostList.CIDRNetworks) > 0 || len(hostList.IPAddresses) > 0 {
		result := &HostList{
			IPAddresses: make(map[string]bool),
			Ranges:      cidranger.NewPCTrieRanger(),
		}
		ipCount := 0
		cdrCount := 0
		for _, ip := range hostList.IPAddresses {
			if net.ParseIP(ip) == nil {
				logger.Warn(logSender, "", "unable to parse IP %#v", ip)
				continue
			}
			result.IPAddresses[ip] = true
			ipCount++
		}
		for _, cidrNet := range hostList.CIDRNetworks {
			_, network, err := net.ParseCIDR(cidrNet)
			if err != nil {
				logger.Warn(logSender, "", "unable to parse CIDR network %#v", cidrNet)
				continue
			}
			err = result.Ranges.Insert(cidranger.NewBasicRangerEntry(*network))
			if err == nil {
				cdrCount++
			}
		}

		logger.Info(logSender, "", "list %#v loaded, ip addresses loaded: %v/%v networks loaded: %v/%v",
			name, ipCount, len(hostList.IPAddresses), cdrCount, len(hostList.CIDRNetworks))
		return result, nil
	}

	return nil, nil
}
