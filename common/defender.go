package common

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"

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

// DefenderEntry defines a defender entry
type DefenderEntry struct {
	IP      string    `json:"ip"`
	Score   int       `json:"score,omitempty"`
	BanTime time.Time `json:"ban_time,omitempty"`
}

// GetID returns an unique ID for a defender entry
func (d *DefenderEntry) GetID() string {
	return hex.EncodeToString([]byte(d.IP))
}

// GetBanTime returns the ban time for a defender entry as string
func (d *DefenderEntry) GetBanTime() string {
	if d.BanTime.IsZero() {
		return ""
	}
	return d.BanTime.UTC().Format(time.RFC3339)
}

// MarshalJSON returns the JSON encoding of a DefenderEntry.
func (d *DefenderEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID      string `json:"id"`
		IP      string `json:"ip"`
		Score   int    `json:"score,omitempty"`
		BanTime string `json:"ban_time,omitempty"`
	}{
		ID:      d.GetID(),
		IP:      d.IP,
		Score:   d.Score,
		BanTime: d.GetBanTime(),
	})
}

// Defender defines the interface that a defender must implements
type Defender interface {
	GetHosts() []*DefenderEntry
	GetHost(ip string) (*DefenderEntry, error)
	AddEvent(ip string, event HostEvent)
	IsBanned(ip string) bool
	GetBanTime(ip string) *time.Time
	GetScore(ip string) int
	DeleteHost(ip string) bool
	Reload() error
}

// DefenderConfig defines the "defender" configuration
type DefenderConfig struct {
	// Set to true to enable the defender
	Enabled bool `json:"enabled" mapstructure:"enabled"`
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
	// soft and hard limit
	EntriesSoftLimit int `json:"entries_soft_limit" mapstructure:"entries_soft_limit"`
	EntriesHardLimit int `json:"entries_hard_limit" mapstructure:"entries_hard_limit"`
	// Path to a file containing a list of ip addresses and/or networks to never ban
	SafeListFile string `json:"safelist_file" mapstructure:"safelist_file"`
	// Path to a file containing a list of ip addresses and/or networks to always ban
	BlockListFile string `json:"blocklist_file" mapstructure:"blocklist_file"`
}

type memoryDefender struct {
	config *DefenderConfig
	sync.RWMutex
	// IP addresses of the clients trying to connected are stored inside hosts,
	// they are added to banned once the thresold is reached.
	// A violation from a banned host will increase the ban time
	// based on the configured BanTimeIncrement
	hosts     map[string]hostScore // the key is the host IP
	banned    map[string]time.Time // the key is the host IP
	safeList  *HostList
	blockList *HostList
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

func newInMemoryDefender(config *DefenderConfig) (Defender, error) {
	err := config.validate()
	if err != nil {
		return nil, err
	}
	defender := &memoryDefender{
		config: config,
		hosts:  make(map[string]hostScore),
		banned: make(map[string]time.Time),
	}

	if err := defender.Reload(); err != nil {
		return nil, err
	}

	return defender, nil
}

// Reload reloads block and safe lists
func (d *memoryDefender) Reload() error {
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

// GetHosts returns hosts that are banned or for which some violations have been detected
func (d *memoryDefender) GetHosts() []*DefenderEntry {
	d.RLock()
	defer d.RUnlock()

	var result []*DefenderEntry
	for k, v := range d.banned {
		if v.After(time.Now()) {
			result = append(result, &DefenderEntry{
				IP:      k,
				BanTime: v,
			})
		}
	}
	for k, v := range d.hosts {
		score := 0
		for _, event := range v.Events {
			if event.dateTime.Add(time.Duration(d.config.ObservationTime) * time.Minute).After(time.Now()) {
				score += event.score
			}
		}
		if score > 0 {
			result = append(result, &DefenderEntry{
				IP:    k,
				Score: score,
			})
		}
	}

	return result
}

// GetHost returns a defender host by ip, if any
func (d *memoryDefender) GetHost(ip string) (*DefenderEntry, error) {
	d.RLock()
	defer d.RUnlock()

	if banTime, ok := d.banned[ip]; ok {
		if banTime.After(time.Now()) {
			return &DefenderEntry{
				IP:      ip,
				BanTime: banTime,
			}, nil
		}
	}

	if hs, ok := d.hosts[ip]; ok {
		score := 0
		for _, event := range hs.Events {
			if event.dateTime.Add(time.Duration(d.config.ObservationTime) * time.Minute).After(time.Now()) {
				score += event.score
			}
		}
		if score > 0 {
			return &DefenderEntry{
				IP:    ip,
				Score: score,
			}, nil
		}
	}

	return nil, util.NewRecordNotFoundError("host not found")
}

// IsBanned returns true if the specified IP is banned
// and increase ban time if the IP is found.
// This method must be called as soon as the client connects
func (d *memoryDefender) IsBanned(ip string) bool {
	d.RLock()

	if banTime, ok := d.banned[ip]; ok {
		if banTime.After(time.Now()) {
			increment := d.config.BanTime * d.config.BanTimeIncrement / 100
			if increment == 0 {
				increment++
			}

			d.RUnlock()

			// we can save an earlier ban time if there are contemporary updates
			// but this should not make much difference. I prefer to hold a read lock
			// until possible for performance reasons, this method is called each
			// time a new client connects and it must be as fast as possible
			d.Lock()
			d.banned[ip] = banTime.Add(time.Duration(increment) * time.Minute)
			d.Unlock()

			return true
		}
	}

	defer d.RUnlock()

	if d.blockList != nil && d.blockList.isListed(ip) {
		// permanent ban
		return true
	}

	return false
}

// DeleteHost removes the specified IP from the defender lists
func (d *memoryDefender) DeleteHost(ip string) bool {
	d.Lock()
	defer d.Unlock()

	if _, ok := d.banned[ip]; ok {
		delete(d.banned, ip)
		return true
	}

	if _, ok := d.hosts[ip]; ok {
		delete(d.hosts, ip)
		return true
	}

	return false
}

// AddEvent adds an event for the given IP.
// This method must be called for clients not yet banned
func (d *memoryDefender) AddEvent(ip string, event HostEvent) {
	d.Lock()
	defer d.Unlock()

	if d.safeList != nil && d.safeList.isListed(ip) {
		return
	}

	// ignore events for already banned hosts
	if v, ok := d.banned[ip]; ok {
		if v.After(time.Now()) {
			return
		}
		delete(d.banned, ip)
	}

	var score int

	switch event {
	case HostEventLoginFailed:
		score = d.config.ScoreValid
	case HostEventLimitExceeded:
		score = d.config.ScoreLimitExceeded
	case HostEventUserNotFound, HostEventNoLoginTried:
		score = d.config.ScoreInvalid
	}

	ev := hostEvent{
		dateTime: time.Now(),
		score:    score,
	}

	if hs, ok := d.hosts[ip]; ok {
		hs.Events = append(hs.Events, ev)
		hs.TotalScore = 0

		idx := 0
		for _, event := range hs.Events {
			if event.dateTime.Add(time.Duration(d.config.ObservationTime) * time.Minute).After(time.Now()) {
				hs.Events[idx] = event
				hs.TotalScore += event.score
				idx++
			}
		}

		hs.Events = hs.Events[:idx]
		if hs.TotalScore >= d.config.Threshold {
			d.banned[ip] = time.Now().Add(time.Duration(d.config.BanTime) * time.Minute)
			delete(d.hosts, ip)
			d.cleanupBanned()
		} else {
			d.hosts[ip] = hs
		}
	} else {
		d.hosts[ip] = hostScore{
			TotalScore: ev.score,
			Events:     []hostEvent{ev},
		}
		d.cleanupHosts()
	}
}

func (d *memoryDefender) countBanned() int {
	d.RLock()
	defer d.RUnlock()

	return len(d.banned)
}

func (d *memoryDefender) countHosts() int {
	d.RLock()
	defer d.RUnlock()

	return len(d.hosts)
}

// GetBanTime returns the ban time for the given IP or nil if the IP is not banned
func (d *memoryDefender) GetBanTime(ip string) *time.Time {
	d.RLock()
	defer d.RUnlock()

	if banTime, ok := d.banned[ip]; ok {
		return &banTime
	}

	return nil
}

// GetScore returns the score for the given IP
func (d *memoryDefender) GetScore(ip string) int {
	d.RLock()
	defer d.RUnlock()

	score := 0

	if hs, ok := d.hosts[ip]; ok {
		for _, event := range hs.Events {
			if event.dateTime.Add(time.Duration(d.config.ObservationTime) * time.Minute).After(time.Now()) {
				score += event.score
			}
		}
	}

	return score
}

func (d *memoryDefender) cleanupBanned() {
	if len(d.banned) > d.config.EntriesHardLimit {
		kvList := make(kvList, 0, len(d.banned))

		for k, v := range d.banned {
			if v.Before(time.Now()) {
				delete(d.banned, k)
			}

			kvList = append(kvList, kv{
				Key:   k,
				Value: v.UnixNano(),
			})
		}

		// we removed expired ip addresses, if any, above, this could be enough
		numToRemove := len(d.banned) - d.config.EntriesSoftLimit

		if numToRemove <= 0 {
			return
		}

		sort.Sort(kvList)

		for idx, kv := range kvList {
			if idx >= numToRemove {
				break
			}

			delete(d.banned, kv.Key)
		}
	}
}

func (d *memoryDefender) cleanupHosts() {
	if len(d.hosts) > d.config.EntriesHardLimit {
		kvList := make(kvList, 0, len(d.hosts))

		for k, v := range d.hosts {
			value := int64(0)
			if len(v.Events) > 0 {
				value = v.Events[len(v.Events)-1].dateTime.UnixNano()
			}
			kvList = append(kvList, kv{
				Key:   k,
				Value: value,
			})
		}

		sort.Sort(kvList)

		numToRemove := len(d.hosts) - d.config.EntriesSoftLimit

		for idx, kv := range kvList {
			if idx >= numToRemove {
				break
			}

			delete(d.hosts, kv.Key)
		}
	}
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

type kv struct {
	Key   string
	Value int64
}

type kvList []kv

func (p kvList) Len() int           { return len(p) }
func (p kvList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p kvList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
