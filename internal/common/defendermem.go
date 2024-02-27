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
	"sort"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type memoryDefender struct {
	baseDefender
	sync.RWMutex
	// IP addresses of the clients trying to connected are stored inside hosts,
	// they are added to banned once the thresold is reached.
	// A violation from a banned host will increase the ban time
	// based on the configured BanTimeIncrement
	hosts  map[string]hostScore // the key is the host IP
	banned map[string]time.Time // the key is the host IP
}

func newInMemoryDefender(config *DefenderConfig) (Defender, error) {
	err := config.validate()
	if err != nil {
		return nil, err
	}
	ipList, err := dataprovider.NewIPList(dataprovider.IPListTypeDefender)
	if err != nil {
		return nil, err
	}
	defender := &memoryDefender{
		baseDefender: baseDefender{
			config: config,
			ipList: ipList,
		},
		hosts:  make(map[string]hostScore),
		banned: make(map[string]time.Time),
	}

	return defender, nil
}

// GetHosts returns hosts that are banned or for which some violations have been detected
func (d *memoryDefender) GetHosts() ([]dataprovider.DefenderEntry, error) {
	d.RLock()
	defer d.RUnlock()

	var result []dataprovider.DefenderEntry
	for k, v := range d.banned {
		if v.After(time.Now()) {
			result = append(result, dataprovider.DefenderEntry{
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
			result = append(result, dataprovider.DefenderEntry{
				IP:    k,
				Score: score,
			})
		}
	}

	return result, nil
}

// GetHost returns a defender host by ip, if any
func (d *memoryDefender) GetHost(ip string) (dataprovider.DefenderEntry, error) {
	d.RLock()
	defer d.RUnlock()

	if banTime, ok := d.banned[ip]; ok {
		if banTime.After(time.Now()) {
			return dataprovider.DefenderEntry{
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
			return dataprovider.DefenderEntry{
				IP:    ip,
				Score: score,
			}, nil
		}
	}

	return dataprovider.DefenderEntry{}, util.NewRecordNotFoundError("host not found")
}

// IsBanned returns true if the specified IP is banned
// and increase ban time if the IP is found.
// This method must be called as soon as the client connects
func (d *memoryDefender) IsBanned(ip, protocol string) bool {
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

	return d.baseDefender.isBanned(ip, protocol)
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
// This method must be called for clients not yet banned.
// Returns true if the IP is in the defender's safe list.
func (d *memoryDefender) AddEvent(ip, protocol string, event HostEvent) bool {
	if d.IsSafe(ip, protocol) {
		return true
	}

	d.Lock()
	defer d.Unlock()

	// ignore events for already banned hosts
	if v, ok := d.banned[ip]; ok {
		if v.After(time.Now()) {
			return false
		}
		delete(d.banned, ip)
	}

	score := d.baseDefender.getScore(event)

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
		d.baseDefender.logEvent(ip, protocol, event, hs.TotalScore)

		hs.Events = hs.Events[:idx]
		if hs.TotalScore >= d.config.Threshold {
			d.baseDefender.logBan(ip, protocol)
			d.banned[ip] = time.Now().Add(time.Duration(d.config.BanTime) * time.Minute)
			delete(d.hosts, ip)
			d.cleanupBanned()
			eventManager.handleIPBlockedEvent(EventParams{
				Event:     ipBlockedEventName,
				IP:        ip,
				Timestamp: time.Now().UnixNano(),
				Status:    1,
			})
		} else {
			d.hosts[ip] = hs
		}
	} else {
		d.baseDefender.logEvent(ip, protocol, event, ev.score)
		d.hosts[ip] = hostScore{
			TotalScore: ev.score,
			Events:     []hostEvent{ev},
		}
		d.cleanupHosts()
	}
	return false
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
func (d *memoryDefender) GetBanTime(ip string) (*time.Time, error) {
	d.RLock()
	defer d.RUnlock()

	if banTime, ok := d.banned[ip]; ok {
		return &banTime, nil
	}

	return nil, nil
}

// GetScore returns the score for the given IP
func (d *memoryDefender) GetScore(ip string) (int, error) {
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

	return score, nil
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

type kv struct {
	Key   string
	Value int64
}

type kvList []kv

func (p kvList) Len() int           { return len(p) }
func (p kvList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p kvList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
