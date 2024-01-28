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

package dataprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yl2chen/cidranger"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	// maximum number of entries to match in memory
	// if the list contains more elements than this limit a
	// database query will be executed
	ipListMemoryLimit = 15000
)

var (
	inMemoryLists map[IPListType]*IPList
)

func init() {
	inMemoryLists = map[IPListType]*IPList{}
}

// IPListType is the enumerable for the supported IP list types
type IPListType int

// AsString returns the string representation for the list type
func (t IPListType) AsString() string {
	switch t {
	case IPListTypeAllowList:
		return "Allow list"
	case IPListTypeDefender:
		return "Defender"
	case IPListTypeRateLimiterSafeList:
		return "Rate limiters safe list"
	default:
		return ""
	}
}

// Supported IP list types
const (
	IPListTypeAllowList IPListType = iota + 1
	IPListTypeDefender
	IPListTypeRateLimiterSafeList
)

// Supported IP list modes
const (
	ListModeAllow = iota + 1
	ListModeDeny
)

const (
	ipTypeV4 = iota + 1
	ipTypeV6
)

var (
	supportedIPListType = []IPListType{IPListTypeAllowList, IPListTypeDefender, IPListTypeRateLimiterSafeList}
)

// CheckIPListType returns an error if the provided IP list type is not valid
func CheckIPListType(t IPListType) error {
	if !util.Contains(supportedIPListType, t) {
		return util.NewValidationError(fmt.Sprintf("invalid list type %d", t))
	}
	return nil
}

// IPListEntry defines an entry for the IP addresses list
type IPListEntry struct {
	IPOrNet     string     `json:"ipornet"`
	Description string     `json:"description,omitempty"`
	Type        IPListType `json:"type"`
	Mode        int        `json:"mode"`
	// Defines the protocols the entry applies to
	// - 0 all the supported protocols
	// - 1 SSH
	// - 2 FTP
	// - 4 WebDAV
	// - 8 HTTP
	// Protocols can be combined
	Protocols int    `json:"protocols"`
	First     []byte `json:"first,omitempty"`
	Last      []byte `json:"last,omitempty"`
	IPType    int    `json:"ip_type,omitempty"`
	// Creation time as unix timestamp in milliseconds
	CreatedAt int64 `json:"created_at"`
	// last update time as unix timestamp in milliseconds
	UpdatedAt int64 `json:"updated_at"`
	// in multi node setups we mark the rule as deleted to be able to update the cache
	DeletedAt int64 `json:"-"`
}

// PrepareForRendering prepares an IP list entry for rendering.
// It hides internal fields
func (e *IPListEntry) PrepareForRendering() {
	e.First = nil
	e.Last = nil
	e.IPType = 0
}

// HasProtocol returns true if the specified protocol is defined
func (e *IPListEntry) HasProtocol(proto string) bool {
	switch proto {
	case protocolSSH:
		return e.Protocols&1 != 0
	case protocolFTP:
		return e.Protocols&2 != 0
	case protocolWebDAV:
		return e.Protocols&4 != 0
	case protocolHTTP:
		return e.Protocols&8 != 0
	default:
		return false
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (e *IPListEntry) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		entry, err := provider.ipListEntryExists(e.IPOrNet, e.Type)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload IP list entry before rendering as json: %v", err)
			return nil, err
		}
		entry.PrepareForRendering()
		return json.Marshal(entry)
	}
	e.PrepareForRendering()
	return json.Marshal(e)
}

func (e *IPListEntry) getKey() string {
	return fmt.Sprintf("%d_%s", e.Type, e.IPOrNet)
}

func (e *IPListEntry) getName() string {
	return e.Type.AsString() + "-" + e.IPOrNet
}

func (e *IPListEntry) getFirst() netip.Addr {
	if e.IPType == ipTypeV4 {
		var a4 [4]byte
		copy(a4[:], e.First)
		return netip.AddrFrom4(a4)
	}
	var a16 [16]byte
	copy(a16[:], e.First)
	return netip.AddrFrom16(a16)
}

func (e *IPListEntry) getLast() netip.Addr {
	if e.IPType == ipTypeV4 {
		var a4 [4]byte
		copy(a4[:], e.Last)
		return netip.AddrFrom4(a4)
	}
	var a16 [16]byte
	copy(a16[:], e.Last)
	return netip.AddrFrom16(a16)
}

func (e *IPListEntry) checkProtocols() {
	for _, proto := range ValidProtocols {
		if !e.HasProtocol(proto) {
			return
		}
	}
	e.Protocols = 0
}

func (e *IPListEntry) validate() error {
	if err := CheckIPListType(e.Type); err != nil {
		return err
	}
	e.checkProtocols()
	switch e.Type {
	case IPListTypeDefender:
		if e.Mode < ListModeAllow || e.Mode > ListModeDeny {
			return util.NewValidationError(fmt.Sprintf("invalid list mode: %d", e.Mode))
		}
	default:
		if e.Mode != ListModeAllow {
			return util.NewValidationError("invalid list mode")
		}
	}
	e.PrepareForRendering()
	if !strings.Contains(e.IPOrNet, "/") {
		// parse as IP
		parsed, err := netip.ParseAddr(e.IPOrNet)
		if err != nil {
			return util.NewI18nError(util.NewValidationError(fmt.Sprintf("invalid IP %q", e.IPOrNet)), util.I18nErrorIPInvalid)
		}
		if parsed.Is4() {
			e.IPOrNet += "/32"
		} else if parsed.Is4In6() {
			e.IPOrNet = netip.AddrFrom4(parsed.As4()).String() + "/32"
		} else {
			e.IPOrNet += "/128"
		}
	}
	prefix, err := netip.ParsePrefix(e.IPOrNet)
	if err != nil {
		return util.NewI18nError(util.NewValidationError(fmt.Sprintf("invalid network %q: %v", e.IPOrNet, err)), util.I18nErrorNetInvalid)
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		e.IPOrNet = fmt.Sprintf("%s/%d", netip.AddrFrom4(prefix.Addr().As4()).String(), prefix.Bits()-96)
	}
	// TODO: to remove when the in memory ranger switch to netip
	_, _, err = net.ParseCIDR(e.IPOrNet)
	if err != nil {
		return util.NewI18nError(util.NewValidationError(fmt.Sprintf("invalid network: %v", err)), util.I18nErrorNetInvalid)
	}
	if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		e.IPType = ipTypeV4
		first := prefix.Addr().As4()
		last := util.GetLastIPForPrefix(prefix).As4()
		e.First = first[:]
		e.Last = last[:]
	} else {
		e.IPType = ipTypeV6
		first := prefix.Addr().As16()
		last := util.GetLastIPForPrefix(prefix).As16()
		e.First = first[:]
		e.Last = last[:]
	}
	return nil
}

func (e *IPListEntry) getACopy() IPListEntry {
	first := make([]byte, len(e.First))
	copy(first, e.First)
	last := make([]byte, len(e.Last))
	copy(last, e.Last)

	return IPListEntry{
		IPOrNet:     e.IPOrNet,
		Description: e.Description,
		Type:        e.Type,
		Mode:        e.Mode,
		First:       first,
		Last:        last,
		IPType:      e.IPType,
		Protocols:   e.Protocols,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
		DeletedAt:   e.DeletedAt,
	}
}

// getAsRangerEntry returns the entry as cidranger.RangerEntry
func (e *IPListEntry) getAsRangerEntry() (cidranger.RangerEntry, error) {
	_, network, err := net.ParseCIDR(e.IPOrNet)
	if err != nil {
		return nil, err
	}
	entry := e.getACopy()
	return &rangerEntry{
		entry:   &entry,
		network: *network,
	}, nil
}

func (e IPListEntry) satisfySearchConstraints(filter, from, order string) bool {
	if filter != "" && !strings.HasPrefix(e.IPOrNet, filter) {
		return false
	}
	if from != "" {
		if order == OrderASC {
			return e.IPOrNet > from
		}
		return e.IPOrNet < from
	}
	return true
}

type rangerEntry struct {
	entry   *IPListEntry
	network net.IPNet
}

func (e *rangerEntry) Network() net.IPNet {
	return e.network
}

// IPList defines an IP list
type IPList struct {
	isInMemory atomic.Bool
	listType   IPListType
	mu         sync.RWMutex
	Ranges     cidranger.Ranger
}

func (l *IPList) addEntry(e *IPListEntry) {
	if l.listType != e.Type {
		return
	}
	if !l.isInMemory.Load() {
		return
	}
	entry, err := e.getAsRangerEntry()
	if err != nil {
		providerLog(logger.LevelError, "unable to get entry to add %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.Ranges.Insert(entry); err != nil {
		providerLog(logger.LevelError, "unable to add entry %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
		return
	}
	if l.Ranges.Len() >= ipListMemoryLimit {
		providerLog(logger.LevelError, "memory limit exceeded for list type %d, disabling memory mode", l.listType)
		l.isInMemory.Store(false)
	}
}

func (l *IPList) removeEntry(e *IPListEntry) {
	if l.listType != e.Type {
		return
	}
	if !l.isInMemory.Load() {
		return
	}
	entry, err := e.getAsRangerEntry()
	if err != nil {
		providerLog(logger.LevelError, "unable to get entry to remove %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.Ranges.Remove(entry.Network()); err != nil {
		providerLog(logger.LevelError, "unable to remove entry %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
	}
}

func (l *IPList) updateEntry(e *IPListEntry) {
	if l.listType != e.Type {
		return
	}
	if !l.isInMemory.Load() {
		return
	}
	entry, err := e.getAsRangerEntry()
	if err != nil {
		providerLog(logger.LevelError, "unable to get entry to update %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.Ranges.Remove(entry.Network()); err != nil {
		providerLog(logger.LevelError, "unable to remove entry to update %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
		return
	}
	if err := l.Ranges.Insert(entry); err != nil {
		providerLog(logger.LevelError, "unable to add entry to update %q for list type %d, disabling memory mode, err: %v",
			e.IPOrNet, l.listType, err)
		l.isInMemory.Store(false)
	}
	if l.Ranges.Len() >= ipListMemoryLimit {
		providerLog(logger.LevelError, "memory limit exceeded for list type %d, disabling memory mode", l.listType)
		l.isInMemory.Store(false)
	}
}

// DisableMemoryMode disables memory mode forcing database queries
func (l *IPList) DisableMemoryMode() {
	l.isInMemory.Store(false)
}

// IsListed checks if there is a match for the specified IP and protocol.
// If there are multiple matches, the first one is returned, in no particular order,
// so the behavior is undefined
func (l *IPList) IsListed(ip, protocol string) (bool, int, error) {
	if l.isInMemory.Load() {
		l.mu.RLock()
		defer l.mu.RUnlock()

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false, 0, fmt.Errorf("invalid IP %s", ip)
		}

		entries, err := l.Ranges.ContainingNetworks(parsedIP)
		if err != nil {
			return false, 0, fmt.Errorf("unable to find containing networks for ip %q: %w", ip, err)
		}
		for _, e := range entries {
			entry, ok := e.(*rangerEntry)
			if ok {
				if entry.entry.Protocols == 0 || entry.entry.HasProtocol(protocol) {
					return true, entry.entry.Mode, nil
				}
			}
		}

		return false, 0, nil
	}

	entries, err := provider.getListEntriesForIP(ip, l.listType)
	if err != nil {
		return false, 0, err
	}
	for _, e := range entries {
		if e.Protocols == 0 || e.HasProtocol(protocol) {
			return true, e.Mode, nil
		}
	}

	return false, 0, nil
}

// NewIPList returns a new IP list for the specified type
func NewIPList(listType IPListType) (*IPList, error) {
	delete(inMemoryLists, listType)
	count, err := provider.countIPListEntries(listType)
	if err != nil {
		return nil, err
	}
	if count < ipListMemoryLimit {
		providerLog(logger.LevelInfo, "using in-memory matching for list type %d, num entries: %d", listType, count)
		entries, err := provider.getIPListEntries(listType, "", "", OrderASC, 0)
		if err != nil {
			return nil, err
		}
		ipList := &IPList{
			listType: listType,
			Ranges:   cidranger.NewPCTrieRanger(),
		}
		for idx := range entries {
			e := entries[idx]
			entry, err := e.getAsRangerEntry()
			if err != nil {
				return nil, fmt.Errorf("unable to get ranger for entry %q: %w", e.IPOrNet, err)
			}
			if err := ipList.Ranges.Insert(entry); err != nil {
				return nil, fmt.Errorf("unable to add ranger for entry %q: %w", e.IPOrNet, err)
			}
		}
		ipList.isInMemory.Store(true)
		inMemoryLists[listType] = ipList

		return ipList, nil
	}
	providerLog(logger.LevelInfo, "list type %d has %d entries, in-memory matching disabled", listType, count)
	ipList := &IPList{
		listType: listType,
		Ranges:   nil,
	}
	ipList.isInMemory.Store(false)
	return ipList, nil
}
