package common

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/drakkan/sftpgo/v2/util"
)

var (
	errNoBucket               = errors.New("no bucket found")
	errReserve                = errors.New("unable to reserve token")
	rateLimiterProtocolValues = []string{ProtocolSSH, ProtocolFTP, ProtocolWebDAV, ProtocolHTTP}
)

// RateLimiterType defines the supported rate limiters types
type RateLimiterType int

// Supported rate limiter types
const (
	rateLimiterTypeGlobal RateLimiterType = iota + 1
	rateLimiterTypeSource
)

// RateLimiterConfig defines the configuration for a rate limiter
type RateLimiterConfig struct {
	// Average defines the maximum rate allowed. 0 means disabled
	Average int64 `json:"average" mapstructure:"average"`
	// Period defines the period as milliseconds. Default: 1000 (1 second).
	// The rate is actually defined by dividing average by period.
	// So for a rate below 1 req/s, one needs to define a period larger than a second.
	Period int64 `json:"period" mapstructure:"period"`
	// Burst is the maximum number of requests allowed to go through in the
	// same arbitrarily small period of time. Default: 1.
	Burst int `json:"burst" mapstructure:"burst"`
	// Type defines the rate limiter type:
	// - rateLimiterTypeGlobal is a global rate limiter independent from the source
	// - rateLimiterTypeSource is a per-source rate limiter
	Type int `json:"type" mapstructure:"type"`
	// Protocols defines the protocols for this rate limiter.
	// Available protocols are: "SFTP", "FTP", "DAV".
	// A rate limiter with no protocols defined is disabled
	Protocols []string `json:"protocols" mapstructure:"protocols"`
	// AllowList defines a list of IP addresses and IP ranges excluded from rate limiting
	AllowList []string `json:"allow_list" mapstructure:"mapstructure"`
	// If the rate limit is exceeded, the defender is enabled, and this is a per-source limiter,
	// a new defender event will be generated
	GenerateDefenderEvents bool `json:"generate_defender_events" mapstructure:"generate_defender_events"`
	// The number of per-ip rate limiters kept in memory will vary between the
	// soft and hard limit
	EntriesSoftLimit int `json:"entries_soft_limit" mapstructure:"entries_soft_limit"`
	EntriesHardLimit int `json:"entries_hard_limit" mapstructure:"entries_hard_limit"`
}

func (r *RateLimiterConfig) isEnabled() bool {
	return r.Average > 0 && len(r.Protocols) > 0
}

func (r *RateLimiterConfig) validate() error {
	if r.Burst < 1 {
		return fmt.Errorf("invalid burst %v. It must be >= 1", r.Burst)
	}
	if r.Period < 100 {
		return fmt.Errorf("invalid period %v. It must be >= 100", r.Period)
	}
	if r.Type != int(rateLimiterTypeGlobal) && r.Type != int(rateLimiterTypeSource) {
		return fmt.Errorf("invalid type %v", r.Type)
	}
	if r.Type != int(rateLimiterTypeGlobal) {
		if r.EntriesSoftLimit <= 0 {
			return fmt.Errorf("invalid entries_soft_limit %v", r.EntriesSoftLimit)
		}
		if r.EntriesHardLimit <= r.EntriesSoftLimit {
			return fmt.Errorf("invalid entries_hard_limit %v must be > %v", r.EntriesHardLimit, r.EntriesSoftLimit)
		}
	}
	r.Protocols = util.RemoveDuplicates(r.Protocols)
	for _, protocol := range r.Protocols {
		if !util.IsStringInSlice(protocol, rateLimiterProtocolValues) {
			return fmt.Errorf("invalid protocol %#v", protocol)
		}
	}
	return nil
}

func (r *RateLimiterConfig) getLimiter() *rateLimiter {
	limiter := &rateLimiter{
		burst:                  r.Burst,
		globalBucket:           nil,
		generateDefenderEvents: r.GenerateDefenderEvents,
	}
	var maxDelay time.Duration
	period := time.Duration(r.Period) * time.Millisecond
	rtl := float64(r.Average*int64(time.Second)) / float64(period)
	limiter.rate = rate.Limit(rtl)
	if rtl < 1 {
		maxDelay = period / 2
	} else {
		maxDelay = time.Second / (time.Duration(rtl) * 2)
	}
	if maxDelay > 10*time.Second {
		maxDelay = 10 * time.Second
	}
	limiter.maxDelay = maxDelay
	limiter.buckets = sourceBuckets{
		buckets:   make(map[string]sourceRateLimiter),
		hardLimit: r.EntriesHardLimit,
		softLimit: r.EntriesSoftLimit,
	}
	if r.Type != int(rateLimiterTypeSource) {
		limiter.globalBucket = rate.NewLimiter(limiter.rate, limiter.burst)
	}
	return limiter
}

// RateLimiter defines a rate limiter
type rateLimiter struct {
	rate                   rate.Limit
	burst                  int
	maxDelay               time.Duration
	globalBucket           *rate.Limiter
	buckets                sourceBuckets
	generateDefenderEvents bool
	allowList              []func(net.IP) bool
}

// Wait blocks until the limit allows one event to happen
// or returns an error if the time to wait exceeds the max
// allowed delay
func (rl *rateLimiter) Wait(source string) (time.Duration, error) {
	if len(rl.allowList) > 0 {
		ip := net.ParseIP(source)
		if ip != nil {
			for idx := range rl.allowList {
				if rl.allowList[idx](ip) {
					return 0, nil
				}
			}
		}
	}
	var res *rate.Reservation
	if rl.globalBucket != nil {
		res = rl.globalBucket.Reserve()
	} else {
		var err error
		res, err = rl.buckets.reserve(source)
		if err != nil {
			rateLimiter := rate.NewLimiter(rl.rate, rl.burst)
			res = rl.buckets.addAndReserve(rateLimiter, source)
		}
	}
	if !res.OK() {
		return 0, errReserve
	}
	delay := res.Delay()
	if delay > rl.maxDelay {
		res.Cancel()
		if rl.generateDefenderEvents && rl.globalBucket == nil {
			AddDefenderEvent(source, HostEventLimitExceeded)
		}
		return delay, fmt.Errorf("rate limit exceed, wait time to respect rate %v, max wait time allowed %v", delay, rl.maxDelay)
	}
	time.Sleep(delay)
	return 0, nil
}

type sourceRateLimiter struct {
	lastActivity int64
	bucket       *rate.Limiter
}

func (s *sourceRateLimiter) updateLastActivity() {
	atomic.StoreInt64(&s.lastActivity, time.Now().UnixNano())
}

func (s *sourceRateLimiter) getLastActivity() int64 {
	return atomic.LoadInt64(&s.lastActivity)
}

type sourceBuckets struct {
	sync.RWMutex
	buckets   map[string]sourceRateLimiter
	hardLimit int
	softLimit int
}

func (b *sourceBuckets) reserve(source string) (*rate.Reservation, error) {
	b.RLock()
	defer b.RUnlock()

	if src, ok := b.buckets[source]; ok {
		src.updateLastActivity()
		return src.bucket.Reserve(), nil
	}

	return nil, errNoBucket
}

func (b *sourceBuckets) addAndReserve(r *rate.Limiter, source string) *rate.Reservation {
	b.Lock()
	defer b.Unlock()

	b.cleanup()

	src := sourceRateLimiter{
		bucket: r,
	}
	src.updateLastActivity()
	b.buckets[source] = src
	return src.bucket.Reserve()
}

func (b *sourceBuckets) cleanup() {
	if len(b.buckets) >= b.hardLimit {
		numToRemove := len(b.buckets) - b.softLimit

		kvList := make(kvList, 0, len(b.buckets))

		for k, v := range b.buckets {
			kvList = append(kvList, kv{
				Key:   k,
				Value: v.getLastActivity(),
			})
		}

		sort.Sort(kvList)

		for idx, kv := range kvList {
			if idx >= numToRemove {
				break
			}

			delete(b.buckets, kv.Key)
		}
	}
}
