package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	fsmetaPostgresCacheHit = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_fsmeta_postgres_cache_hit",
		Help: "The FSMeta PostgreSQL cache was available.",
	})
	fsmetaPostgresCacheMiss = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_fsmeta_postgres_cache_miss",
		Help: "The FSMeta PostgreSQL cache was not available.",
	})
	fsmetaPostgresCacheInvalid = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_fsmeta_postgres_cache_invalid",
		Help: "The FSMeta PostgreSQL cache was invalid.",
	})
	fsmetaPostgresSelfHealSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_fsmeta_postgres_self_heal_success",
		Help: "The FSMeta PostgreSQL cache was self healed successfully.",
	})
	fsmetaPostgresSelfHealFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_fsmeta_postgres_self_heal_failed",
		Help: "The FSMeta PostgreSQL cache failed to heal property.",
	})
)

func FSMetaPostgresCache(err error) {
	if err == nil {
		fsmetaPostgresCacheHit.Inc()
	} else if err.Error() == `fsmeta: Get(cache miss)` {
		fsmetaPostgresCacheMiss.Inc()
	} else if err.Error() == `fsmeta: Get(cached key invalid)` {
		fsmetaPostgresCacheInvalid.Inc()
	}
}

func FSMetaPostgresSelfHeal(err error) {
	if err == nil {
		fsmetaPostgresSelfHealSuccess.Inc()
	} else {
		fsmetaPostgresSelfHealFailed.Inc()
	}
}
