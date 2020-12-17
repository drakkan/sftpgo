package telemetry

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/metrics"
)

func initializeRouter(enableProfiler bool) {
	router = chi.NewRouter()

	router.Use(middleware.Recoverer)

	router.Group(func(r chi.Router) {
		r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, "ok")
		})
	})

	metrics.AddMetricsEndpoint(metricsPath, router)

	if enableProfiler {
		logger.InfoToConsole("enabling the built-in profiler")
		logger.Info(logSender, "", "enabling the built-in profiler")
		router.Mount(pprofBasePath, middleware.Profiler())
	}
}
