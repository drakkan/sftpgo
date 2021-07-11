package telemetry

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/metric"
)

func initializeRouter(enableProfiler bool) {
	router = chi.NewRouter()

	router.Use(middleware.GetHead)
	router.Use(middleware.Recoverer)

	router.Group(func(r chi.Router) {
		r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
			render.PlainText(w, r, "ok")
		})
	})

	router.Group(func(router chi.Router) {
		router.Use(checkAuth)
		metric.AddMetricsEndpoint(metricsPath, router)

		if enableProfiler {
			logger.InfoToConsole("enabling the built-in profiler")
			logger.Info(logSender, "", "enabling the built-in profiler")
			router.Mount(pprofBasePath, middleware.Profiler())
		}
	})
}

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateCredentials(r) {
			w.Header().Set(common.HTTPAuthenticationHeader, "Basic realm=\"SFTPGo telemetry\"")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateCredentials(r *http.Request) bool {
	if !httpAuth.IsEnabled() {
		return true
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return httpAuth.ValidateCredentials(username, password)
}
