// Package telemetry provides telemetry information for SFTPGo, such as:
//		- health information (for health checks)
//		- metrics
// 		- profiling information
package telemetry

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"

	"github.com/drakkan/sftpgo/logger"
)

const (
	logSender     = "telemetry"
	metricsPath   = "/metrics"
	pprofBasePath = "/debug"
)

var (
	router *chi.Mux
)

// Conf telemetry server configuration.
type Conf struct {
	// The port used for serving HTTP requests. 0 disable the HTTP server. Default: 10000
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces. Default: "127.0.0.1"
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
}

// Initialize configures and starts the telemetry server.
func (c Conf) Initialize(enableProfiler bool) error {
	logger.Debug(logSender, "", "initializing telemetry server with config %+v", c)
	initializeRouter(enableProfiler)
	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort),
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 14, // 16KB
	}
	return httpServer.ListenAndServe()
}
