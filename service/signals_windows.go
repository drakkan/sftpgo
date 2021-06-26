package service

import (
	"os"
	"os/signal"

	"github.com/drakkan/sftpgo/v2/logger"
)

func registerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			logger.Debug(logSender, "", "Received interrupt request")
			os.Exit(0)
		}
	}()
}
