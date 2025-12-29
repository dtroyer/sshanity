// sshanity/main.go
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"xr7.org/sshanity/server"
)

func main() {
	setupLogging("trace")

	SSHServer := server.SetupServer(server.SSHConfig{})
	SSHServer.RunServer()

	// Wait for a termination signal (e.g. Ctrl-C)
	cancelChan := make(chan os.Signal, 1)
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	<-cancelChan
}

func setupLogging(logLevel string) {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
	log.SetOutput(os.Stderr)

	var level log.Level
	err := level.UnmarshalText([]byte(logLevel))
	if err != nil {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
	}
}
