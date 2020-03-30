package cmd

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const defaultExitCode = 1

func init() {
	log.SetOutput(os.Stdout)
}

func handleErr(e error) {
	if e != nil {
		msg := e.Error()
		if !strings.HasSuffix(msg, "\n") {
			msg = msg + "\n"
		}
		log.Error(msg)
		os.Exit(defaultExitCode)
	}
}
