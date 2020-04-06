package cmd

import (
	"os"
	"os/user"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	defaultExitCode       = 1
	defaultProjectDirName = ".certron"
)

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

func defaultProjectDir() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}

	return path.Join(u.HomeDir, defaultProjectDirName)
}
