package main

import (
	"github.com/spf13/viper"
	"salzr.com/certron/cmd"
)

func main() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("certron")

	c, err := cmd.RootCommand()
	if err != nil {
		panic(err)
	}

	if err := c.Execute(); err != nil {
		panic(err)
	}
}
