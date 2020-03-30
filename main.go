package main

import (
	"salzr.com/certron/cmd"
)

func main() {
	c, err := cmd.RootCommand()
	if err != nil {
		panic(err)
	}
	if err := c.Execute(); err != nil {
		panic(err)
	}
}
