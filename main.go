package main

import (
	"os"

	"github.com/urfave/cli"

	"github.com/mitchellh/go-homedir"
)

var jayPath string

func init() {
	var err error
	jayPath, err = homedir.Expand("~/.jay")
	check(err)
}

func main() {
	app := cli.NewApp()
	app.Name = "jay"
	app.Usage = "A journal for the paranoid"
	app.Action = handleAddAction

	app.Commands = []cli.Command{
		{
			Name:   "init",
			Usage:  "initialize Jay",
			Action: handleInitAction,
		},
		{
			Name:   "add",
			Usage:  "add an entry",
			Action: handleAddAction,
		},
		{
			Name:   "read",
			Usage:  "read entries",
			Action: handleReadAction,
		},
	}

	err := app.Run(os.Args)
	check(err)
}
