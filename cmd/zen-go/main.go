package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"
)

const version = "0.0.0"

func newCommand() *cli.Command {
	return &cli.Command{
		Name:    "zen-go",
		Usage:   "Aikido Zen CLI tool for Go",
		Suggest: true,
		Version: version,

		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize Aikido Firewall (creates orchestrion.tool.go)",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force overwrite existing orchestrion.tool.go file",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return initCommand(cmd.Root().Writer, cmd.Bool("force"))
				},
			},
		},
	}
}

func main() {
	cmd := newCommand()
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
