package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"

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
			{
				Name:            "toolexec",
				SkipFlagParsing: true,
				Action: func(ctx context.Context, cmd *cli.Command) error {
					args := cmd.Args().Slice()
					if len(args) == 0 {
						return fmt.Errorf("no tool specified")
					}

					tool := args[0]
					toolArgs := args[1:]
					toolName := filepath.Base(tool)

					out := io.Writer(os.Stdout)
					outErr := io.Writer(os.Stderr)

					if logPath := os.Getenv("ZENGO_LOG"); logPath != "" {
						// #nosec G304 - logPath is from environment variable set by user
						logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
						if err != nil {
							return err
						}
						defer func() {
							if err := logFile.Close(); err != nil {
								fmt.Fprintf(os.Stderr, "failed to close log file: %v\n", err)
							}
						}()

						out = io.MultiWriter(os.Stdout, logFile)
						outErr = io.MultiWriter(os.Stderr, logFile)
					}

					switch toolName {
					case "compile":
						return toolexecCompileCommand(out, outErr, tool, toolArgs)
					case "link":
						return toolexecLinkCommand(out, outErr, tool, toolArgs)
					default:
						return passthrough(tool, toolArgs)
					}
				},
			},
		},
	}
}

func main() {
	cmd := newCommand()
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// For toolexec, preserve exit codes from tools
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		log.Fatal(err)
	}
}

func isDebug() bool {
	return os.Getenv("ZENGO_DEBUG") != ""
}
