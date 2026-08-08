package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/rselbach/scimtest/internal/web"
)

// version is injected by goreleaser; source builds fall back to Go module
// build info.
var version = ""

type cliOptions struct {
	command      string
	port         string
	debug        bool
	debugSecrets bool
	noOpen       bool
	stateFile    string
	help         bool
	version      bool
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		mustWriteOutput(os.Stderr, "%v\n\n", err)
		usage(os.Stderr)
		os.Exit(2)
	}
	if opts.help {
		usage(os.Stdout)
		return
	}
	if opts.version {
		mustWriteOutput(os.Stdout, "%s\n", versionString())
		return
	}
	if opts.stateFile != "" {
		if err := os.Setenv("SCIMTEST_STATE_FILE", opts.stateFile); err != nil {
			mustWriteOutput(os.Stderr, "set state file: %v\n", err)
			os.Exit(1)
		}
	}
	if err := web.Run(web.RunOptions{Debug: opts.debug, DebugSecrets: opts.debugSecrets, NoOpen: opts.noOpen, Port: opts.port}); err != nil {
		mustWriteOutput(os.Stderr, "run web: %v\n", err)
		os.Exit(1)
	}
}

func parseArgs(args []string) (cliOptions, error) {
	var opts cliOptions
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "web":
			opts.command = "web"
		case "version":
			return cliOptions{version: true}, nil
		case "help":
			return cliOptions{help: true}, nil
		default:
			return cliOptions{}, fmt.Errorf("unknown subcommand %q", args[0])
		}
		args = args[1:]
	}

	fs := flag.NewFlagSet("scimtest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.debug, "debug", false, "")
	fs.BoolVar(&opts.debugSecrets, "debug-secrets", false, "")
	fs.BoolVar(&opts.noOpen, "no-open", false, "")
	fs.BoolVar(&opts.version, "version", false, "")
	fs.StringVar(&opts.stateFile, "state-file", "", "")
	portValue := fs.String("port", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cliOptions{help: true}, nil
		}
		return cliOptions{}, err
	}
	if fs.NArg() > 0 {
		return cliOptions{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opts.debugSecrets {
		opts.debug = true
	}
	if *portValue != "" {
		if err := setPort(&opts, *portValue); err != nil {
			return cliOptions{}, err
		}
	}
	return opts, nil
}

func setPort(opts *cliOptions, value string) error {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q: must be an integer from 1 through 65535", value)
	}
	opts.port = strconv.Itoa(port)
	return nil
}

func versionString() string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "devel"
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "devel" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && len(setting.Value) >= 7 {
				return "scimtest " + v + " (" + setting.Value[:7] + ")"
			}
		}
	}
	return "scimtest " + v
}

func usage(w *os.File) {
	mustWriteOutput(w, "Usage: scimtest [web] [flags]\n")
	mustWriteOutput(w, "       scimtest version\n\n")
	mustWriteOutput(w, "Launches the scimtest admin UI and OIDC/SAML/SCIM test endpoints.\n\n")
	mustWriteOutput(w, "Flags (single or double dashes both work):\n")
	mustWriteOutput(w, "  --port N          require this exact admin port; without it, ports are\n")
	mustWriteOutput(w, "                    tried upward from the last used port or 8080\n")
	mustWriteOutput(w, "  --state-file PATH use an isolated SQLite state file (also runs a second\n")
	mustWriteOutput(w, "                    instance next to a running one)\n")
	mustWriteOutput(w, "  --debug           print OIDC/SAML RP traffic and ID token payloads\n")
	mustWriteOutput(w, "  --debug-secrets   include credentials and tokens in debug output\n")
	mustWriteOutput(w, "  --no-open         start without opening the admin UI in a browser\n")
	mustWriteOutput(w, "  --version         print the version and exit\n\n")
	mustWriteOutput(w, "Environment:\n")
	mustWriteOutput(w, "  SCIMTEST_PORT        same as --port\n")
	mustWriteOutput(w, "  SCIMTEST_STATE_FILE  same as --state-file\n")
	mustWriteOutput(w, "  PORT                 deprecated alias for SCIMTEST_PORT\n")
}

func mustWriteOutput(w *os.File, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		panic(fmt.Sprintf("write output: %v", err))
	}
}
