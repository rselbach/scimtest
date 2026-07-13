package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"scimtest/internal/web"
)

type cliOptions struct {
	command      string
	port         string
	debug        bool
	debugSecrets bool
	noOpen       bool
	help         bool
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
	switch opts.command {
	case "", "web":
		if err := web.Run(web.RunOptions{Debug: opts.debug, DebugSecrets: opts.debugSecrets, NoOpen: opts.noOpen, Port: opts.port}); err != nil {
			mustWriteOutput(os.Stderr, "run web: %v\n", err)
			os.Exit(1)
		}
	default:
		mustWriteOutput(os.Stderr, "unknown subcommand %q\n\n", opts.command)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func parseArgs(args []string) (cliOptions, error) {
	var opts cliOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "help":
			return cliOptions{help: true}, nil
		case arg == "--debug":
			opts.debug = true
		case arg == "--debug-secrets":
			opts.debug = true
			opts.debugSecrets = true
		case arg == "--no-open":
			opts.noOpen = true
		case arg == "--port":
			if i+1 >= len(args) {
				return cliOptions{}, fmt.Errorf("--port requires a value")
			}
			i++
			if err := setPort(&opts, args[i]); err != nil {
				return cliOptions{}, err
			}
		case strings.HasPrefix(arg, "--port="):
			if err := setPort(&opts, strings.TrimPrefix(arg, "--port=")); err != nil {
				return cliOptions{}, err
			}
		case arg == "web":
			if opts.command != "" {
				return cliOptions{}, fmt.Errorf("multiple commands provided")
			}
			opts.command = arg
		default:
			return cliOptions{}, fmt.Errorf("unknown argument %q", arg)
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

func usage(w *os.File) {
	mustWriteOutput(w, "Usage: scimtest [--debug] [--no-open] [--port N] [web]\n")
	mustWriteOutput(w, "       scimtest web [--debug] [--no-open] [--port N]\n\n")
	mustWriteOutput(w, "  (no args)  launch the web UI and auth endpoints (default port 8080)\n")
	mustWriteOutput(w, "  web        launch the web UI and auth endpoints (default port 8080)\n")
	mustWriteOutput(w, "  --port N   require this exact admin port (overrides $PORT; no fallback)\n")
	mustWriteOutput(w, "  --debug    print OIDC/SAML RP requests and responses to stdout\n")
	mustWriteOutput(w, "  --debug-secrets  include credentials and tokens in debug output\n")
	mustWriteOutput(w, "  --no-open  start without opening the admin UI in a browser\n\n")
	mustWriteOutput(w, "  $PORT      same as --port; without either, ports are tried upward from 8080\n")
}

func mustWriteOutput(w *os.File, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		panic(fmt.Sprintf("write output: %v", err))
	}
}
