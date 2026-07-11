package main

import (
	"fmt"
	"os"

	"scimtest/internal/web"
)

func main() {
	command, debug, debugSecrets, help, err := parseArgs(os.Args[1:])
	if err != nil {
		mustWriteOutput(os.Stderr, "%v\n\n", err)
		usage(os.Stderr)
		os.Exit(2)
	}
	if help {
		usage(os.Stdout)
		return
	}
	switch command {
	case "", "web":
		if err := web.Run(web.RunOptions{Debug: debug, DebugSecrets: debugSecrets}); err != nil {
			mustWriteOutput(os.Stderr, "run web: %v\n", err)
			os.Exit(1)
		}
	default:
		mustWriteOutput(os.Stderr, "unknown subcommand %q\n\n", command)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func parseArgs(args []string) (string, bool, bool, bool, error) {
	var command string
	var debug bool
	var debugSecrets bool
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "help":
			return "", false, false, true, nil
		case "--debug":
			debug = true
		case "--debug-secrets":
			debug = true
			debugSecrets = true
		case "web":
			if command != "" {
				return "", false, false, false, fmt.Errorf("multiple commands provided")
			}
			command = arg
		default:
			return "", false, false, false, fmt.Errorf("unknown argument %q", arg)
		}
	}
	return command, debug, debugSecrets, false, nil
}

func usage(w *os.File) {
	mustWriteOutput(w, "Usage: scimtest [--debug] [web]\n")
	mustWriteOutput(w, "       scimtest web [--debug]\n\n")
	mustWriteOutput(w, "  (no args)  launch the web UI and auth endpoints on $PORT (default 8080)\n")
	mustWriteOutput(w, "  web        launch the web UI and auth endpoints on $PORT (default 8080)\n")
	mustWriteOutput(w, "  --debug    print OIDC/SAML RP requests and responses to stdout\n")
	mustWriteOutput(w, "  --debug-secrets  include credentials and tokens in debug output\n")
}

func mustWriteOutput(w *os.File, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		panic(fmt.Sprintf("write output: %v", err))
	}
}
