package main

import (
	"fmt"
	"os"

	"scimtest/internal/web"
)

func main() {
	command, debug, help, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n\n", err)
		usage(os.Stderr)
		os.Exit(2)
	}
	if help {
		usage(os.Stdout)
		return
	}
	switch command {
	case "", "web":
		if err := web.Run(web.RunOptions{Debug: debug}); err != nil {
			fmt.Fprintf(os.Stderr, "run web: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", command)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func parseArgs(args []string) (string, bool, bool, error) {
	var command string
	var debug bool
	for _, arg := range args {
		switch arg {
		case "-h", "--help", "help":
			return "", false, true, nil
		case "--debug":
			debug = true
		case "web":
			if command != "" {
				return "", false, false, fmt.Errorf("multiple commands provided")
			}
			command = arg
		default:
			return "", false, false, fmt.Errorf("unknown argument %q", arg)
		}
	}
	return command, debug, false, nil
}

func usage(w *os.File) {
	fmt.Fprintf(w, "Usage: scimtest [--debug] [web]\n")
	fmt.Fprintf(w, "       scimtest web [--debug]\n\n")
	fmt.Fprintf(w, "  (no args)  launch the web UI and auth endpoints on $PORT (default 8080)\n")
	fmt.Fprintf(w, "  web        launch the web UI and auth endpoints on $PORT (default 8080)\n")
	fmt.Fprintf(w, "  --debug    print OIDC/SAML RP requests and responses to stdout\n")
}
