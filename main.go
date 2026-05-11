package main

import (
	"fmt"
	"os"

	"scimtest/internal/web"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "web":
			if err := web.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "run web: %v\n", err)
				os.Exit(1)
			}
			return
		case "-h", "--help", "help":
			usage(os.Stdout)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", args[0])
			usage(os.Stderr)
			os.Exit(2)
		}
	}

	if err := web.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "run web: %v\n", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, "Usage: scimtest [web]\n\n")
	fmt.Fprintf(w, "  (no args)  launch the web UI and auth endpoints on $PORT (default 8080)\n")
	fmt.Fprintf(w, "  web        launch the web UI and auth endpoints on $PORT (default 8080)\n")
}
