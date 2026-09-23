// Command evilgophish is the unified gophish + evilginx2 + live-feed
// application: one binary, one configuration, one GUI.
//
// Subcommands:
//
//	serve        run the unified application (admin GUI + proxy engine +
//	             feed server)
//	feed         run the standalone live-feed dashboard server
//	version      print the evilgophish version
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serveMain(os.Args[2:])
	case "feed":
		err = feedMain(os.Args[2:])
	case "version":
		fmt.Printf("evilgophish %s\n", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: evilgophish <command> [args]

commands:
  serve       run the unified application (gophish GUI + proxy engine + feed server)
  feed        run the standalone live-feed dashboard server
  version     print the evilgophish version`)
}