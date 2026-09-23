package main

import (
	"flag"

	evilfeed "evilgophish/shared/feed"
)

// feedMain runs the standalone live-feed dashboard server. It mirrors the
// behavior of the legacy evilfeed binary.
func feedMain(args []string) error {
	fs := flag.NewFlagSet("feed", flag.ExitOnError)
	listen := fs.String("listen", "localhost:1337", "feed server listen address")
	static := fs.String("static", "./app", "feed dashboard static directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv := evilfeed.NewServer(*listen, *static)
	return srv.Start()
}