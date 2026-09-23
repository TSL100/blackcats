// Command evilfeed runs the standalone live-feed dashboard server.
//
// It is a thin wrapper over evilgophish/shared/feed so the standalone binary
// behaves exactly as before while sharing a single hub/server implementation
// with the unified evilgophish application.
package main

import (
	"evilgophish/shared/feed"
)

func main() {
	srv := feed.NewServer("localhost:1337", "./app")
	err := srv.Start()
	// Historical behavior: no diagnostics, the process simply exits (e.g.
	// when the port is already taken).
	_ = err
}