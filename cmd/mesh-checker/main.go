// Command mesh-checker probes ICMP, TCP, and UDP reachability between mesh peers.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bsmr/mesh-checker/internal/pkg/cli"
)

func main() {
	if err := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
