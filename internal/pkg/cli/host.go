package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func init() {
	register("host", "manage peer hosts: add|remove|list", runHost)
}

func runHost(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("host: missing subcommand (add|remove|list)")
	}
	switch args[0] {
	case "add":
		return runHostAdd(args[1:], stdout, stderr)
	case "remove":
		return runHostRemove(args[1:], stdout, stderr)
	case "list":
		return runHostList(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("host: unknown subcommand %q", args[0])
	}
}

func runHostAdd(args []string, stdout, stderr io.Writer) error {
	// Extract positional (name, addr) before the flags, mirroring pki cert.
	var name, addr string
	var flagArgs []string
	i := 0
	for ; i < len(args) && len(args[i]) > 0 && args[i][0] != '-'; i++ {
	}
	if i >= 2 {
		name = args[0]
		addr = args[1]
		flagArgs = args[2:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("host add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	var checks multiString
	fs.Var(&checks, "check", "enable check (icmp|tcp|udp|https); may repeat. Default: all four.")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if name == "" || addr == "" {
		rest := fs.Args()
		if len(rest) != 2 {
			return errors.New("host add: usage: host add <name> <addr>")
		}
		name, addr = rest[0], rest[1]
	} else if len(fs.Args()) != 0 {
		return errors.New("host add: unexpected extra arguments")
	}
	if len(checks) == 0 {
		checks = []string{"icmp", "tcp", "udp", "https"}
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for _, p := range c.Peers {
			if p.Name == name {
				return fmt.Errorf("host add: peer %q already exists", name)
			}
		}
		c.Peers = append(c.Peers, config.Peer{Name: name, Addr: addr, Checks: checks})
		fmt.Fprintf(stdout, "added peer %s (%s)\n", name, addr)
		return nil
	})
}

func runHostRemove(args []string, stdout, stderr io.Writer) error {
	var name string
	var flagArgs []string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		name = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("host remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if name == "" {
		rest := fs.Args()
		if len(rest) != 1 {
			return errors.New("host remove: usage: host remove <name>")
		}
		name = rest[0]
	} else if len(fs.Args()) != 0 {
		return errors.New("host remove: unexpected extra arguments")
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for i, p := range c.Peers {
			if p.Name == name {
				c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
				fmt.Fprintf(stdout, "removed peer %s\n", name)
				return nil
			}
		}
		return fmt.Errorf("host remove: peer %q not found", name)
	})
}

func runHostList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("host list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDR\tCHECKS")
	for _, p := range cfg.Peers {
		fmt.Fprintf(tw, "%s\t%s\t%v\n", p.Name, p.Addr, p.Checks)
	}
	return tw.Flush()
}
