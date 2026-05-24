package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
)

func init() {
	register("status", "show mesh status table", runStatus)
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(cfg.PKI.CACertPath)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	tlsCert, err := tls.LoadX509KeyPair(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	if err != nil {
		return err
	}

	_, ihPort, err := net.SplitHostPort(cfg.Listeners.InterHost.Addr)
	if err != nil {
		return err
	}
	urls := map[string]string{cfg.Host.Name: "https://" + net.JoinHostPort(cfg.Host.AdvertiseAddr, ihPort)}
	for _, p := range cfg.Peers {
		urls[p.Name] = "https://" + net.JoinHostPort(p.Addr, ihPort)
	}
	cl := interhost.NewClient(caPool, tlsCert, urls)

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tREACHABLE\tDETAIL")
	for name := range urls {
		ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
		v, err := cl.Fetch(ctx2, name)
		cancel()
		if err != nil {
			fmt.Fprintf(tw, "%s\tno\t%s\n", name, err.Error())
			continue
		}
		fmt.Fprintf(tw, "%s\tyes\t%d peers known\n", v.Host, len(v.Samples))
	}
	return tw.Flush()
}
