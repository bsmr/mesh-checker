package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/config"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	httpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/http"
	icmpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/icmp"
	tcpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/tcp"
	udpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
	"github.com/bsmr/mesh-checker/internal/pkg/recoverwrap"
	"github.com/bsmr/mesh-checker/internal/pkg/scheduler"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
	serverprobe "github.com/bsmr/mesh-checker/internal/pkg/server/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/server/ui"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

func init() {
	register("serve", "run daemon + all three listeners", runServe)
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := config.CheckMode(*cfgPath); err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, err := config.ValidateWithWarnings(cfg); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caPEM, err := os.ReadFile(cfg.PKI.CACertPath)
	if err != nil {
		return fmt.Errorf("serve: read CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return errors.New("serve: CA bundle has no certs")
	}
	hostTLSCert, err := tls.LoadX509KeyPair(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	if err != nil {
		return fmt.Errorf("serve: load host cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(hostTLSCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("serve: parse host cert leaf: %w", err)
	}
	if leaf.Subject.CommonName != cfg.Host.Name {
		return fmt.Errorf("serve: host.name %q does not match host cert CN %q",
			cfg.Host.Name, leaf.Subject.CommonName)
	}

	udpSecret, err := base64.StdEncoding.DecodeString(cfg.Probe.UDPSharedSecret)
	if err != nil {
		return fmt.Errorf("serve: decode udp secret: %w", err)
	}
	sessionSecret, err := base64.StdEncoding.DecodeString(cfg.UI.SessionSecret)
	if err != nil {
		return err
	}

	st := store.New(cfg.Probe.RingbufferSize)

	probers := mustProbers(caPool, udpSecret, cfg)
	jobs := buildJobs(cfg, probers)

	sched := scheduler.New(scheduler.Config{
		Interval:      time.Duration(cfg.Probe.IntervalSeconds) * time.Second,
		JitterPercent: cfg.Probe.JitterPercent,
		Workers:       maxInt(2*len(jobs), 4),
		Timeout:       time.Duration(cfg.Probe.TimeoutSeconds) * time.Second,
	}, jobs, st)

	_, ihPort, err := net.SplitHostPort(cfg.Listeners.InterHost.Addr)
	if err != nil {
		return fmt.Errorf("serve: parse interhost addr: %w", err)
	}
	peerNames := map[string]bool{cfg.Host.Name: true}
	peerURLs := map[string]string{cfg.Host.Name: "https://" + net.JoinHostPort(cfg.Host.AdvertiseAddr, ihPort)}
	for _, p := range cfg.Peers {
		peerNames[p.Name] = true
		peerURLs[p.Name] = "https://" + net.JoinHostPort(p.Addr, ihPort)
	}
	cl := interhost.NewClient(caPool, hostTLSCert, peerURLs)

	agg := aggregator.New(cl, st, cfg.Host.Name, peerNamesList(cfg), cfg.Probe.FailureWindow, cfg.Probe.FailureThreshold, 2*time.Second)

	ihMux := interhost.NewMux(interhost.Deps{
		MeshCA: caPool, HostCert: hostTLSCert, Peers: peerNames,
		FetchLocal: func() aggregator.ObserverView { return agg.LocalView() },
	})
	ihServer := &http.Server{Addr: cfg.Listeners.InterHost.Addr, Handler: ihMux, TLSConfig: interhost.ServerTLSConfig(hostTLSCert, caPool)}

	sess := ui.NewSession(sessionSecret, time.Duration(cfg.UI.SessionTTLSeconds)*time.Second)
	loginH := ui.NewLoginHandler(cfg.UI.Users, sess, 250*time.Millisecond)
	sseH := ui.NewSSEHandler(agg, time.Second)
	uiMux := ui.NewMux(ui.Deps{Login: loginH, SSE: sseH, Session: sess})
	uiServer := &http.Server{Addr: cfg.Listeners.UI.Addr, Handler: uiMux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{hostTLSCert}, MinVersion: tls.VersionTLS12}}

	probeServer := &http.Server{Addr: cfg.Listeners.Probe.HTTPAddr, Handler: serverprobe.NewHTTPHandler()}

	allowed := map[string]bool{}
	for _, p := range cfg.Peers {
		allowed[p.Addr] = true
	}
	udpEcho, err := serverprobe.NewUDPEcho(cfg.Listeners.Probe.UDPAddr, udpSecret, allowed)
	if err != nil {
		return err
	}

	errCh := make(chan error, 4)
	recoverwrap.Go("listener.interhost", func() {
		errCh <- ihServer.ListenAndServeTLS(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	})
	recoverwrap.Go("listener.ui", func() {
		errCh <- uiServer.ListenAndServeTLS(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	})
	recoverwrap.Go("listener.probe", func() {
		errCh <- probeServer.ListenAndServe()
	})
	recoverwrap.Go("listener.udp-echo", func() {
		udpEcho.Run()
		errCh <- nil
	})
	recoverwrap.Go("scheduler.run", func() {
		sched.Run(ctx)
	})

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ihServer.Shutdown(shutdownCtx)
	_ = uiServer.Shutdown(shutdownCtx)
	_ = probeServer.Shutdown(shutdownCtx)
	_ = udpEcho.Close()
	return nil
}

func mustProbers(caPool *x509.CertPool, udpSecret []byte, cfg *config.Config) map[probe.Protocol]probe.Prober {
	timeout := time.Duration(cfg.Probe.TimeoutSeconds) * time.Second
	pr := map[probe.Protocol]probe.Prober{
		probe.TCP:   tcpprobe.New(timeout),
		probe.HTTPS: httpprobe.New(caPool, timeout),
		probe.UDP:   udpprobe.New(udpSecret, cfg.Host.Name, timeout),
	}
	icmpP, err := icmpprobe.New(timeout)
	if err != nil {
		slog.Warn("icmp prober unavailable; icmp checks will be skipped", "err", err)
	} else {
		pr[probe.ICMP] = icmpP
	}
	return pr
}

func buildJobs(cfg *config.Config, pr map[probe.Protocol]probe.Prober) []scheduler.Job {
	var jobs []scheduler.Job
	for _, p := range cfg.Peers {
		target := probe.Target{Name: p.Name, Addr: p.Addr, TCPPort: p.TCPPort, UDPPort: p.UDPPort, HTTPSURL: p.HTTPSURL}
		for _, ch := range p.Checks {
			pp := probe.Protocol(ch)
			prober, ok := pr[pp]
			if !ok {
				continue
			}
			jobs = append(jobs, scheduler.Job{Peer: p.Name, Protocol: pp, Target: target, Prober: prober})
		}
	}
	return jobs
}

func peerNamesList(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		out = append(out, p.Name)
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
