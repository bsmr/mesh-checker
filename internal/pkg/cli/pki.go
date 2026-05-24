package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func init() {
	register("pki", "PKI helpers: 'pki init' or 'pki cert <host>'", runPKI)
}

func runPKI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("pki: missing subcommand (init|cert)")
	}
	switch args[0] {
	case "init":
		return runPKIInit(args[1:], stdout, stderr)
	case "cert":
		return runPKICert(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("pki: unknown subcommand %q", args[0])
	}
}

func runPKIInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caCert := fs.String("ca-cert", "", "output path for the CA certificate (required)")
	caKey := fs.String("ca-key", "", "output path for the CA private key (required)")
	cn := fs.String("cn", "mesh-checker CA", "common name for the CA")
	lifetime := fs.Duration("lifetime", 10*365*24*time.Hour, "CA validity duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caCert == "" || *caKey == "" {
		return errors.New("pki init: --ca-cert and --ca-key are required")
	}
	ca, err := pki.GenerateCA(*cn, *lifetime)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := pki.Encode(ca)
	if err != nil {
		return err
	}
	if err := writeStrict(*caCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeStrict(*caKey, keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s and %s\n", *caCert, *caKey)
	return nil
}

func runPKICert(args []string, stdout, stderr io.Writer) error {
	// The host name may appear as the first positional argument before any
	// flags. Extract it so that flag.Parse can process the remaining args.
	var hostName string
	var flagArgs []string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		hostName = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("pki cert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caCert := fs.String("ca-cert", "", "path to CA certificate (required)")
	caKey := fs.String("ca-key", "", "path to CA private key (required)")
	outCert := fs.String("out-cert", "", "output path for host certificate (required)")
	outKey := fs.String("out-key", "", "output path for host private key (required)")
	var sans multiString
	fs.Var(&sans, "san", "additional SAN (DNS or IP). May be repeated.")
	lifetime := fs.Duration("lifetime", 365*24*time.Hour, "host cert validity")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	// Also accept host name as the sole trailing positional argument.
	if hostName == "" {
		rest := fs.Args()
		if len(rest) != 1 {
			return errors.New("pki cert: exactly one positional argument required (hostName)")
		}
		hostName = rest[0]
	} else if len(fs.Args()) != 0 {
		return errors.New("pki cert: unexpected extra arguments")
	}
	if *caCert == "" || *caKey == "" || *outCert == "" || *outKey == "" {
		return errors.New("pki cert: --ca-cert, --ca-key, --out-cert, --out-key are required")
	}
	caCertPEM, err := os.ReadFile(*caCert)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(*caKey)
	if err != nil {
		return err
	}
	ca, err := pki.Decode(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	host, err := pki.GenerateHostCert(ca, hostName, sans, *lifetime)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := pki.Encode(host)
	if err != nil {
		return err
	}
	if err := writeStrict(*outCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeStrict(*outKey, keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s and %s\n", *outCert, *outKey)
	return nil
}

func writeStrict(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

type multiString []string

func (m *multiString) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiString) Set(v string) error { *m = append(*m, v); return nil }
