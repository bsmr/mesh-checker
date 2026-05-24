package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func init() {
	register("user", "manage UI users: add|remove", runUser)
}

// passwordReader is overridable in tests.
var passwordReader = readPasswordFromTerminal

func readPasswordFromTerminal() (string, error) {
	fmt.Fprint(os.Stderr, "password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func runUser(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("user: missing subcommand (add|remove)")
	}
	switch args[0] {
	case "add":
		return runUserAdd(args[1:], stdout, stderr)
	case "remove":
		return runUserRemove(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("user: unknown subcommand %q", args[0])
	}
}

func runUserAdd(args []string, stdout, stderr io.Writer) error {
	// Allow positional <name> before flags.
	var name string
	var flagArgs []string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		name = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if name == "" {
		rest := fs.Args()
		if len(rest) != 1 {
			return errors.New("user add: usage: user add <name>")
		}
		name = rest[0]
	} else if len(fs.Args()) != 0 {
		return errors.New("user add: unexpected extra arguments")
	}
	pw, err := passwordReader()
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("user add: empty password not allowed")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for _, u := range c.UI.Users {
			if u.Name == name {
				return fmt.Errorf("user add: user %q already exists", name)
			}
		}
		c.UI.Users = append(c.UI.Users, config.User{Name: name, PasswordHash: string(hash)})
		fmt.Fprintf(stdout, "added user %s\n", name)
		return nil
	})
}

func runUserRemove(args []string, stdout, stderr io.Writer) error {
	var name string
	var flagArgs []string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		name = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("user remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if name == "" {
		rest := fs.Args()
		if len(rest) != 1 {
			return errors.New("user remove: usage: user remove <name>")
		}
		name = rest[0]
	} else if len(fs.Args()) != 0 {
		return errors.New("user remove: unexpected extra arguments")
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for i, u := range c.UI.Users {
			if u.Name == name {
				c.UI.Users = append(c.UI.Users[:i], c.UI.Users[i+1:]...)
				fmt.Fprintf(stdout, "removed user %s\n", name)
				return nil
			}
		}
		return fmt.Errorf("user remove: user %q not found", name)
	})
}
