package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ghostenv/ghostenv/internal/envfile"
	"github.com/ghostenv/ghostenv/internal/mask"
	"github.com/ghostenv/ghostenv/internal/runner"
	"github.com/ghostenv/ghostenv/internal/vault"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [envfile]",
	Short: "Lock up your .env secrets",
	Long:  "Imports secrets from a .env file into the encrypted vault and generates a masked .env in its place.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := ".env"
		if len(args) > 0 {
			path = args[0]
		}

		// Read the real .env
		pairs, err := envfile.Parse(path)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", path, err)
		}
		if len(pairs) == 0 {
			fmt.Println("No secrets found in", path)
			return nil
		}

		// Open or create vault
		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		// Store each secret
		for _, kv := range pairs {
			v.Set(kv.Key, kv.Value)
		}
		if err := v.Save(); err != nil {
			return fmt.Errorf("could not save vault: %w", err)
		}

		// Generate masked .env
		masked := mask.Generate(v.MasterKey(), pairs)
		if err := os.WriteFile(path, []byte(masked), 0644); err != nil {
			return fmt.Errorf("could not write masked %s: %w", path, err)
		}

		fmt.Printf("Locked %d secrets from %s\n", len(pairs), path)
		fmt.Println("Original values are now in the vault.")
		fmt.Println("The .env file now contains masked (fake) values.")
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "See what's stored in the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		secrets := v.List()
		if len(secrets) == 0 {
			fmt.Println("Vault is empty. Run 'ghostenv init' to import secrets.")
			return nil
		}

		fmt.Printf("Vault: %d secrets stored\n\n", len(secrets))
		for _, s := range secrets {
			fmt.Printf("  %-30s (set %s)\n", s.Key, s.Age)
		}
		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show [key]",
	Short: "View real secret values",
	Long:  "Shows real secret values. Specify a key to show one, or omit to show all.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		if len(args) == 1 {
			val, ok := v.Get(args[0])
			if !ok {
				return fmt.Errorf("secret %q not found", args[0])
			}
			fmt.Println(val)
			return nil
		}

		secrets := v.List()
		for _, s := range secrets {
			val, _ := v.Get(s.Key)
			fmt.Printf("%s=%s\n", s.Key, val)
		}
		return nil
	},
}

var setCmd = &cobra.Command{
	Use:   "set KEY VALUE",
	Short: "Add or update a secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		v.Set(args[0], args[1])
		if err := v.Save(); err != nil {
			return fmt.Errorf("could not save vault: %w", err)
		}

		fmt.Printf("Updated %s\n", args[0])
		return nil
	},
}

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit all secrets in your editor",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		updated, err := v.EditInTerminal()
		if err != nil {
			return fmt.Errorf("edit failed: %w", err)
		}

		if updated {
			fmt.Println("Secrets updated.")
		} else {
			fmt.Println("No changes.")
		}
		return nil
	},
}

var execCmd = &cobra.Command{
	Use:                "exec -- COMMAND [ARGS...]",
	Short:              "Run a command with real secrets injected",
	Long:               "Runs a command with the real secret values set as environment variables. Secrets only exist in the child process.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("usage: ghostenv exec -- COMMAND [ARGS...]")
		}

		v, err := vault.Open()
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		env := v.EnvMap()
		return runner.Exec(args[0], args[1:], env)
	},
}

// Helper to format key=value pairs for display
func formatEnvLine(key, value string) string {
	if strings.Contains(value, " ") || strings.Contains(value, "\"") {
		return fmt.Sprintf("%s=%q", key, value)
	}
	return fmt.Sprintf("%s=%s", key, value)
}
