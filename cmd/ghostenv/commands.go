package main

import (
	"fmt"
	"os"

	"github.com/ghostenv/ghostenv/internal/envfile"
	"github.com/ghostenv/ghostenv/internal/mask"
	"github.com/ghostenv/ghostenv/internal/runner"
	"github.com/ghostenv/ghostenv/internal/vault"

	"github.com/spf13/cobra"
)

var forceInit bool

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

		// Check if file is already masked
		maskedCount := 0
		for _, kv := range pairs {
			if mask.IsMasked(kv.Value) {
				maskedCount++
			}
		}
		if maskedCount == len(pairs) {
			return fmt.Errorf("%s is already masked. Nothing to import", path)
		}
		if maskedCount > 0 {
			fmt.Printf("Warning: %d of %d values look already masked, importing the rest.\n", maskedCount, len(pairs))
		}

		// Open or create vault
		var v *vault.Vault
		if vault.ExistsInCwd() && !forceInit {
			return fmt.Errorf("vault already exists. Use --force to reimport, or 'ghostenv set' to update individual secrets")
		}
		if vault.ExistsInCwd() && forceInit {
			v, err = vault.Open()
		} else {
			v, err = vault.Init()
		}
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		// Store each non-masked secret
		imported := 0
		for _, kv := range pairs {
			if !mask.IsMasked(kv.Value) {
				v.Set(kv.Key, kv.Value)
				imported++
			}
		}

		v.SetEnvFile(path)
		if err := v.Save(); err != nil {
			return fmt.Errorf("could not save vault: %w", err)
		}

		// Generate masked .env
		if err := regenMaskedEnv(v); err != nil {
			return fmt.Errorf("could not write masked env: %w", err)
		}

		// Add .ghostenv/ to .gitignore if not already there
		addToGitignore(".ghostenv/")

		fmt.Printf("Locked %d secrets from %s\n", imported, path)
		fmt.Println("Original values are now in the vault.")
		fmt.Println("The .env file now contains masked (fake) values.")
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&forceInit, "force", false, "Reimport even if vault already exists")
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "See what's stored in the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
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

		envFile := v.EnvFile()
		if envFile != "" {
			fmt.Printf("\nMasked env: %s\n", envFile)
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
			return err
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
			return err
		}

		v.Set(args[0], args[1])
		if err := v.Save(); err != nil {
			return fmt.Errorf("could not save vault: %w", err)
		}

		if err := regenMaskedEnv(v); err != nil {
			return fmt.Errorf("could not update masked env: %w", err)
		}

		fmt.Printf("Updated %s\n", args[0])
		return nil
	},
}

var removeCmd = &cobra.Command{
	Use:     "remove KEY",
	Aliases: []string{"rm"},
	Short:   "Remove a secret from the vault",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		key := args[0]
		if !v.Has(key) {
			return fmt.Errorf("secret %q not found", key)
		}

		v.Delete(key)
		if err := v.Save(); err != nil {
			return fmt.Errorf("could not save vault: %w", err)
		}

		if err := regenMaskedEnv(v); err != nil {
			return fmt.Errorf("could not update masked env: %w", err)
		}

		fmt.Printf("Removed %s\n", key)
		return nil
	},
}

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit all secrets in your editor",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		updated, err := v.EditInTerminal()
		if err != nil {
			return fmt.Errorf("edit failed: %w", err)
		}

		if updated {
			if err := regenMaskedEnv(v); err != nil {
				return fmt.Errorf("could not update masked env: %w", err)
			}
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
			return err
		}

		env := v.EnvMap()
		return runner.Exec(args[0], args[1:], env)
	},
}

var runCmd = &cobra.Command{
	Use:                "run COMMAND [ARGS...]",
	Short:              "Run a command with real secrets injected",
	Long:               "Shorthand for 'ghostenv exec'. Runs a command with real secrets as environment variables.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: ghostenv run COMMAND [ARGS...]")
		}

		v, err := vault.Open()
		if err != nil {
			return err
		}

		env := v.EnvMap()
		return runner.Exec(args[0], args[1:], env)
	},
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show differences between vault and masked .env",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		envFile := v.EnvFile()
		if envFile == "" {
			return fmt.Errorf("no .env file configured. Run 'ghostenv init' first")
		}

		// Parse current .env file
		filePairs, err := envfile.Parse(envFile)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", envFile, err)
		}

		fileKeys := make(map[string]bool)
		for _, kv := range filePairs {
			fileKeys[kv.Key] = true
		}

		vaultKeys := make(map[string]bool)
		for _, info := range v.List() {
			vaultKeys[info.Key] = true
		}

		changes := 0

		// Keys in vault but not in .env
		for key := range vaultKeys {
			if !fileKeys[key] {
				fmt.Printf("  + %-30s (in vault, missing from %s)\n", key, envFile)
				changes++
			}
		}

		// Keys in .env but not in vault
		for _, kv := range filePairs {
			if !vaultKeys[kv.Key] {
				fmt.Printf("  - %-30s (in %s, missing from vault)\n", kv.Key, envFile)
				changes++
			}
		}

		if changes == 0 {
			fmt.Println("Vault and masked .env are in sync.")
		} else {
			fmt.Printf("\n%d difference(s) found. Run 'ghostenv set' or 'ghostenv remove' to fix.\n", changes)
		}

		return nil
	},
}

// regenMaskedEnv regenerates the masked .env file from the current vault state.
func regenMaskedEnv(v *vault.Vault) error {
	envFile := v.EnvFile()
	if envFile == "" {
		return nil
	}

	pairs := v.Pairs()
	var kvs []envfile.KeyValue
	for _, p := range pairs {
		kvs = append(kvs, envfile.KeyValue{Key: p.Key, Value: p.Value})
	}

	masked := mask.Generate(v.MasterKey(), kvs)
	return os.WriteFile(envFile, []byte(masked), 0644)
}

// addToGitignore adds an entry to .gitignore if not already present.
func addToGitignore(entry string) {
	path := ".gitignore"
	content, err := os.ReadFile(path)
	if err != nil {
		// No .gitignore, create one
		os.WriteFile(path, []byte(entry+"\n"), 0644)
		return
	}

	// Check if already present
	lines := string(content)
	for _, line := range splitLines(lines) {
		if line == entry {
			return
		}
	}

	// Append
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	content = append(content, []byte(entry+"\n")...)
	os.WriteFile(path, content, 0644)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
