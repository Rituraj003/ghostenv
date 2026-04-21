package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ghostenv/ghostenv/internal/envfile"
	"github.com/ghostenv/ghostenv/internal/guard"
	"github.com/ghostenv/ghostenv/internal/mask"
	"github.com/ghostenv/ghostenv/internal/policy"
	"github.com/ghostenv/ghostenv/internal/runner"
	"github.com/ghostenv/ghostenv/internal/scrub"
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
		if maskedCount == len(pairs) && !forceInit {
			return fmt.Errorf("%s is already masked. Nothing to import", path)
		}
		if maskedCount > 0 && !forceInit {
			fmt.Printf("Warning: %d of %d values look already masked, importing the rest.\n", maskedCount, len(pairs))
		}

		// Open or create vault
		var v *vault.Vault
		var oldSecrets map[string]string
		if vault.ExistsInCwd() && !forceInit {
			return fmt.Errorf("vault already exists. Use --force to reimport, or 'ghostenv set' to update individual secrets")
		}
		if vault.ExistsInCwd() && forceInit {
			// Preserve existing secrets before destroying
			if oldVault, err := vault.Open(); err == nil {
				oldSecrets = oldVault.EnvMap()
			}
			// Rename old vault aside, init new one, then clean up
			cwd, _ := os.Getwd()
			backupDir := cwd + "/.ghostenv.bak"
			os.Rename(cwd+"/.ghostenv", backupDir)
			v, err = vault.Init()
			if err != nil {
				// Restore old vault on failure
				os.Rename(backupDir, cwd+"/.ghostenv")
				return fmt.Errorf("could not reinitialize vault: %w", err)
			}
			os.RemoveAll(backupDir)
		} else {
			v, err = vault.Init()
		}
		if err != nil {
			return fmt.Errorf("could not open vault: %w", err)
		}

		// Restore old secrets first
		for key, val := range oldSecrets {
			v.Set(key, val)
		}

		// Import new non-masked secrets from .env (overrides old ones)
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

		// Generate starter policy if tools are detected
		starter := policy.GenerateStarter()
		if !starter.IsEmpty() {
			if err := starter.Save(v.Dir()); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write policy.yaml: %v\n", err)
			} else {
				fmt.Printf("Generated policy with %d rules (see .ghostenv/policy.yaml)\n", len(starter.Allow))
			}
		}

		// Add ghostenv instructions to agent config files
		addAgentInstructions()

		fmt.Printf("Locked %d secrets from %s\n", imported, path)
		fmt.Println("Original values are now in the vault.")
		fmt.Println("The .env file now contains masked (fake) values.")
		fmt.Println("\nNext steps:")
		fmt.Println("  ghostenv run <command>       Run a command with real secrets")
		fmt.Println("  ghostenv status              See stored keys and policy")
		fmt.Println("  ghostenv policy add <cmd>    Allow a command for AI agents")
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

		// Show policy summary
		pol, err := policy.Load(v.Dir())
		if err == nil && !pol.IsEmpty() {
			fmt.Printf("\nPolicy: %d rules\n", len(pol.Allow))
			fmt.Print(pol.Format())
		} else {
			fmt.Println("\nPolicy: none (agents cannot run commands until rules are added)")
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
		if err := guard.Confirm(); err != nil {
			return err
		}

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
		if err := guard.Confirm(); err != nil {
			return err
		}

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

		// Check for --all flag
		injectAll := false
		if len(args) > 0 && args[0] == "--all" {
			injectAll = true
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("usage: ghostenv exec -- COMMAND [ARGS...]")
		}

		return runWithSecrets(args[0], args[1:], injectAll)
	},
}

var runCmd = &cobra.Command{
	Use:                "run COMMAND [ARGS...]",
	Short:              "Run a command with real secrets injected",
	Long:               "Runs a command with real secrets as environment variables.\nUse --all to inject all secrets regardless of policy.\n\nWhen called from an AI agent, policy is strictly enforced and output is scrubbed.",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check for --all flag
		injectAll := false
		if len(args) > 0 && args[0] == "--all" {
			injectAll = true
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("usage: ghostenv run COMMAND [ARGS...]")
		}

		return runWithSecrets(args[0], args[1:], injectAll)
	},
}

// runWithSecrets handles both human and agent execution modes.
//
// Human mode: prompt for confirmation, loose policy (warn if no match), syscall.Exec
// Agent mode: no prompt, strict policy enforcement, capture + scrub output
func runWithSecrets(bin string, args []string, injectAll bool) error {
	agentMode := guard.IsAgent()

	if !agentMode {
		if err := guard.Confirm(); err != nil {
			return err
		}
	}

	v, err := vault.Open()
	if err != nil {
		return err
	}

	allSecrets := v.EnvMap()
	var injected map[string]string

	if agentMode {
		if injectAll {
			return fmt.Errorf("--all is not allowed when running from an AI agent")
		}
		injected, err = scopeSecrets(v, bin, args)
		if err != nil {
			return err
		}
	} else {
		injected = allSecrets
	}

	// Agent mode: capture output and scrub secrets
	if agentMode {
		output, runErr := runner.RunCapture(bin, args, injected)
		// Scrub against ALL secrets, not just injected ones
		output = scrub.Output(output, allSecrets)
		fmt.Print(output)
		if runErr != nil {
			return fmt.Errorf("command failed: %w", runErr)
		}
		return nil
	}

	// Human mode: replace process
	return runner.Exec(bin, args, injected)
}

// scopeSecrets enforces the policy allowlist (agent mode only).
// Returns an error if no policy exists or no rule matches.
func scopeSecrets(v *vault.Vault, bin string, args []string) (map[string]string, error) {
	pol, err := policy.Load(v.Dir())
	if err != nil || pol.IsEmpty() {
		return nil, fmt.Errorf("no policy file found. Run 'ghostenv init' or 'ghostenv policy add' to create one")
	}

	rule, matched := pol.Match(bin, args)
	if !matched {
		return nil, fmt.Errorf("command %q is not in the policy allowlist. Run: ghostenv policy add %q", bin, bin+" "+strings.Join(args, " "))
	}

	return rule.FilterSecrets(v.EnvMap()), nil
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

const ghostenvBlock = `
# ghostenv
.env values are masked (fake). Real secrets are in the encrypted vault.
Use ` + "`ghostenv run <command>`" + ` to run commands that need secrets.
Use ` + "`ghostenv policy add \"<command>\"`" + ` to allow new commands.
Do NOT edit .env directly — it is managed by ghostenv.
`

// agentFiles maps agent config files to check/create.
// Order matters: first existing file wins for the "created" message.
var agentFiles = []struct {
	path string
	name string
}{
	{"CLAUDE.md", "Claude Code"},
	{"AGENTS.md", "Codex"},
	{".cursorrules", "Cursor"},
	{".windsurfrules", "Windsurf"},
	{".github/copilot-instructions.md", "Copilot"},
}

// addAgentInstructions appends ghostenv instructions to all existing agent
// config files. If none exist, creates CLAUDE.md as the default.
func addAgentInstructions() {
	found := false
	for _, af := range agentFiles {
		content, err := os.ReadFile(af.path)
		if err != nil {
			continue
		}
		// Already has ghostenv block
		if strings.Contains(string(content), "# ghostenv") {
			found = true
			continue
		}
		// Append
		if len(content) > 0 && content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		content = append(content, []byte(ghostenvBlock)...)
		if err := os.WriteFile(af.path, content, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not update %s: %v\n", af.path, err)
			continue
		}
		fmt.Printf("Updated %s with ghostenv instructions\n", af.path)
		found = true
	}

	// No agent files found — create CLAUDE.md
	if !found {
		if err := os.WriteFile("CLAUDE.md", []byte(strings.TrimLeft(ghostenvBlock, "\n")), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create CLAUDE.md: %v\n", err)
			return
		}
		fmt.Println("Created CLAUDE.md with ghostenv instructions")
	}
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

var restoreStdout bool

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore real secrets to the .env file",
	Long:  "Writes real secret values back to the .env file, replacing the masked values.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := guard.Confirm(); err != nil {
			return err
		}

		v, err := vault.Open()
		if err != nil {
			return err
		}

		pairs := v.Pairs()
		var kvs []envfile.KeyValue
		for _, p := range pairs {
			kvs = append(kvs, envfile.KeyValue{Key: p.Key, Value: p.Value})
		}
		content := envfile.Format(kvs)

		if restoreStdout {
			fmt.Print(content)
			return nil
		}

		envFile := v.EnvFile()
		if envFile == "" {
			return fmt.Errorf("no .env file configured. Run 'ghostenv init' first")
		}

		if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
			return err
		}

		fmt.Printf("Restored %d secrets to %s\n", len(pairs), envFile)
		return nil
	},
}

func init() {
	restoreCmd.Flags().BoolVar(&restoreStdout, "stdout", false, "Print to stdout instead of writing to file")
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the secrets policy",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return fmt.Errorf("could not load policy: %w", err)
		}

		fmt.Print(pol.Format())
		return nil
	},
}

var policyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a starter policy based on installed tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		starter := policy.GenerateStarter()
		if starter.IsEmpty() {
			fmt.Println("No known tools detected in PATH. Create .ghostenv/policy.yaml manually.")
			return nil
		}

		if err := starter.Save(v.Dir()); err != nil {
			return fmt.Errorf("could not write policy: %w", err)
		}

		fmt.Printf("Generated policy with %d rules:\n", len(starter.Allow))
		fmt.Print(starter.Format())
		return nil
	},
}

var policyAddCmd = &cobra.Command{
	Use:   "add COMMAND [KEY...]",
	Short: "Add a command to the policy allowlist",
	Long:  "Adds a command pattern to the policy. Specify secret key names to inject, or omit for 'all'.\nExample: ghostenv policy add \"npm publish\" NPM_TOKEN",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		command := args[0]
		inject := []string{"all"}
		if len(args) > 1 {
			inject = args[1:]
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return fmt.Errorf("could not load policy: %w", err)
		}

		if err := pol.Add(command, inject); err != nil {
			return err
		}

		if err := pol.Save(v.Dir()); err != nil {
			return fmt.Errorf("could not save policy: %w", err)
		}

		fmt.Printf("Added: %s -> %s\n", command, strings.Join(inject, ", "))
		return nil
	},
}

var policyRemoveCmd = &cobra.Command{
	Use:   "remove COMMAND",
	Short: "Remove a command from the policy allowlist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := vault.Open()
		if err != nil {
			return err
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return fmt.Errorf("could not load policy: %w", err)
		}

		if !pol.Remove(args[0]) {
			return fmt.Errorf("no rule found for %q", args[0])
		}

		if err := pol.Save(v.Dir()); err != nil {
			return fmt.Errorf("could not save policy: %w", err)
		}

		fmt.Printf("Removed: %s\n", args[0])
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyInitCmd)
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyRemoveCmd)
}
