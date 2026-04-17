package mcpserver

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ghostenv/ghostenv/internal/policy"
	"github.com/ghostenv/ghostenv/internal/runner"
	"github.com/ghostenv/ghostenv/internal/scrub"
	"github.com/ghostenv/ghostenv/internal/vault"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listInput struct{}
type runInput struct {
	Command string `json:"command" jsonschema_description:"The command to run with secrets injected. Must match an entry in the policy allowlist."`
}
type policiesInput struct{}
type policyAddInput struct {
	Command string   `json:"command" jsonschema_description:"The command pattern to allow, e.g. 'npm publish' or 'gh *'"`
	Inject  []string `json:"inject" jsonschema_description:"Secret key names to inject, or ['all'] for all secrets. Defaults to all if omitted."`
}
type policyRemoveInput struct {
	Command string `json:"command" jsonschema_description:"The exact command pattern to remove from the policy"`
}

// Run starts the MCP server over stdio.
func Run() error {
	// Disable helper so MCP server uses fallback keychain (no Touch ID in agent context)
	os.Setenv("GHOSTENV_NO_HELPER", "1")

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ghostenv",
		Version: "0.2.0",
	}, nil)

	// Tool: secrets_list — show key names and masked values (no real values)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_list",
		Description: "List all secret keys stored in the vault with their masked (fake) values. Real values are never shown.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input listInput) (*mcp.CallToolResult, any, error) {
		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		secrets := v.List()
		if len(secrets) == 0 {
			return textResult("Vault is empty."), nil, nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Vault: %d secrets\n\n", len(secrets)))
		for _, s := range secrets {
			sb.WriteString(fmt.Sprintf("  %-30s (set %s)\n", s.Key, s.Age))
		}
		return textResult(sb.String()), nil, nil
	})

	// Tool: secrets_run — run a command with scoped secrets (must match policy)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_run",
		Description: "Run a command with real secrets injected as environment variables. The command must match an entry in the policy allowlist (.ghostenv/policy.yaml). Only the secrets specified in the matching policy rule are injected. Output is scrubbed to remove any leaked secret values.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input runInput) (*mcp.CallToolResult, any, error) {
		if input.Command == "" {
			return errorResult("command is required"), nil, nil
		}

		args := strings.Fields(input.Command)
		if len(args) == 0 {
			return errorResult("command is required"), nil, nil
		}

		// Load vault
		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		// Load and enforce policy
		pol, err := policy.Load(v.Dir())
		if err != nil {
			return errorResult("could not load policy: " + err.Error()), nil, nil
		}

		if pol.IsEmpty() {
			return errorResult("no policy file found. Run 'ghostenv init' or create .ghostenv/policy.yaml"), nil, nil
		}

		rule, matched := pol.Match(args[0], args[1:])
		if !matched {
			return errorResult(fmt.Sprintf("command %q is not in the policy allowlist. Add it to .ghostenv/policy.yaml", args[0])), nil, nil
		}

		allSecrets := v.EnvMap()
		injected := rule.FilterSecrets(allSecrets)

		// Run the command with scoped secrets
		output, err := runner.RunCapture(args[0], args[1:], injected)

		// Scrub against ALL secrets, not just injected ones
		output = scrub.Output(output, allSecrets)

		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Command failed: %s\n\n%s", err.Error(), output)},
				},
				IsError: true,
			}, nil, nil
		}

		return textResult(output), nil, nil
	})

	// Tool: secrets_policies — list allowed commands
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_policies",
		Description: "List all commands that are allowed to receive secrets, as defined in .ghostenv/policy.yaml.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input policiesInput) (*mcp.CallToolResult, any, error) {
		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return errorResult("could not load policy: " + err.Error()), nil, nil
		}

		if pol.IsEmpty() {
			return textResult("No policy rules defined. Run 'ghostenv policy init' to generate one."), nil, nil
		}

		return textResult(pol.Format()), nil, nil
	})

	// Tool: secrets_policy_add — add a command to the policy allowlist
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_policy_add",
		Description: "Add a command to the policy allowlist so it can receive secrets via secrets_run. Shells and generic runtimes (bash, python, node, etc.) are blocked.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input policyAddInput) (*mcp.CallToolResult, any, error) {
		if input.Command == "" {
			return errorResult("command is required"), nil, nil
		}

		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return errorResult("could not load policy: " + err.Error()), nil, nil
		}

		inject := input.Inject
		if len(inject) == 0 {
			inject = []string{"all"}
		}

		if err := pol.Add(input.Command, inject); err != nil {
			return errorResult(err.Error()), nil, nil
		}

		if err := pol.Save(v.Dir()); err != nil {
			return errorResult("could not save policy: " + err.Error()), nil, nil
		}

		return textResult(fmt.Sprintf("Added policy rule: %s -> %s", input.Command, strings.Join(inject, ", "))), nil, nil
	})

	// Tool: secrets_policy_remove — remove a command from the policy allowlist
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_policy_remove",
		Description: "Remove a command from the policy allowlist.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input policyRemoveInput) (*mcp.CallToolResult, any, error) {
		if input.Command == "" {
			return errorResult("command is required"), nil, nil
		}

		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		pol, err := policy.Load(v.Dir())
		if err != nil {
			return errorResult("could not load policy: " + err.Error()), nil, nil
		}

		if !pol.Remove(input.Command) {
			return errorResult(fmt.Sprintf("no rule found for %q", input.Command)), nil, nil
		}

		if err := pol.Save(v.Dir()); err != nil {
			return errorResult("could not save policy: " + err.Error()), nil, nil
		}

		return textResult(fmt.Sprintf("Removed policy rule: %s", input.Command)), nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
	return nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Error: " + msg},
		},
		IsError: true,
	}
}
