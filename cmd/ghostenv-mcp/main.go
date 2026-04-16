package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghostenv/ghostenv/internal/runner"
	"github.com/ghostenv/ghostenv/internal/scrub"
	"github.com/ghostenv/ghostenv/internal/vault"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListMaskedInput struct{}

type ExecInput struct {
	Command string `json:"command" jsonschema_description:"The command to run with secrets injected"`
}

// Blocked commands — generic runtimes and shells that could leak secrets.
var blockedCommands = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true,
	"python": true, "python3": true, "node": true, "ruby": true,
	"perl": true, "env": true, "printenv": true, "export": true,
	"set": true, "echo": true, "cat": true,
}

func main() {
	// Disable helper so MCP server uses fallback keychain (no Touch ID in agent context)
	os.Setenv("GHOSTENV_NO_HELPER", "1")

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ghostenv",
		Version: "0.1.0",
	}, nil)

	// Tool: secrets_list — show key names (no real values)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_list",
		Description: "List all secret keys stored in the vault with their masked (fake) values. Real values are never shown.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListMaskedInput) (*mcp.CallToolResult, any, error) {
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

	// Tool: secrets_exec — run a command with all secrets injected, output scrubbed
	mcp.AddTool(server, &mcp.Tool{
		Name:        "secrets_exec",
		Description: "Run a command with real secrets injected as environment variables. Blocked commands (bash, python, env, etc.) are rejected. Output is scrubbed to remove any leaked secret values.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecInput) (*mcp.CallToolResult, any, error) {
		if input.Command == "" {
			return errorResult("command is required"), nil, nil
		}

		args := strings.Fields(input.Command)
		if len(args) == 0 {
			return errorResult("command is required"), nil, nil
		}

		// Block dangerous commands
		bin := filepath.Base(args[0])
		if blockedCommands[bin] {
			return errorResult(fmt.Sprintf("command %q is blocked — generic runtimes and shells cannot receive secrets", bin)), nil, nil
		}

		// Load vault
		v, err := vault.Open()
		if err != nil {
			return errorResult("could not open vault: " + err.Error()), nil, nil
		}

		secrets := v.EnvMap()

		// Run the command
		output, err := runner.RunCapture(args[0], args[1:], secrets)

		// Scrub output of any real secret values
		output = scrub.Output(output, secrets)

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

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
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
