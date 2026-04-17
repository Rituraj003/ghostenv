# ghostenv

Keep your secrets away from AI agents.

ghostenv locks your `.env` secrets in an encrypted vault and replaces them with masked (fake) values. AI agents can see what keys exist but never the real values. When you need to run a command that requires secrets, ghostenv injects them into only that process.

## How it works

1. Your real secrets get encrypted and stored in a per-project vault (`.ghostenv/`)
2. Your `.env` file gets replaced with fake values like `gv_YZXELQYXBPKJNIX2`
3. When you run a command through `ghostenv run`, real secrets are injected into that process only — they never touch your shell environment

## Install

**Homebrew** (macOS/Linux):
```bash
brew install Rituraj003/tap/ghostenv
```

**Binary release** (macOS/Linux/Windows):

Download from [GitHub Releases](https://github.com/Rituraj003/ghostenv/releases).

**From source:**
```bash
go install github.com/Rituraj003/ghostenv/cmd/ghostenv@latest
```

## Quick start

```bash
# Lock up your .env secrets
ghostenv init

# Your .env now contains masked values — safe for AI agents to read
cat .env
# OPENAI_API_KEY=gv_YZXELQYXBPKJNIX2
# GITHUB_TOKEN=gv_X73CCW5SRWTUU22C

# Run commands with real secrets injected
ghostenv run npm publish
ghostenv run gh pr create
```

## Commands

| Command | Description |
|---|---|
| `ghostenv init [file]` | Import secrets from a `.env` file into the vault |
| `ghostenv status` | Show stored keys and when they were set |
| `ghostenv show [key]` | View real secret values |
| `ghostenv set KEY VALUE` | Add or update a secret |
| `ghostenv edit` | Edit all secrets in your `$EDITOR` |
| `ghostenv remove KEY` | Remove a secret from the vault |
| `ghostenv run CMD` | Run a command with real secrets injected |
| `ghostenv run --all CMD` | Run a command, injecting all secrets (ignore policy) |
| `ghostenv restore` | Write real secrets back to `.env` (undo masking) |
| `ghostenv diff` | Show differences between vault and masked `.env` |
| `ghostenv exec -- CMD` | Same as `run`, with explicit `--` separator |
| `ghostenv policy show` | Show the current policy allowlist |
| `ghostenv policy init` | Generate a starter policy from installed tools |
| `ghostenv mcp` | Start the MCP server for AI agent integration |

## Shell completions

```bash
# Zsh
ghostenv completion zsh >> ~/.zshrc

# Bash
ghostenv completion bash >> ~/.bashrc

# Fish
ghostenv completion fish > ~/.config/fish/completions/ghostenv.fish
```

## Policy

ghostenv uses a policy file (`.ghostenv/policy.yaml`) to control which commands receive which secrets. A starter policy is auto-generated during `ghostenv init` based on tools found in your PATH.

```yaml
allow:
  - command: "npm publish"
    inject: [NPM_TOKEN]
  - command: "gh *"
    inject: [GITHUB_TOKEN]
  - command: "docker push *"
    inject: all
```

- **CLI**: `ghostenv run` uses the policy for per-secret scoping. If no rule matches, all secrets are injected with a warning. Use `--all` to bypass.
- **MCP server**: Strict enforcement. Commands not in the policy are rejected.

## Key storage

The vault master key is stored in the OS keychain (macOS) or via `secret-tool` (Linux). On Linux, if `secret-tool` is unavailable, ghostenv falls back to GPG automatically.

Force GPG with `GHOSTENV_BACKEND=gpg`. Set `GHOSTENV_GPG_KEY` to pick a specific GPG key.

## Security model

- Secrets are encrypted at rest with AES-256-GCM
- Master key never stored in plaintext
- `ghostenv run` injects secrets into the child process only — they disappear when the process exits
- Policy allowlist controls which commands can receive which secrets
- MCP server scrubs command output for leaked secrets (including base64/hex/URL-encoded forms)
- Process tree scanning blocks access when an AI agent is detected as a parent process
- Masked values are deterministic (stable across sessions) but not reversible
- Each project has its own isolated vault

## License

MIT
