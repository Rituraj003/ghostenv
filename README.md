# ghostenv

Keep your secrets away from AI agents.

ghostenv locks your `.env` secrets in an encrypted vault and replaces them with masked (fake) values. AI agents can see what keys exist but never the real values. When you need to run a command that requires secrets, ghostenv injects them into only that process.

## How it works

1. Your real secrets get encrypted and stored in a per-project vault (`.ghostenv/`)
2. Your `.env` file gets replaced with fake values like `gv_YZXELQYXBPKJNIX2`
3. When you run a command through `ghostenv run`, real secrets are injected into that process only — they never touch your shell environment
4. AI agents are auto-detected — they get strict policy enforcement and scrubbed output

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

# See everything at a glance
ghostenv status
```

`ghostenv init` also:
- Generates a starter policy from tools found in your PATH
- Adds instructions to agent config files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`) — or creates `CLAUDE.md` if none exist
- Adds `.ghostenv/` to `.gitignore`

## Commands

| Command | Description |
|---|---|
| `ghostenv init [file]` | Import secrets from a `.env` file into the vault |
| `ghostenv status` | Show stored keys, policy, and masked env path |
| `ghostenv show [key]` | View real secret values |
| `ghostenv set KEY VALUE` | Add or update a secret |
| `ghostenv edit` | Edit all secrets in your `$EDITOR` |
| `ghostenv remove KEY` | Remove a secret from the vault |
| `ghostenv run CMD` | Run a command with real secrets injected |
| `ghostenv restore` | Write real secrets back to `.env` (undo masking) |
| `ghostenv diff` | Show differences between vault and masked `.env` |
| `ghostenv exec -- CMD` | Same as `run`, with explicit `--` separator |
| `ghostenv policy show` | Show the current policy allowlist |
| `ghostenv policy init` | Generate a starter policy from installed tools |
| `ghostenv policy add CMD [KEY...]` | Add a command to the policy allowlist |
| `ghostenv policy remove CMD` | Remove a command from the policy |

## AI agent integration

ghostenv auto-detects AI agents (Claude, Codex, Cursor, Copilot, etc.) in the process tree and switches behavior:

| | Human | AI agent |
|---|---|---|
| `ghostenv run` | All secrets injected, no questions | Policy enforced — must match allowlist |
| `ghostenv show` | Prompts for confirmation | Blocked |
| `ghostenv edit` | Opens `$EDITOR` | Blocked |
| Command output | Passed through directly | Scrubbed for leaked secrets |

Agents discover ghostenv through the `.env` comments and the `CLAUDE.md` / agent config files created during init. They don't need to read this README.

## Policy

The policy file (`.ghostenv/policy.yaml`) controls what AI agents can do. It has no effect on humans — you always get all your secrets.

```yaml
allow:
  - command: "npm publish"
    inject: [NPM_TOKEN]
  - command: "gh *"
    inject: [GITHUB_TOKEN]
  - command: "docker push *"
    inject: all
```

A starter policy is auto-generated during `ghostenv init` based on tools in your PATH. Manage it with:

```bash
ghostenv policy add "npm publish" NPM_TOKEN
ghostenv policy add "docker push *"          # defaults to all secrets
ghostenv policy remove "npm publish"
ghostenv policy show
```

## Shell completions

```bash
# Zsh
ghostenv completion zsh >> ~/.zshrc

# Bash
ghostenv completion bash >> ~/.bashrc

# Fish
ghostenv completion fish > ~/.config/fish/completions/ghostenv.fish
```

## Key storage

The vault master key is stored in the OS keychain (macOS) or via `secret-tool` (Linux). On Linux, if `secret-tool` is unavailable, ghostenv falls back to GPG automatically.

Force GPG with `GHOSTENV_BACKEND=gpg`. Set `GHOSTENV_GPG_KEY` to pick a specific GPG key.

## Security model

- Secrets are encrypted at rest with AES-256-GCM
- Master key stored in OS keychain, never in plaintext
- `ghostenv run` injects secrets into the child process only — they disappear when the process exits
- AI agents are auto-detected via process tree scanning
- Agent mode: policy enforced, output scrubbed (base64/hex/URL-encoded forms caught)
- Human mode: all secrets injected, no friction
- Masked values are deterministic (stable across sessions) but not reversible
- Each project has its own isolated vault

## License

MIT
