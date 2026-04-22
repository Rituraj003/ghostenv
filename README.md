# ghostenv

**Let AI read your repo. Not your secrets.**

Ghostenv makes `.env` files safe for AI coding agents like Claude Code, Cursor, Codex, and Copilot.

It moves your real secrets into an encrypted per-project vault, replaces `.env` with harmless decoy values, and injects the real credentials only into approved commands at runtime.

## Why this exists

AI agents can read files, grep your repo, inspect diffs, and operate inside worktrees. That makes local `.env` files a real liability.

Most fixes try to stop agents from reading `.env`. Ghostenv takes a different approach: **it makes `.env` safe to read.**

## Quick example

```bash
ghostenv init
cat .env
# OPENAI_API_KEY=gv_YZXELQYXBPKJNIX2
# GITHUB_TOKEN=gv_X73CCW5SRWTUU22C

ghostenv run gh pr create
ghostenv run npm publish
```

Your agent sees the keys. It never sees the secrets.

## How it works

1. Real secrets are encrypted into a local project vault (`.ghostenv/`)
2. `.env` is rewritten with masked placeholder values
3. `ghostenv run` injects the real values into the child process only — they disappear when it exits
4. When Ghostenv detects an AI agent, it restricts which commands receive secrets and scrubs command output for leaks

## Install

**Quick install** (macOS/Linux):
```bash
curl -sL https://raw.githubusercontent.com/Rituraj003/ghostenv/main/install.sh | sh
```

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

## Getting started

```bash
# Import your .env into the vault
ghostenv init

# Run commands that need secrets
ghostenv run npm publish
ghostenv run terraform apply

# See what's stored
ghostenv status

# Restore real .env if needed
ghostenv restore
```

`ghostenv init` also:
- Generates a starter policy from tools found in your PATH
- Adds instructions to agent config files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`)
- Adds `.ghostenv/` to `.gitignore`

## Agent behavior

Ghostenv auto-detects AI agents in the process tree and switches behavior:

| | Human | AI agent |
|---|---|---|
| `ghostenv run` | All secrets injected, no friction | Policy enforced, must match allowlist |
| `ghostenv show` | Prompts for confirmation | Blocked |
| Command output | Passed through | Scrubbed for leaked secrets |

Agents discover Ghostenv through the `.env` comments and agent config files created during init. They don't need to read this README.

## Policy

The policy file (`.ghostenv/policy.yaml`) controls what AI agents can run. It has no effect on humans.

```yaml
allow:
  - command: "npm publish"
    inject: [NPM_TOKEN]
  - command: "gh *"
    inject: [GITHUB_TOKEN]
  - command: "docker push *"
    inject: all
```

A starter policy is auto-generated during `ghostenv init`. Manage it with:

```bash
ghostenv policy add "npm publish" NPM_TOKEN
ghostenv policy add "docker push *"
ghostenv policy remove "npm publish"
ghostenv policy show
```

## Commands

| Command | Description |
|---|---|
| `ghostenv init [file]` | Import secrets from `.env` into the vault |
| `ghostenv status` | Show stored keys, policy, and masked env path |
| `ghostenv show [key]` | View real secret values |
| `ghostenv set KEY VALUE` | Add or update a secret |
| `ghostenv edit` | Edit all secrets in `$EDITOR` |
| `ghostenv remove KEY` | Remove a secret from the vault |
| `ghostenv run CMD` | Run a command with real secrets injected |
| `ghostenv restore` | Write real secrets back to `.env` |
| `ghostenv diff` | Show differences between vault and `.env` |
| `ghostenv exec -- CMD` | Same as `run`, with explicit `--` separator |
| `ghostenv policy show` | Show the current policy allowlist |
| `ghostenv policy init` | Generate a starter policy from installed tools |
| `ghostenv policy add CMD [KEY...]` | Add a command to the policy |
| `ghostenv policy remove CMD` | Remove a command from the policy |

## Security model

- Secrets encrypted at rest with AES-256-GCM
- Master key stored in OS keychain (macOS), `secret-tool` / GPG / password-encrypted file (Linux)
- Vault writes are atomic (temp file + rename) to prevent corruption
- Real secrets appear only inside the command that needs them, then disappear when it exits
- Agent mode: policy enforced, output scrubbed (base64, hex, and URL-encoded forms caught)
- Masked values are deterministic (stable across sessions) but not reversible
- Each project has its own isolated vault

## Shell completions

```bash
ghostenv completion zsh >> ~/.zshrc
ghostenv completion bash >> ~/.bashrc
ghostenv completion fish > ~/.config/fish/completions/ghostenv.fish
```

## License

MIT
