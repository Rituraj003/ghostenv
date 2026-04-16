# ghostenv

Keep your secrets away from AI agents.

ghostenv locks your `.env` secrets in an encrypted vault and replaces them with masked (fake) values. AI agents can see what keys exist but never the real values. When you need to run a command that requires secrets, ghostenv injects them into only that process.

## How it works

1. Your real secrets get encrypted and stored in a local vault (`~/.ghostenv/`)
2. Your `.env` file gets replaced with fake values like `gv_YZXELQYXBPKJNIX2`
3. When you run a command through `ghostenv exec`, real secrets are injected into that process only — they never touch your shell environment

## Install

```bash
go install github.com/ghostenv/ghostenv/cmd/ghostenv@latest
```

## Quick start

```bash
# Lock up your .env secrets
ghostenv init .env

# Your .env now contains masked values — safe for AI agents to read
cat .env
# OPENAI_API_KEY=gv_YZXELQYXBPKJNIX2
# GITHUB_TOKEN=gv_X73CCW5SRWTUU22C

# Run commands with real secrets injected
ghostenv exec -- npm publish
ghostenv exec -- gh pr create
```

## Commands

| Command | Description |
|---|---|
| `ghostenv init [file]` | Import secrets from a `.env` file into the vault |
| `ghostenv status` | Show stored keys and when they were set |
| `ghostenv show [key]` | View real secret values |
| `ghostenv set KEY VALUE` | Add or update a secret |
| `ghostenv edit` | Edit all secrets in your `$EDITOR` |
| `ghostenv exec -- CMD` | Run a command with real secrets injected |

## Security model

- Secrets are encrypted at rest with AES-256-GCM
- Real values never exist in your shell environment
- `ghostenv exec` injects secrets into the child process only — they disappear when the process exits
- Masked values are deterministic (stable across sessions) but not reversible

## License

MIT
