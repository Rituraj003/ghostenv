package keychain

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const service = "ghostenv"

// Store saves the master key to the OS keychain or GPG.
// On macOS, always uses the security CLI with -A flag so any process can read
// without prompting. Touch ID protection is enforced on Load, not Store.
func Store(account string, key []byte, vaultDir string) error {
	encoded := hex.EncodeToString(key)

	if useGPG() {
		return gpgStore(vaultDir, encoded)
	}

	switch runtime.GOOS {
	case "darwin":
		return storeFallback(account, encoded)

	case "linux":
		cmd := exec.Command("secret-tool", "store",
			"--label", "ghostenv master key",
			"service", service, "account", account,
		)
		cmd.Stdin = strings.NewReader(encoded)
		return cmd.Run()

	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

// Load retrieves the master key from the OS keychain or GPG.
// On macOS, always uses the security CLI for consistency with Store.
// Touch ID authentication is handled separately by the guard package.
func Load(account string, vaultDir string) ([]byte, error) {
	if useGPG() {
		return gpgLoad(vaultDir)
	}

	switch runtime.GOOS {
	case "darwin":
		return loadFallback(account)

	case "linux":
		out, err := exec.Command("secret-tool", "lookup",
			"service", service, "account", account,
		).Output()
		if err != nil {
			return nil, fmt.Errorf("key not found in keychain")
		}
		return hex.DecodeString(strings.TrimSpace(string(out)))

	default:
		return nil, fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

// Delete removes the master key from the OS keychain or GPG.
func Delete(account string, vaultDir string) error {
	if useGPG() {
		return gpgDelete(vaultDir)
	}

	switch runtime.GOOS {
	case "darwin":
		return exec.Command("security", "delete-generic-password",
			"-s", service, "-a", account,
		).Run()

	case "linux":
		return exec.Command("secret-tool", "store",
			"--label", "ghostenv master key (deleted)",
			"service", service, "account", account,
		).Run()

	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

// Fallback: plain security command (no Touch ID protection)
func storeFallback(account, encoded string) error {
	exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	// -A allows any application to access without prompting
	return exec.Command("security", "add-generic-password",
		"-s", service, "-a", account, "-w", encoded, "-A",
	).Run()
}

func loadFallback(account string) ([]byte, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-s", service, "-a", account, "-w",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("key not found in keychain")
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}
