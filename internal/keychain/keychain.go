package keychain

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const service = "ghostenv"

// Store saves the master key to the OS keychain, GPG, or password-encrypted file.
// On macOS, uses the security CLI with default access controls.
// On Linux, tries secret-tool, then GPG, then password-based file encryption.
func Store(account string, key []byte, vaultDir string) error {
	encoded := hex.EncodeToString(key)

	if usePassword() {
		return passwordStore(vaultDir, encoded)
	}
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

// Load retrieves the master key from the OS keychain, GPG, or password-encrypted file.
func Load(account string, vaultDir string) ([]byte, error) {
	if usePassword() {
		return passwordLoad(vaultDir)
	}
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

// Delete removes the master key from the OS keychain, GPG, or password-encrypted file.
func Delete(account string, vaultDir string) error {
	if usePassword() {
		return passwordDelete(vaultDir)
	}
	if useGPG() {
		return gpgDelete(vaultDir)
	}

	switch runtime.GOOS {
	case "darwin":
		return exec.Command("security", "delete-generic-password",
			"-s", service, "-a", account,
		).Run()

	case "linux":
		return exec.Command("secret-tool", "clear",
			"service", service, "account", account,
		).Run()

	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

// storeFallback uses the macOS security CLI to store the key.
// Without -A, macOS prompts the user when a new application tries to access
// the entry, providing one more barrier against local secret extraction.
func storeFallback(account, encoded string) error {
	exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	return exec.Command("security", "add-generic-password",
		"-s", service, "-a", account, "-w", encoded,
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
