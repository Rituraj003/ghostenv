package keychain

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const service = "ghostenv"

// Store saves the master key to the OS keychain.
func Store(account string, key []byte) error {
	encoded := hex.EncodeToString(key)

	switch runtime.GOOS {
	case "darwin":
		// Delete existing entry first (ignore errors if not found)
		exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
		return exec.Command("security", "add-generic-password",
			"-s", service, "-a", account, "-w", encoded,
		).Run()

	case "linux":
		return exec.Command("secret-tool", "store",
			"--label", "ghostenv master key",
			"service", service, "account", account,
		).Run()

	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

// Load retrieves the master key from the OS keychain.
func Load(account string) ([]byte, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("security", "find-generic-password",
			"-s", service, "-a", account, "-w",
		).Output()
		if err != nil {
			return nil, fmt.Errorf("key not found in keychain")
		}
		return hex.DecodeString(strings.TrimSpace(string(out)))

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

// Delete removes the master key from the OS keychain.
func Delete(account string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("security", "delete-generic-password",
			"-s", service, "-a", account,
		).Run()

	case "linux":
		// secret-tool doesn't have a direct delete; clear by storing empty
		return exec.Command("secret-tool", "store",
			"--label", "ghostenv master key (deleted)",
			"service", service, "account", account,
		).Run()

	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}
