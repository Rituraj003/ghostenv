package keychain

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const service = "ghostenv"

// helperPath finds the ghostenv-keychain binary.
// Checks next to the ghostenv binary first, then PATH.
// Set GHOSTENV_NO_HELPER=1 to skip (used in tests).
func helperPath() (string, error) {
	if os.Getenv("GHOSTENV_NO_HELPER") == "1" {
		return "", fmt.Errorf("helper disabled")
	}

	// Check next to the current executable
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "ghostenv-keychain")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Check PATH
	return exec.LookPath("ghostenv-keychain")
}

// Store saves the master key to the OS keychain or GPG.
func Store(account string, key []byte, vaultDir string) error {
	encoded := hex.EncodeToString(key)

	if useGPG() {
		return gpgStore(vaultDir, encoded)
	}

	switch runtime.GOOS {
	case "darwin":
		helper, err := helperPath()
		if err != nil {
			return storeFallback(account, encoded)
		}
		out, err := exec.Command(helper, "store", account, encoded).CombinedOutput()
		if err != nil {
			return fmt.Errorf("keychain store failed: %s", strings.TrimSpace(string(out)))
		}
		return nil

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
func Load(account string, vaultDir string) ([]byte, error) {
	if useGPG() {
		return gpgLoad(vaultDir)
	}

	switch runtime.GOOS {
	case "darwin":
		helper, err := helperPath()
		if err != nil {
			return loadFallback(account)
		}
		out, err := exec.Command(helper, "load", account).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("keychain load failed: %s", strings.TrimSpace(string(out)))
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

// Delete removes the master key from the OS keychain or GPG.
func Delete(account string, vaultDir string) error {
	if useGPG() {
		return gpgDelete(vaultDir)
	}

	switch runtime.GOOS {
	case "darwin":
		helper, err := helperPath()
		if err != nil {
			return exec.Command("security", "delete-generic-password",
				"-s", service, "-a", account,
			).Run()
		}
		out, err := exec.Command(helper, "delete", account).CombinedOutput()
		if err != nil {
			return fmt.Errorf("keychain delete failed: %s", strings.TrimSpace(string(out)))
		}
		return nil

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
