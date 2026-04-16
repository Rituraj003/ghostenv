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

// useGPG returns true if GPG should be used as the key storage backend.
// Set GHOSTENV_BACKEND=gpg to force it, otherwise auto-detect on Linux:
// use gpg when secret-tool is unavailable but gpg is.
func useGPG() bool {
	if os.Getenv("GHOSTENV_BACKEND") == "gpg" {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := exec.LookPath("secret-tool"); err == nil {
		return false
	}
	if _, err := exec.LookPath("gpg"); err == nil {
		return true
	}
	return false
}

// gpgKeyPath returns the path to the GPG-encrypted master key file.
func gpgKeyPath(vaultDir string) string {
	return filepath.Join(vaultDir, "master.key.gpg")
}

// gpgRecipient returns the GPG key to encrypt to.
// Uses GHOSTENV_GPG_KEY if set, otherwise the default GPG key.
func gpgRecipient() (string, error) {
	if key := os.Getenv("GHOSTENV_GPG_KEY"); key != "" {
		return key, nil
	}
	out, err := exec.Command("gpg", "--list-secret-keys", "--with-colons").Output()
	if err != nil {
		return "", fmt.Errorf("no GPG secret keys found")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "uid:") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 {
				return fields[9], nil
			}
		}
	}
	return "", fmt.Errorf("no GPG secret keys found")
}

func gpgStore(vaultDir, encoded string) error {
	recipient, err := gpgRecipient()
	if err != nil {
		return err
	}
	cmd := exec.Command("gpg", "--batch", "--yes", "-e", "-r", recipient, "-o", gpgKeyPath(vaultDir))
	cmd.Stdin = strings.NewReader(encoded)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gpg encrypt failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func gpgLoad(vaultDir string) ([]byte, error) {
	out, err := exec.Command("gpg", "--batch", "--quiet", "-d", gpgKeyPath(vaultDir)).Output()
	if err != nil {
		return nil, fmt.Errorf("key not found or gpg decrypt failed")
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func gpgDelete(vaultDir string) error {
	return os.Remove(gpgKeyPath(vaultDir))
}
