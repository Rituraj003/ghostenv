package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const (
	pbkdf2Iterations = 100_000
	saltSize         = 16
)

// usePassword returns true if the password-based file backend should be used.
// This is the last-resort fallback on Linux when neither secret-tool nor gpg
// is available. Can be forced with GHOSTENV_BACKEND=password.
func usePassword() bool {
	if os.Getenv("GHOSTENV_BACKEND") == "password" {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := exec.LookPath("secret-tool"); err == nil {
		return false
	}
	if _, err := exec.LookPath("gpg"); err == nil {
		return false
	}
	return true
}

func passwordKeyPath(vaultDir string) string {
	return filepath.Join(vaultDir, "master.key.enc")
}

// passwordStore encrypts the master key with a user-provided password
// and writes it to .ghostenv/master.key.enc.
func passwordStore(vaultDir, encoded string) error {
	password, err := promptNewPassword()
	if err != nil {
		return err
	}

	// Generate salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("could not generate salt: %w", err)
	}

	// Derive encryption key from password
	dk, err := pbkdf2.Key(sha256.New, string(password), salt, pbkdf2Iterations, 32)

	// Encrypt the master key hex string
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(encoded), nil)

	// Write: hex(salt) + ":" + hex(ciphertext)
	data := hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext)
	return os.WriteFile(passwordKeyPath(vaultDir), []byte(data), 0600)
}

// passwordLoad decrypts the master key from .ghostenv/master.key.enc
// using a user-provided password.
func passwordLoad(vaultDir string) ([]byte, error) {
	data, err := os.ReadFile(passwordKeyPath(vaultDir))
	if err != nil {
		return nil, fmt.Errorf("password-encrypted key not found")
	}

	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("corrupted key file")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("corrupted key file")
	}
	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("corrupted key file")
	}

	password, err := promptPassword("Enter vault password: ")
	if err != nil {
		return nil, err
	}

	// Derive decryption key
	dk, err := pbkdf2.Key(sha256.New, string(password), salt, pbkdf2Iterations, 32)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("corrupted key file")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted key file")
	}

	return hex.DecodeString(string(plaintext))
}

func passwordDelete(vaultDir string) error {
	return os.Remove(passwordKeyPath(vaultDir))
}

func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read password: %w", err)
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	return password, nil
}

func promptNewPassword() ([]byte, error) {
	password, err := promptPassword("Set vault password: ")
	if err != nil {
		return nil, err
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return nil, err
	}

	if string(password) != string(confirm) {
		return nil, fmt.Errorf("passwords do not match")
	}

	return password, nil
}
