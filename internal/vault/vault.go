package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Secret holds a secret value and metadata.
type Secret struct {
	Value   string    `json:"value"`
	SetAt   time.Time `json:"set_at"`
}

// SecretInfo is returned by List for display purposes.
type SecretInfo struct {
	Key string
	Age string
}

// Vault manages encrypted secrets on disk.
type Vault struct {
	path      string
	masterKey []byte
	secrets   map[string]Secret
}

// vaultDir returns the directory where the vault is stored.
func vaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".ghostenv")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// Open loads the vault from disk, or creates a new one.
func Open() (*Vault, error) {
	dir, err := vaultDir()
	if err != nil {
		return nil, err
	}

	v := &Vault{
		path:    filepath.Join(dir, "vault.enc"),
		secrets: make(map[string]Secret),
	}

	// Load or generate master key
	keyPath := filepath.Join(dir, "master.key")
	if keyData, err := os.ReadFile(keyPath); err == nil && len(keyData) == 32 {
		v.masterKey = keyData
	} else {
		v.masterKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, v.masterKey); err != nil {
			return nil, fmt.Errorf("could not generate master key: %w", err)
		}
		if err := os.WriteFile(keyPath, v.masterKey, 0600); err != nil {
			return nil, fmt.Errorf("could not save master key: %w", err)
		}
	}

	// Load existing vault if present
	if _, err := os.Stat(v.path); err == nil {
		if err := v.load(); err != nil {
			return nil, fmt.Errorf("could not load vault: %w", err)
		}
	}

	return v, nil
}

// MasterKey returns the vault's master key (used for masking).
func (v *Vault) MasterKey() []byte {
	return v.masterKey
}

// Set adds or updates a secret.
func (v *Vault) Set(key, value string) {
	v.secrets[key] = Secret{
		Value: value,
		SetAt: time.Now(),
	}
}

// Get retrieves a secret value.
func (v *Vault) Get(key string) (string, bool) {
	s, ok := v.secrets[key]
	if !ok {
		return "", false
	}
	return s.Value, true
}

// Delete removes a secret.
func (v *Vault) Delete(key string) {
	delete(v.secrets, key)
}

// List returns all secret keys with their age, sorted alphabetically.
func (v *Vault) List() []SecretInfo {
	var infos []SecretInfo
	for key, s := range v.secrets {
		infos = append(infos, SecretInfo{
			Key: key,
			Age: humanAge(s.SetAt),
		})
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Key < infos[j].Key
	})
	return infos
}

// EnvMap returns all secrets as a key-value map (for injection).
func (v *Vault) EnvMap() map[string]string {
	m := make(map[string]string, len(v.secrets))
	for key, s := range v.secrets {
		m[key] = s.Value
	}
	return m
}

// AllPairs returns all secrets as key-value pairs for editing.
func (v *Vault) AllPairs() map[string]string {
	return v.EnvMap()
}

// Save encrypts and writes the vault to disk.
func (v *Vault) Save() error {
	plaintext, err := json.Marshal(v.secrets)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(v.masterKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(v.path, ciphertext, 0600)
}

// load decrypts and reads the vault from disk.
func (v *Vault) load() error {
	data, err := os.ReadFile(v.path)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("vault data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("could not decrypt vault (wrong key?): %w", err)
	}

	return json.Unmarshal(plaintext, &v.secrets)
}

func humanAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d min ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}
