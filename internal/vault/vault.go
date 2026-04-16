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
	Value string    `json:"value"`
	SetAt time.Time `json:"set_at"`
}

// SecretInfo is returned by List for display purposes.
type SecretInfo struct {
	Key string
	Age string
}

// Config stores vault metadata alongside the encrypted secrets.
type Config struct {
	EnvFile string `json:"env_file"`
}

// Vault manages encrypted secrets on disk.
type Vault struct {
	dir        string
	path       string
	configPath string
	masterKey  []byte
	secrets    map[string]Secret
	config     Config
}

// findProjectDir walks up from cwd looking for an existing .ghostenv/ directory.
// Returns empty string if none found.
func findProjectDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, ".ghostenv")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// Init creates a new vault in the current directory.
// Returns an error if a vault already exists here.
func Init() (*Vault, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cwd, ".ghostenv")

	// Check if vault already exists
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return nil, fmt.Errorf("vault already exists in this project. Use 'ghostenv set' to update secrets or 'ghostenv init --force' to reimport")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	v := &Vault{
		dir:        dir,
		path:       filepath.Join(dir, "vault.enc"),
		configPath: filepath.Join(dir, "config.json"),
		secrets:    make(map[string]Secret),
	}

	// Generate master key
	v.masterKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, v.masterKey); err != nil {
		return nil, fmt.Errorf("could not generate master key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key"), v.masterKey, 0600); err != nil {
		return nil, fmt.Errorf("could not save master key: %w", err)
	}

	return v, nil
}

// Open loads an existing vault by searching up from cwd.
func Open() (*Vault, error) {
	dir := findProjectDir()
	if dir == "" {
		return nil, fmt.Errorf("no ghostenv vault found. Run 'ghostenv init' first")
	}

	v := &Vault{
		dir:        dir,
		path:       filepath.Join(dir, "vault.enc"),
		configPath: filepath.Join(dir, "config.json"),
		secrets:    make(map[string]Secret),
	}

	// Load master key
	keyPath := filepath.Join(dir, "master.key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil || len(keyData) != 32 {
		return nil, fmt.Errorf("could not read master key")
	}
	v.masterKey = keyData

	// Load existing vault if present
	if _, err := os.Stat(v.path); err == nil {
		if err := v.load(); err != nil {
			return nil, fmt.Errorf("could not load vault: %w", err)
		}
	}

	// Load config if present
	if data, err := os.ReadFile(v.configPath); err == nil {
		json.Unmarshal(data, &v.config)
	}

	return v, nil
}

// Exists returns true if a vault exists in the current directory or any parent.
func Exists() bool {
	return findProjectDir() != ""
}

// ExistsInCwd returns true if a vault exists in the current working directory.
func ExistsInCwd() bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	dir := filepath.Join(cwd, ".ghostenv")
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// MasterKey returns the vault's master key (used for masking).
func (v *Vault) MasterKey() []byte {
	return v.masterKey
}

// SetEnvFile records which .env file this vault manages.
func (v *Vault) SetEnvFile(path string) {
	v.config.EnvFile = path
}

// EnvFile returns the path to the managed .env file.
func (v *Vault) EnvFile() string {
	return v.config.EnvFile
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

// Has returns true if a secret exists.
func (v *Vault) Has(key string) bool {
	_, ok := v.secrets[key]
	return ok
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

// Pairs returns all secrets as envfile-compatible key-value pairs.
func (v *Vault) Pairs() []struct{ Key, Value string } {
	infos := v.List()
	pairs := make([]struct{ Key, Value string }, len(infos))
	for i, info := range infos {
		pairs[i].Key = info.Key
		pairs[i].Value = v.secrets[info.Key].Value
	}
	return pairs
}

// EnvMap returns all secrets as a key-value map (for injection).
func (v *Vault) EnvMap() map[string]string {
	m := make(map[string]string, len(v.secrets))
	for key, s := range v.secrets {
		m[key] = s.Value
	}
	return m
}

// Save encrypts and writes the vault and config to disk.
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
	if err := os.WriteFile(v.path, ciphertext, 0600); err != nil {
		return err
	}

	// Save config
	configData, err := json.Marshal(v.config)
	if err != nil {
		return err
	}
	return os.WriteFile(v.configPath, configData, 0644)
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

// Count returns the number of secrets stored.
func (v *Vault) Count() int {
	return len(v.secrets)
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
