package mask

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"os"
	"strings"

	"github.com/ghostenv/ghostenv/internal/envfile"
)

// Generate creates a masked .env string from real key-value pairs.
// Each value is replaced with a deterministic ghost value (gv_...).
// The ghost value changes when the real secret changes but is not reversible.
func Generate(masterKey []byte, pairs []envfile.KeyValue) string {
	var b strings.Builder

	b.WriteString("# This file is managed by ghostenv. Values are masked.\n")
	b.WriteString("# Real secrets are stored in the encrypted vault.\n")
	b.WriteString("# Run 'ghostenv show' to view real values.\n\n")

	for _, kv := range pairs {
		ghostVal := GhostValue(masterKey, kv.Key, kv.Value)
		b.WriteString(kv.Key)
		b.WriteByte('=')
		b.WriteString(ghostVal)
		b.WriteByte('\n')
	}

	return b.String()
}

// GenerateFromFile creates a masked .env by reading the original file and
// replacing values in-place. Comments, blank lines, and structure are preserved.
// Keys in the vault but not in the original file are appended at the end.
func GenerateFromFile(masterKey []byte, originalPath string, secrets map[string]string) (string, error) {
	f, err := os.Open(originalPath)
	if err != nil {
		// Fall back to flat generation if original can't be read
		var pairs []envfile.KeyValue
		for key, val := range secrets {
			pairs = append(pairs, envfile.KeyValue{Key: key, Value: val})
		}
		return Generate(masterKey, pairs), nil
	}
	defer f.Close()

	var b strings.Builder
	b.WriteString("# This file is managed by ghostenv. Values are masked.\n")
	b.WriteString("# Real secrets are stored in the encrypted vault.\n")
	b.WriteString("# Run 'ghostenv show' to view real values.\n\n")

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip old ghostenv header lines
		if strings.HasPrefix(trimmed, "# This file is managed by ghostenv") ||
			strings.HasPrefix(trimmed, "# Real secrets are stored") ||
			strings.HasPrefix(trimmed, "# Run 'ghostenv show'") {
			continue
		}

		// Preserve comments and blank lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}

		// Parse KEY=VALUE
		idx := strings.IndexByte(trimmed, '=')
		if idx < 0 {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}

		key := strings.TrimSpace(trimmed[:idx])
		if val, ok := secrets[key]; ok {
			ghostVal := GhostValue(masterKey, key, val)
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(ghostVal)
			b.WriteByte('\n')
			seen[key] = true
		} else {
			// Key not in vault, keep original line
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	// Append keys in vault but not in original file
	for key, val := range secrets {
		if !seen[key] {
			ghostVal := GhostValue(masterKey, key, val)
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(ghostVal)
			b.WriteByte('\n')
		}
	}

	return b.String(), nil
}

// IsMasked returns true if a value looks like a ghostenv masked value.
func IsMasked(value string) bool {
	return strings.HasPrefix(value, "gv_")
}

// GhostValue produces a deterministic, non-reversible masked value.
// Format: gv_ + 16 chars of base32(HMAC-SHA256(masterKey, key || ":" || value))
func GhostValue(masterKey []byte, key, value string) string {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(key))
	mac.Write([]byte(":"))
	mac.Write([]byte(value))
	hash := mac.Sum(nil)

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash)
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}

	return "gv_" + encoded
}
