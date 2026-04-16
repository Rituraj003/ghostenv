package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
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
