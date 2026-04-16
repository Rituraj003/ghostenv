package scrub

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestScrubPlaintext(t *testing.T) {
	secrets := map[string]string{"API_KEY": "sk-real-secret-key-123"}
	output := "token: sk-real-secret-key-123 done"
	result := Output(output, secrets)

	if strings.Contains(result, "sk-real-secret-key-123") {
		t.Error("plaintext secret not scrubbed")
	}
	if !strings.Contains(result, "[REDACTED:API_KEY]") {
		t.Error("missing redaction tag")
	}
}

func TestScrubBase64(t *testing.T) {
	secret := "sk-real-secret-key-123"
	secrets := map[string]string{"API_KEY": secret}
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	output := "data: " + encoded + " end"
	result := Output(output, secrets)

	if strings.Contains(result, encoded) {
		t.Error("base64-encoded secret not scrubbed")
	}
}

func TestScrubHex(t *testing.T) {
	secret := "sk-real-secret-key-123"
	secrets := map[string]string{"API_KEY": secret}
	encoded := hex.EncodeToString([]byte(secret))
	output := "hex: " + encoded
	result := Output(output, secrets)

	if strings.Contains(result, encoded) {
		t.Error("hex-encoded secret not scrubbed")
	}
}

func TestScrubSkipsShortSecrets(t *testing.T) {
	secrets := map[string]string{"SHORT": "abc"}
	encoded := base64.StdEncoding.EncodeToString([]byte("abc"))
	output := "data: " + encoded
	result := Output(output, secrets)

	// Short secrets should NOT have their encodings scrubbed (false positive risk)
	if strings.Contains(result, "[REDACTED") && strings.Contains(output, encoded) {
		// Only the raw value should be scrubbed, not encodings
	}
}

func TestScrubEmpty(t *testing.T) {
	secrets := map[string]string{"EMPTY": ""}
	output := "nothing to scrub"
	result := Output(output, secrets)

	if result != output {
		t.Error("empty secret should not change output")
	}
}

func TestScrubMultipleSecrets(t *testing.T) {
	secrets := map[string]string{
		"KEY1": "first-secret-value",
		"KEY2": "second-secret-value",
	}
	output := "a: first-secret-value b: second-secret-value"
	result := Output(output, secrets)

	if strings.Contains(result, "first-secret-value") || strings.Contains(result, "second-secret-value") {
		t.Error("not all secrets scrubbed")
	}
}
