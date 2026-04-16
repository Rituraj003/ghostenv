package mask

import (
	"strings"
	"testing"

	"github.com/ghostenv/ghostenv/internal/envfile"
)

func TestGhostValueDeterministic(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!!")

	v1 := GhostValue(key, "API_KEY", "secret123")
	v2 := GhostValue(key, "API_KEY", "secret123")

	if v1 != v2 {
		t.Errorf("same inputs produced different outputs: %s vs %s", v1, v2)
	}
}

func TestGhostValueChangesWithSecret(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!!")

	v1 := GhostValue(key, "API_KEY", "secret123")
	v2 := GhostValue(key, "API_KEY", "secret456")

	if v1 == v2 {
		t.Error("different secrets produced same ghost value")
	}
}

func TestGhostValueChangesWithKey(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!!")

	v1 := GhostValue(key, "API_KEY", "secret123")
	v2 := GhostValue(key, "OTHER_KEY", "secret123")

	if v1 == v2 {
		t.Error("different key names produced same ghost value")
	}
}

func TestGhostValuePrefix(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!!")
	v := GhostValue(key, "API_KEY", "secret")

	if !strings.HasPrefix(v, "gv_") {
		t.Errorf("expected gv_ prefix, got %s", v)
	}
	// gv_ + 16 chars = 19 total
	if len(v) != 19 {
		t.Errorf("expected length 19, got %d (%s)", len(v), v)
	}
}

func TestIsMasked(t *testing.T) {
	if !IsMasked("gv_ABCDEF1234567890") {
		t.Error("should detect gv_ prefix as masked")
	}
	if IsMasked("sk-real-api-key") {
		t.Error("should not detect real key as masked")
	}
	if IsMasked("") {
		t.Error("should not detect empty string as masked")
	}
}

func TestGenerate(t *testing.T) {
	key := []byte("test-master-key-32-bytes-long!!")
	pairs := []envfile.KeyValue{
		{Key: "API_KEY", Value: "secret"},
		{Key: "TOKEN", Value: "token123"},
	}

	result := Generate(key, pairs)

	if !strings.Contains(result, "API_KEY=gv_") {
		t.Error("output should contain masked API_KEY")
	}
	if !strings.Contains(result, "TOKEN=gv_") {
		t.Error("output should contain masked TOKEN")
	}
	if strings.Contains(result, "=secret") {
		t.Error("output should not contain real secret value")
	}
	if !strings.Contains(result, "managed by ghostenv") {
		t.Error("output should contain header comment")
	}
}
