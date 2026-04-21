package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	content := `# A comment
SIMPLE=value
QUOTED="hello world"
SINGLE_QUOTED='another value'
EMPTY=

# Another comment
SPACED_KEY = spaced_value
`
	os.WriteFile(path, []byte(content), 0644)

	pairs, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	expected := []KeyValue{
		{"SIMPLE", "value"},
		{"QUOTED", "hello world"},
		{"SINGLE_QUOTED", "another value"},
		{"EMPTY", ""},
		{"SPACED_KEY", "spaced_value"},
	}

	if len(pairs) != len(expected) {
		t.Fatalf("expected %d pairs, got %d", len(expected), len(pairs))
	}

	for i, kv := range pairs {
		if kv.Key != expected[i].Key || kv.Value != expected[i].Value {
			t.Errorf("pair %d: expected %s=%q, got %s=%q", i, expected[i].Key, expected[i].Value, kv.Key, kv.Value)
		}
	}
}

func TestParseSkipsInvalidLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	content := `GOOD=value
no_equals_sign
=no_key
ALSO_GOOD=123
`
	os.WriteFile(path, []byte(content), 0644)

	pairs, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Key != "GOOD" || pairs[1].Key != "ALSO_GOOD" {
		t.Errorf("unexpected keys: %v", pairs)
	}
}

func TestFormat(t *testing.T) {
	pairs := []KeyValue{
		{"SIMPLE", "value"},
		{"NEEDS_QUOTES", "hello world"},
	}

	result := Format(pairs)
	expected := "SIMPLE=value\nNEEDS_QUOTES=\"hello world\"\n"

	if result != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	pairs := []KeyValue{
		{"SIMPLE", "value"},
		{"WITH_QUOTES", `say "hello"`},
		{"WITH_SPACES", "hello world"},
		{"EMPTY", ""},
	}

	formatted := Format(pairs)

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte(formatted), 0644)

	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(parsed) != len(pairs) {
		t.Fatalf("expected %d pairs, got %d", len(pairs), len(parsed))
	}

	for i, kv := range parsed {
		if kv.Key != pairs[i].Key || kv.Value != pairs[i].Value {
			t.Errorf("round-trip pair %d: expected %s=%q, got %s=%q", i, pairs[i].Key, pairs[i].Value, kv.Key, kv.Value)
		}
	}
}

func TestParseFileNotFound(t *testing.T) {
	_, err := Parse("/nonexistent/path/.env")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
