package vault

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ghostenv/ghostenv/internal/envfile"
)

// EditInTerminal opens secrets in the user's editor.
// Returns true if secrets were changed.
func (v *Vault) EditInTerminal() (bool, error) {
	// Build current content
	var keys []string
	for k := range v.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []envfile.KeyValue
	for _, k := range keys {
		pairs = append(pairs, envfile.KeyValue{Key: k, Value: v.secrets[k].Value})
	}
	content := envfile.Format(pairs)

	// Write to temp file
	tmp, err := os.CreateTemp("", "ghostenv-edit-*.env")
	if err != nil {
		return false, fmt.Errorf("could not create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return false, err
	}
	tmp.Close()

	// Open in editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("editor exited with error: %w", err)
	}

	// Read back
	newPairs, err := envfile.Parse(tmpPath)
	if err != nil {
		return false, fmt.Errorf("could not parse edited file: %w", err)
	}

	// Check for changes
	changed := false
	newMap := make(map[string]string)
	for _, kv := range newPairs {
		newMap[kv.Key] = kv.Value
	}

	// Detect added or modified keys
	for k, newVal := range newMap {
		if oldSecret, ok := v.secrets[k]; !ok || oldSecret.Value != newVal {
			v.Set(k, newVal)
			changed = true
		}
	}

	// Detect removed keys
	for k := range v.secrets {
		if _, ok := newMap[k]; !ok {
			v.Delete(k)
			changed = true
		}
	}

	if changed {
		return true, v.Save()
	}
	return false, nil
}

// FormatForDisplay returns a human-readable view of secrets (values truncated).
func (v *Vault) FormatForDisplay() string {
	var b strings.Builder
	infos := v.List()
	for _, info := range infos {
		val, _ := v.Get(info.Key)
		display := truncate(val, 20)
		b.WriteString(fmt.Sprintf("  %-30s %s  (%s)\n", info.Key, display, info.Age))
	}
	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
