package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissing(t *testing.T) {
	p, err := Load("/nonexistent/dir")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if !p.IsEmpty() {
		t.Fatal("expected empty policy")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()

	original := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
			{Command: "gh *", Inject: []string{"GITHUB_TOKEN"}},
		},
	}

	if err := original.Save(dir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filepath.Join(dir, "policy.yaml")); err != nil {
		t.Fatalf("policy.yaml not created: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.Allow) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(loaded.Allow))
	}
	if loaded.Allow[0].Command != "npm publish" {
		t.Errorf("expected 'npm publish', got %q", loaded.Allow[0].Command)
	}
	if loaded.Allow[1].Inject[0] != "GITHUB_TOKEN" {
		t.Errorf("expected GITHUB_TOKEN inject, got %q", loaded.Allow[1].Inject[0])
	}
}

func TestMatchExact(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
		},
	}

	rule, ok := p.Match("npm", []string{"publish"})
	if !ok {
		t.Fatal("expected match")
	}
	if rule.Command != "npm publish" {
		t.Errorf("wrong rule matched: %q", rule.Command)
	}
}

func TestMatchWildcard(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "gh *", Inject: []string{"GITHUB_TOKEN"}},
		},
	}

	if _, ok := p.Match("gh", []string{"pr", "create"}); !ok {
		t.Fatal("expected wildcard match for 'gh pr create'")
	}

	if _, ok := p.Match("gh", []string{"issue", "list"}); !ok {
		t.Fatal("expected wildcard match for 'gh issue list'")
	}
}

func TestMatchBinaryOnly(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "kubectl", Inject: []string{"all"}},
		},
	}

	if _, ok := p.Match("kubectl", []string{"get", "pods"}); !ok {
		t.Fatal("expected binary-only match")
	}

	if _, ok := p.Match("kubectl", nil); !ok {
		t.Fatal("expected binary-only match with no args")
	}
}

func TestNoMatch(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
		},
	}

	if _, ok := p.Match("python", []string{"-c", "print('hi')"}); ok {
		t.Fatal("expected no match for python")
	}

	if _, ok := p.Match("npm", []string{"install"}); ok {
		t.Fatal("expected no match for npm install")
	}
}

func TestMatchWithPath(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
		},
	}

	// Should match even if bin has a path prefix
	if _, ok := p.Match("/usr/local/bin/npm", []string{"publish"}); !ok {
		t.Fatal("expected match with full path")
	}
}

func TestMatchTrailingWildcard(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "docker push *", Inject: []string{"all"}},
		},
	}

	if _, ok := p.Match("docker", []string{"push", "myimage:latest"}); !ok {
		t.Fatal("expected match for 'docker push myimage:latest'")
	}

	if _, ok := p.Match("docker", []string{"build", "."}); ok {
		t.Fatal("expected no match for 'docker build .'")
	}
}

func TestInjectAll(t *testing.T) {
	r := Rule{Inject: []string{"all"}}
	if !r.InjectAll() {
		t.Fatal("expected InjectAll true")
	}

	r2 := Rule{Inject: []string{"NPM_TOKEN"}}
	if r2.InjectAll() {
		t.Fatal("expected InjectAll false")
	}
}

func TestFilterSecrets(t *testing.T) {
	all := map[string]string{
		"NPM_TOKEN":    "secret1",
		"GITHUB_TOKEN": "secret2",
		"STRIPE_KEY":   "secret3",
	}

	r := Rule{Inject: []string{"NPM_TOKEN"}}
	filtered := r.FilterSecrets(all)

	if len(filtered) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(filtered))
	}
	if filtered["NPM_TOKEN"] != "secret1" {
		t.Error("wrong value for NPM_TOKEN")
	}

	// inject: all returns everything
	rAll := Rule{Inject: []string{"all"}}
	filteredAll := rAll.FilterSecrets(all)
	if len(filteredAll) != 3 {
		t.Fatalf("expected 3 secrets for inject:all, got %d", len(filteredAll))
	}
}

func TestFilterSecretsMissingKey(t *testing.T) {
	all := map[string]string{
		"NPM_TOKEN": "secret1",
	}

	r := Rule{Inject: []string{"NPM_TOKEN", "NONEXISTENT"}}
	filtered := r.FilterSecrets(all)

	if len(filtered) != 1 {
		t.Fatalf("expected 1 secret (missing key skipped), got %d", len(filtered))
	}
}

func TestGenerateStarter(t *testing.T) {
	// Just verify it doesn't panic and returns a valid policy
	p := GenerateStarter()
	_ = p.IsEmpty() // may or may not have rules depending on what's installed
}

func TestAddEmpty(t *testing.T) {
	p := &Policy{}
	if err := p.Add("", []string{"all"}); err == nil {
		t.Fatal("expected error for empty command")
	}
	if err := p.Add("   ", []string{"all"}); err == nil {
		t.Fatal("expected error for whitespace-only command")
	}
}

func TestFormat(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
			{Command: "gh *", Inject: []string{"GITHUB_TOKEN"}},
		},
	}

	out := p.Format()
	if out == "" {
		t.Fatal("expected non-empty format output")
	}

	empty := &Policy{}
	if empty.Format() != "No policy rules defined.\n" {
		t.Error("expected empty message")
	}
}

func TestAddRule(t *testing.T) {
	p := &Policy{}

	if err := p.Add("npm publish", []string{"NPM_TOKEN"}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if len(p.Allow) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Allow))
	}
	if p.Allow[0].Command != "npm publish" {
		t.Errorf("expected 'npm publish', got %q", p.Allow[0].Command)
	}
}

func TestAddDuplicate(t *testing.T) {
	p := &Policy{
		Allow: []Rule{{Command: "npm publish", Inject: []string{"NPM_TOKEN"}}},
	}

	// Adding same command should update inject, not duplicate
	if err := p.Add("npm publish", []string{"NPM_TOKEN", "NODE_AUTH_TOKEN"}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if len(p.Allow) != 1 {
		t.Fatalf("expected 1 rule (updated), got %d", len(p.Allow))
	}
	if len(p.Allow[0].Inject) != 2 {
		t.Errorf("expected 2 inject keys, got %d", len(p.Allow[0].Inject))
	}
}

func TestAddBlocked(t *testing.T) {
	p := &Policy{}

	blockedCmds := []string{"bash", "python script.py", "node -e code", "env", "cat /etc/passwd"}
	for _, cmd := range blockedCmds {
		if err := p.Add(cmd, []string{"all"}); err == nil {
			t.Errorf("expected error for blocked command %q", cmd)
		}
	}
	if len(p.Allow) != 0 {
		t.Fatalf("expected 0 rules after blocked adds, got %d", len(p.Allow))
	}
}

func TestRemoveRule(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
			{Command: "gh *", Inject: []string{"GITHUB_TOKEN"}},
		},
	}

	if !p.Remove("npm publish") {
		t.Fatal("expected Remove to return true")
	}
	if len(p.Allow) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Allow))
	}
	if p.Allow[0].Command != "gh *" {
		t.Errorf("wrong rule remaining: %q", p.Allow[0].Command)
	}

	if p.Remove("nonexistent") {
		t.Fatal("expected Remove to return false for missing rule")
	}
}

func TestIsBlocked(t *testing.T) {
	if !IsBlocked("bash") {
		t.Error("expected bash to be blocked")
	}
	if !IsBlocked("python script.py") {
		t.Error("expected python to be blocked")
	}
	if IsBlocked("npm publish") {
		t.Error("expected npm to not be blocked")
	}
	if IsBlocked("gh pr create") {
		t.Error("expected gh to not be blocked")
	}
	if !IsBlocked("") {
		t.Error("expected empty command to be blocked")
	}
}

func TestMatchExtraArgs(t *testing.T) {
	p := &Policy{
		Allow: []Rule{
			{Command: "npm publish", Inject: []string{"NPM_TOKEN"}},
		},
	}

	// "npm publish --tag beta" should still match "npm publish"
	if _, ok := p.Match("npm", []string{"publish", "--tag", "beta"}); !ok {
		t.Fatal("expected match with extra trailing args")
	}
}
