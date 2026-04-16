package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ghostenv/ghostenv/internal/keychain"
)

func hasKeychain() bool {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("security", "help").Run() == nil
	case "linux":
		_, err := exec.LookPath("secret-tool")
		return err == nil
	}
	return false
}

func setupTestVault(t *testing.T) *Vault {
	t.Helper()
	if !hasKeychain() {
		t.Skip("no keychain available")
	}

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() {
		// Clean up keychain entry
		account := keychainAccount(filepath.Join(dir, ".ghostenv"))
		keychain.Delete(account)
		os.Chdir(origDir)
	})

	v, err := Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return v
}

func TestInitCreatesVaultDir(t *testing.T) {
	if !hasKeychain() {
		t.Skip("no keychain available")
	}

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer func() {
		account := keychainAccount(filepath.Join(dir, ".ghostenv"))
		keychain.Delete(account)
		os.Chdir(origDir)
	}()

	_, err := Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	ghostDir := filepath.Join(dir, ".ghostenv")
	if _, err := os.Stat(ghostDir); os.IsNotExist(err) {
		t.Error(".ghostenv directory was not created")
	}

	// master.key should NOT exist on disk anymore
	if _, err := os.Stat(filepath.Join(ghostDir, "master.key")); err == nil {
		t.Error("master.key should not be on disk — key should be in keychain")
	}
}

func TestInitFailsIfAlreadyExists(t *testing.T) {
	if !hasKeychain() {
		t.Skip("no keychain available")
	}

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer func() {
		account := keychainAccount(filepath.Join(dir, ".ghostenv"))
		keychain.Delete(account)
		os.Chdir(origDir)
	}()

	_, err := Init()
	if err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	_, err = Init()
	if err == nil {
		t.Error("second Init should have failed")
	}
}

func TestSetGetDelete(t *testing.T) {
	v := setupTestVault(t)

	v.Set("API_KEY", "secret123")
	v.Set("TOKEN", "tok456")

	val, ok := v.Get("API_KEY")
	if !ok || val != "secret123" {
		t.Errorf("expected secret123, got %q (ok=%v)", val, ok)
	}

	if !v.Has("TOKEN") {
		t.Error("expected Has(TOKEN) to be true")
	}

	v.Delete("TOKEN")
	if v.Has("TOKEN") {
		t.Error("expected Has(TOKEN) to be false after delete")
	}

	_, ok = v.Get("TOKEN")
	if ok {
		t.Error("expected Get(TOKEN) to return false after delete")
	}
}

func TestSaveAndReopen(t *testing.T) {
	if !hasKeychain() {
		t.Skip("no keychain available")
	}

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer func() {
		account := keychainAccount(filepath.Join(dir, ".ghostenv"))
		keychain.Delete(account)
		os.Chdir(origDir)
	}()

	v, err := Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	v.Set("SECRET", "myvalue")
	v.SetEnvFile(".env")
	if err := v.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Reopen
	v2, err := Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	val, ok := v2.Get("SECRET")
	if !ok || val != "myvalue" {
		t.Errorf("after reopen: expected myvalue, got %q (ok=%v)", val, ok)
	}

	if v2.EnvFile() != ".env" {
		t.Errorf("expected env file .env, got %q", v2.EnvFile())
	}
}

func TestCount(t *testing.T) {
	v := setupTestVault(t)

	if v.Count() != 0 {
		t.Errorf("expected 0, got %d", v.Count())
	}

	v.Set("A", "1")
	v.Set("B", "2")

	if v.Count() != 2 {
		t.Errorf("expected 2, got %d", v.Count())
	}
}

func TestEnvMap(t *testing.T) {
	v := setupTestVault(t)

	v.Set("KEY1", "val1")
	v.Set("KEY2", "val2")

	m := v.EnvMap()
	if m["KEY1"] != "val1" || m["KEY2"] != "val2" {
		t.Errorf("unexpected env map: %v", m)
	}
}

func TestList(t *testing.T) {
	v := setupTestVault(t)

	v.Set("ZEBRA", "z")
	v.Set("ALPHA", "a")

	list := v.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d", len(list))
	}
	if list[0].Key != "ALPHA" || list[1].Key != "ZEBRA" {
		t.Error("list should be sorted alphabetically")
	}
}

func TestOpenWithoutInit(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	_, err := Open()
	if err == nil {
		t.Error("Open without Init should fail")
	}
}
