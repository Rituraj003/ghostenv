package guard

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/term"
)

const codeChars = "abcdefghjkmnpqrstuvwxyz23456789"

// Known AI agent process names.
var agentProcesses = []string{
	"claude",
	"codex",
	"cursor",
	"aider",
	"copilot",
	"cline",
	"continue",
	"windsurf",
}

// Confirm gates access to secrets with platform-appropriate checks:
//
// macOS:  process tree check → Touch ID (via ghostenv-keychain helper)
// Linux:  process tree check → TTY check → clipboard code (or terminal code fallback)
func Confirm() error {
	if err := checkProcessTree(); err != nil {
		return err
	}

	// On macOS, Touch ID is the gate — no clipboard/code needed
	if runtime.GOOS == "darwin" {
		return requireTouchID()
	}

	// Linux/other: TTY check + clipboard or terminal code
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	code := randomCode(6)

	if err := copyToClipboard(code); err != nil {
		return confirmViaTerminal(code)
	}

	fmt.Fprintf(os.Stderr, "Confirm: a code was copied to your clipboard. Paste it here: ")

	var input string
	fmt.Scanln(&input)

	copyToClipboard("")

	if strings.TrimSpace(input) != code {
		return fmt.Errorf("confirmation failed")
	}

	return nil
}

// requireTouchID triggers Touch ID via the ghostenv-keychain helper.
// If the helper isn't available or no biometrics hardware, it passes through.
func requireTouchID() error {
	helper, err := findHelper()
	if err != nil {
		// No helper — fall back to TTY + clipboard
		return fallbackConfirm()
	}

	// Use a dummy load call to trigger Touch ID.
	// The helper requires Touch ID before returning any key.
	// We use a special account that always exists for auth-only checks.
	out, err := exec.Command(helper, "load", "ghostenv-auth-check").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "not found") {
			// No auth-check key — Touch ID isn't set up yet, allow through
			return nil
		}
		if strings.Contains(msg, "canceled") || strings.Contains(msg, "failed") {
			return fmt.Errorf("Touch ID authentication failed")
		}
		// Other error — fall back
		return fallbackConfirm()
	}

	return nil
}

// fallbackConfirm is used when Touch ID is not available on macOS.
func fallbackConfirm() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	code := randomCode(6)

	if err := copyToClipboard(code); err != nil {
		return confirmViaTerminal(code)
	}

	fmt.Fprintf(os.Stderr, "Confirm: a code was copied to your clipboard. Paste it here: ")

	var input string
	fmt.Scanln(&input)

	copyToClipboard("")

	if strings.TrimSpace(input) != code {
		return fmt.Errorf("confirmation failed")
	}

	return nil
}

// confirmViaTerminal shows the code in the terminal (fallback for headless systems).
func confirmViaTerminal(code string) error {
	fmt.Fprintf(os.Stderr, "Confirm: type %q to continue: ", code)

	var input string
	fmt.Scanln(&input)

	if strings.TrimSpace(input) != code {
		return fmt.Errorf("confirmation failed")
	}

	return nil
}

func findHelper() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		candidate := exe[:len(exe)-len("ghostenv")] + "ghostenv-keychain"
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return exec.LookPath("ghostenv-keychain")
}

// checkProcessTree walks up the process tree and blocks if any ancestor
// is a known AI agent.
func checkProcessTree() error {
	pid := os.Getpid()

	for range 32 {
		ppid, name, err := parentProcess(pid)
		if err != nil || ppid <= 1 {
			break
		}

		nameLower := strings.ToLower(name)
		for _, agent := range agentProcesses {
			if strings.Contains(nameLower, agent) {
				return fmt.Errorf("blocked: detected AI agent %q in process tree (pid %d)", name, pid)
			}
		}

		pid = ppid
	}

	return nil
}

func parentProcess(pid int) (int, string, error) {
	switch runtime.GOOS {
	case "darwin":
		return parentProcessPS(pid)
	case "linux":
		return parentProcessLinux(pid)
	default:
		return 0, "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func parentProcessPS(pid int) (int, string, error) {
	out, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err != nil {
		return 0, "", err
	}

	line := strings.TrimSpace(string(out))
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("unexpected ps output: %q", line)
	}

	var ppid int
	fmt.Sscanf(parts[0], "%d", &ppid)
	name := parts[len(parts)-1]

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	return ppid, name, nil
}

func parentProcessLinux(pid int) (int, string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}

	s := string(data)
	openParen := strings.IndexByte(s, '(')
	closeParen := strings.LastIndexByte(s, ')')
	if openParen < 0 || closeParen < 0 {
		return 0, "", fmt.Errorf("unexpected stat format")
	}
	name := s[openParen+1 : closeParen]

	rest := strings.Fields(s[closeParen+2:])
	if len(rest) < 2 {
		return 0, "", fmt.Errorf("unexpected stat format")
	}

	var ppid int
	fmt.Sscanf(rest[1], "%d", &ppid)

	return ppid, name, nil
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("no clipboard command available")
		}
	default:
		return fmt.Errorf("clipboard not supported on %s", runtime.GOOS)
	}

	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func randomCode(length int) string {
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeChars))))
		b[i] = codeChars[n.Int64()]
	}
	return string(b)
}
