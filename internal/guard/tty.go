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

// Confirm runs three checks before allowing access to secrets:
// 1. Process tree — blocks if a known AI agent is an ancestor
// 2. TTY — blocks if stdin is not an interactive terminal
// 3. Clipboard code — copies a code to clipboard, user must paste it
// On headless/remote systems without clipboard, falls back to terminal prompt.
func Confirm() error {
	if err := checkProcessTree(); err != nil {
		return err
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	code := randomCode(6)

	if err := copyToClipboard(code); err != nil {
		// No clipboard available — fall back to terminal prompt
		return confirmViaTerminal(code)
	}

	fmt.Fprintf(os.Stderr, "Confirm: a code was copied to your clipboard. Paste it here: ")

	var input string
	fmt.Scanln(&input)

	// Clear clipboard
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

// checkProcessTree walks up the process tree and blocks if any ancestor
// is a known AI agent. You cannot fake your parent process name.
func checkProcessTree() error {
	pid := os.Getpid()

	for range 32 { // max depth to avoid infinite loops
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

// parentProcess returns the parent PID and process name for a given PID.
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

// parentProcessPS uses ps to get parent PID and name (macOS).
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

	// ps on macOS may show full path
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	return ppid, name, nil
}

// parentProcessLinux reads /proc to get parent PID and name.
func parentProcessLinux(pid int) (int, string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}

	// Format: pid (name) state ppid ...
	s := string(data)

	// Find process name between parentheses
	openParen := strings.IndexByte(s, '(')
	closeParen := strings.LastIndexByte(s, ')')
	if openParen < 0 || closeParen < 0 {
		return 0, "", fmt.Errorf("unexpected stat format")
	}
	name := s[openParen+1 : closeParen]

	// Fields after the closing paren
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
