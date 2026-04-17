package guard

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/term"
)

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

// IsAgent returns true if an AI agent is detected in the process tree.
func IsAgent() bool {
	pid := os.Getpid()

	for range 32 {
		ppid, name, err := parentProcess(pid)
		if err != nil || ppid <= 1 {
			break
		}

		nameLower := strings.ToLower(name)
		for _, agent := range agentProcesses {
			if strings.Contains(nameLower, agent) {
				return true
			}
		}

		pid = ppid
	}

	return false
}

// Confirm blocks agents entirely, then prompts humans for confirmation.
// Use this for commands that reveal secret values (show, edit, restore).
func Confirm() error {
	if IsAgent() {
		return fmt.Errorf("blocked: this command cannot be run from an AI agent")
	}

	if runtime.GOOS == "darwin" {
		return confirmDarwin()
	}

	return confirmLinux()
}

// confirmDarwin uses Touch ID if the helper is available.
// Without the helper, the macOS security CLI already prompts the user
// via a system dialog on keychain access, so no additional gate is needed.
func confirmDarwin() error {
	helper, err := findHelper()
	if err != nil {
		return nil
	}

	out, err := exec.Command(helper, "load", "ghostenv-auth-check").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "not found") {
			return nil
		}
		if strings.Contains(msg, "canceled") || strings.Contains(msg, "failed") {
			return fmt.Errorf("Touch ID authentication failed")
		}
		return nil
	}

	return nil
}

// confirmLinux requires an interactive terminal and a simple Enter press.
func confirmLinux() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	fmt.Fprintf(os.Stderr, "Press Enter to continue with secrets: ")
	var input string
	fmt.Scanln(&input)
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
