package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Exec runs a command with the given secrets injected as environment variables.
// The secrets only exist in the child process — they are never exported to the parent shell.
func Exec(name string, args []string, secrets map[string]string) error {
	binPath, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("command not found: %s", name)
	}

	// Start with the current environment
	env := os.Environ()

	// Inject secrets, overwriting any existing values
	existing := make(map[string]int)
	for i, e := range env {
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			existing[e[:idx]] = i
		}
	}

	for key, val := range secrets {
		entry := key + "=" + val
		if idx, ok := existing[key]; ok {
			env[idx] = entry
		} else {
			env = append(env, entry)
		}
	}

	// Replace the current process with the target command.
	// This ensures secrets only live in the child process.
	argv := append([]string{name}, args...)
	return syscall.Exec(binPath, argv, env)
}

// Run is like Exec but runs as a child process and returns.
// Use this when you need to continue after the command finishes.
func Run(name string, args []string, secrets map[string]string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Build env
	cmd.Env = os.Environ()
	for key, val := range secrets {
		cmd.Env = append(cmd.Env, key+"="+val)
	}

	return cmd.Run()
}

// RunCapture runs a command with secrets injected and captures stdout+stderr.
// Used by the MCP server to return output to the agent.
func RunCapture(name string, args []string, secrets map[string]string) (string, error) {
	cmd := exec.Command(name, args...)

	// Build env
	cmd.Env = os.Environ()
	for key, val := range secrets {
		cmd.Env = append(cmd.Env, key+"="+val)
	}

	out, err := cmd.CombinedOutput()
	return string(out), err
}
