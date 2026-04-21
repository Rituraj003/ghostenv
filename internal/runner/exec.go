package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// buildEnv returns the current environment with secrets injected,
// overwriting any existing values for the same keys.
func buildEnv(secrets map[string]string) []string {
	env := os.Environ()

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

	return env
}

// Exec runs a command with the given secrets injected as environment variables.
// The secrets only exist in the child process — they are never exported to the parent shell.
func Exec(name string, args []string, secrets map[string]string) error {
	binPath, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("command not found: %s", name)
	}

	argv := append([]string{name}, args...)
	return syscall.Exec(binPath, argv, buildEnv(secrets))
}

// Run is like Exec but runs as a child process and returns.
func Run(name string, args []string, secrets map[string]string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = buildEnv(secrets)
	return cmd.Run()
}

// RunCapture runs a command with secrets injected and captures stdout+stderr.
func RunCapture(name string, args []string, secrets map[string]string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = buildEnv(secrets)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
