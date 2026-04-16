package guard

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// RequireTTY returns an error if stdin is not an interactive terminal.
// This blocks AI agents from accessing sensitive commands since they
// run commands non-interactively (no TTY attached).
func RequireTTY() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal. AI agents cannot access secrets directly")
	}
	return nil
}
