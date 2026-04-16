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

// Confirm copies a random code to the clipboard and asks the user to paste it.
// expect/script can spoof a TTY and read terminal output, but cannot access
// the system clipboard, making this resistant to automation.
func Confirm() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	code := randomCode(6)

	if err := copyToClipboard(code); err != nil {
		return fmt.Errorf("could not copy to clipboard: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Confirm: a code was copied to your clipboard. Paste it here: ")

	var input string
	fmt.Scanln(&input)

	if strings.TrimSpace(input) != code {
		return fmt.Errorf("confirmation failed")
	}

	// Clear the clipboard so the code doesn't linger
	copyToClipboard("")

	return nil
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		// Try xclip first, fall back to xsel
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else {
			cmd = exec.Command("xsel", "--clipboard", "--input")
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
