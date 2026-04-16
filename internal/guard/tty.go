package guard

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/term"
)

const codeChars = "abcdefghjkmnpqrstuvwxyz23456789"

// Confirm requires the user to type back a random 4-char code.
// Blocks AI agents since they can't respond to interactive prompts.
func Confirm() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this command requires an interactive terminal")
	}

	code := randomCode(4)
	fmt.Fprintf(os.Stderr, "Confirm: type %q to continue: ", code)

	var input string
	fmt.Scanln(&input)

	if strings.TrimSpace(input) != code {
		return fmt.Errorf("confirmation failed")
	}

	return nil
}

func randomCode(length int) string {
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeChars))))
		b[i] = codeChars[n.Int64()]
	}
	return string(b)
}
