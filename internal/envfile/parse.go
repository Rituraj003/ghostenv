package envfile

import (
	"bufio"
	"os"
	"strings"
)

// KeyValue holds a single environment variable pair.
type KeyValue struct {
	Key   string
	Value string
}

// Parse reads a .env file and returns key-value pairs.
// Skips blank lines and comments (lines starting with #).
func Parse(path string) ([]KeyValue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pairs []KeyValue
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '='
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Strip surrounding quotes from value
		value = stripQuotes(value)

		if key != "" {
			pairs = append(pairs, KeyValue{Key: key, Value: value})
		}
	}

	return pairs, scanner.Err()
}

// Format writes key-value pairs as a .env formatted string.
func Format(pairs []KeyValue) string {
	var b strings.Builder
	for _, kv := range pairs {
		b.WriteString(kv.Key)
		b.WriteByte('=')
		if strings.ContainsAny(kv.Value, " \t\"'#") {
			b.WriteString("\"" + strings.ReplaceAll(kv.Value, "\"", "\\\"") + "\"")
		} else {
			b.WriteString(kv.Value)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			// Unescape backslash-escaped quotes inside double-quoted values
			return strings.ReplaceAll(s[1:len(s)-1], "\\\"", "\"")
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}
