package scrub

import "strings"

// Output replaces any occurrence of real secret values in the output
// with [REDACTED]. This prevents secrets from leaking through command output.
func Output(output string, secrets map[string]string) string {
	for key, val := range secrets {
		if val == "" {
			continue
		}
		output = strings.ReplaceAll(output, val, "[REDACTED:"+key+"]")
	}
	return output
}
