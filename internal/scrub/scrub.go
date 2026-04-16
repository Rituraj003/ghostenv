package scrub

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

type replacement struct {
	find    string
	replace string
}

// Output replaces any occurrence of real secret values in the output
// with [REDACTED]. Also catches base64, hex, and URL-encoded forms.
func Output(output string, secrets map[string]string) string {
	var reps []replacement

	for key, val := range secrets {
		if val == "" {
			continue
		}
		tag := "[REDACTED:" + key + "]"
		reps = append(reps, replacement{val, tag})

		// Only encode-scrub secrets >= 8 chars to avoid false positives
		if len(val) >= 8 {
			for _, enc := range encodedVariants(val) {
				if enc != val {
					reps = append(reps, replacement{enc, tag})
				}
			}
		}
	}

	// Sort longest first to avoid partial match corruption
	sort.Slice(reps, func(i, j int) bool {
		return len(reps[i].find) > len(reps[j].find)
	})

	for _, r := range reps {
		output = strings.ReplaceAll(output, r.find, r.replace)
	}
	return output
}

func encodedVariants(val string) []string {
	b := []byte(val)
	return []string{
		base64.StdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		url.QueryEscape(val),
	}
}
