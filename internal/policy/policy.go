package policy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy represents a .ghostenv/policy.yaml file.
type Policy struct {
	Allow []Rule `yaml:"allow"`
}

// Rule is one entry in the allowlist.
type Rule struct {
	Command string   `yaml:"command"` // e.g. "npm publish", "gh *"
	Inject  []string `yaml:"inject"`  // key names, or ["all"]
}

// Load reads policy.yaml from the given directory.
// Returns an empty policy (not an error) if the file does not exist.
func Load(dir string) (*Policy, error) {
	path := filepath.Join(dir, "policy.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Policy{}, nil
		}
		return nil, err
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Save writes the policy to policy.yaml in the given directory.
func (p *Policy) Save(dir string) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}

	header := "# ghostenv policy — commands allowed to receive secrets\n" +
		"# Edit this file to control which commands can access your secrets.\n" +
		"# Use 'inject: all' to inject every secret, or list specific key names.\n\n"

	return os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(header+string(data)), 0644)
}

// IsEmpty returns true if the policy has no rules.
func (p *Policy) IsEmpty() bool {
	return len(p.Allow) == 0
}

// Match finds the first rule whose command pattern matches the given binary and args.
// Returns the matched rule and true, or nil and false if no rule matches.
func (p *Policy) Match(bin string, args []string) (*Rule, bool) {
	binBase := filepath.Base(bin)
	for i := range p.Allow {
		if p.Allow[i].match(binBase, args) {
			return &p.Allow[i], true
		}
	}
	return nil, false
}

// match checks if a rule's command pattern matches the given binary name and args.
// Pattern format: "binary arg1 arg2" where * matches any single token,
// and a trailing * matches any remaining args.
func (r *Rule) match(bin string, args []string) bool {
	tokens := strings.Fields(r.Command)
	if len(tokens) == 0 {
		return false
	}

	// First token is the binary name
	if tokens[0] != bin {
		return false
	}

	pattern := tokens[1:]

	// No pattern args means match the binary alone (any subcommand)
	if len(pattern) == 0 {
		return true
	}

	// If pattern is just "*", match anything
	if len(pattern) == 1 && pattern[0] == "*" {
		return true
	}

	// Match positionally
	for i, pat := range pattern {
		// Trailing * matches one or more remaining args
		if pat == "*" && i == len(pattern)-1 {
			return len(args) > i
		}
		if i >= len(args) {
			return false
		}
		if pat != "*" && pat != args[i] {
			return false
		}
	}

	// All pattern tokens matched; args can have extra trailing args
	return true
}

// InjectAll returns true if the rule injects all secrets.
func (r *Rule) InjectAll() bool {
	for _, v := range r.Inject {
		if strings.ToLower(v) == "all" {
			return true
		}
	}
	return false
}

// FilterSecrets returns only the secrets whose keys are listed in the rule's Inject field.
// If InjectAll() is true, returns all secrets.
func (r *Rule) FilterSecrets(all map[string]string) map[string]string {
	if r.InjectAll() {
		return all
	}

	filtered := make(map[string]string, len(r.Inject))
	for _, key := range r.Inject {
		if val, ok := all[key]; ok {
			filtered[key] = val
		}
	}
	return filtered
}

// blockedBinaries are commands that can never be added to the policy.
// These are generic runtimes and shells that could trivially leak secrets.
var blockedBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true, "csh": true, "tcsh": true, "ksh": true,
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true,
	"env": true, "printenv": true, "export": true, "set": true,
	"echo": true, "cat": true, "tee": true, "xargs": true,
}

// IsBlocked returns true if a command pattern targets a blocked binary.
func IsBlocked(command string) bool {
	tokens := strings.Fields(command)
	if len(tokens) == 0 {
		return true
	}
	return blockedBinaries[tokens[0]]
}

// Add appends a rule to the policy. Returns an error if the command is blocked.
func (p *Policy) Add(command string, inject []string) error {
	tokens := strings.Fields(command)
	if len(tokens) == 0 {
		return fmt.Errorf("command cannot be empty")
	}
	if IsBlocked(command) {
		return fmt.Errorf("command %q is blocked — shells and generic runtimes cannot receive secrets", tokens[0])
	}

	// Check for duplicate
	for i, r := range p.Allow {
		if r.Command == command {
			p.Allow[i].Inject = inject
			return nil
		}
	}

	p.Allow = append(p.Allow, Rule{Command: command, Inject: inject})
	return nil
}

// Remove deletes a rule by command pattern. Returns true if a rule was removed.
func (p *Policy) Remove(command string) bool {
	for i, r := range p.Allow {
		if r.Command == command {
			p.Allow = append(p.Allow[:i], p.Allow[i+1:]...)
			return true
		}
	}
	return false
}

// knownTools maps binary names to default policy rules.
var knownTools = []struct {
	bin   string
	rules []Rule
}{
	{"npm", []Rule{{Command: "npm publish", Inject: []string{"NPM_TOKEN"}}}},
	{"gh", []Rule{{Command: "gh *", Inject: []string{"GITHUB_TOKEN"}}}},
	{"docker", []Rule{{Command: "docker push *", Inject: []string{"all"}}, {Command: "docker login", Inject: []string{"all"}}}},
	{"terraform", []Rule{{Command: "terraform apply", Inject: []string{"all"}}, {Command: "terraform plan", Inject: []string{"all"}}}},
	{"wrangler", []Rule{{Command: "wrangler deploy", Inject: []string{"CLOUDFLARE_API_TOKEN"}}, {Command: "wrangler publish", Inject: []string{"CLOUDFLARE_API_TOKEN"}}}},
	{"kubectl", []Rule{{Command: "kubectl *", Inject: []string{"all"}}}},
	{"vercel", []Rule{{Command: "vercel *", Inject: []string{"VERCEL_TOKEN"}}}},
	{"flyctl", []Rule{{Command: "flyctl deploy", Inject: []string{"FLY_API_TOKEN"}}}},
	{"aws", []Rule{{Command: "aws *", Inject: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}}}},
}

// GenerateStarter creates a starter policy by detecting which tools are installed.
func GenerateStarter() Policy {
	var rules []Rule
	for _, tool := range knownTools {
		if _, err := exec.LookPath(tool.bin); err == nil {
			rules = append(rules, tool.rules...)
		}
	}
	return Policy{Allow: rules}
}

// Format returns a human-readable representation of the policy.
func (p *Policy) Format() string {
	if p.IsEmpty() {
		return "No policy rules defined.\n"
	}

	var b strings.Builder
	for _, r := range p.Allow {
		inject := strings.Join(r.Inject, ", ")
		b.WriteString("  ")
		b.WriteString(r.Command)
		b.WriteString("  ->  ")
		b.WriteString(inject)
		b.WriteByte('\n')
	}
	return b.String()
}
