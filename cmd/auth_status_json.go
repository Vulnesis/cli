package cmd

import (
	"os"
	"strings"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

// authStatusDoc is `vulnetix auth status -o json`. Keys are stable. It never
// carries a key, token, secret or any part of one, and makes no network call:
// Verified is always null here (run `auth verify` to check the credential).
type authStatusDoc struct {
	Authenticated   bool              `json:"authenticated"`
	OrgID           string            `json:"orgId"`
	Source          string            `json:"source"`
	Method          string            `json:"method"`
	PackageFirewall authStatusPFWPart `json:"packageFirewall"`
	Verified        *bool             `json:"verified"`
}

type authStatusPFWPart struct {
	Ecosystems []string `json:"ecosystems"`
}

func buildAuthStatusDoc() authStatusDoc {
	doc := authStatusDoc{PackageFirewall: authStatusPFWPart{Ecosystems: []string{}}}
	if creds, err := auth.LoadCredentials(); err == nil && creds != nil {
		doc.Authenticated = true
		doc.OrgID = creds.OrgID
		doc.Method = string(creds.Method)
		doc.Source = authSourceKey(auth.CredentialSource())
	}
	if home, err := os.UserHomeDir(); err == nil {
		doc.PackageFirewall.Ecosystems = configuredEcosystemIDs(home, auth.PackageFirewallMachine())
	}
	return doc
}

// authSourceKey maps auth.CredentialSource to env, project, home, keyring or
// netrc; "" when there is no credential.
func authSourceKey(source string) string {
	switch {
	case strings.HasPrefix(source, "environment"):
		return "env"
	case strings.HasPrefix(source, "keyring"):
		return "keyring"
	case strings.HasPrefix(source, "project"):
		return "project"
	case strings.HasPrefix(source, "home"):
		return "home"
	case strings.HasPrefix(source, "netrc"):
		return "netrc"
	default:
		return ""
	}
}
