package cmd

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

func TestNoninteractiveCredentials(t *testing.T) {
	const org = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name             string
		flagKey, flagOrg string
		env              map[string]string
		method           auth.AuthMethod
		err              string
	}{
		{name: "apikey env", env: map[string]string{"VULNETIX_API_KEY": "k", "VULNETIX_ORG_ID": org}, method: auth.DirectAPIKey},
		{name: "apikey flags", flagKey: "k", flagOrg: org, method: auth.DirectAPIKey},
		{name: "apikey wins over sigv4", env: map[string]string{"VULNETIX_API_KEY": "k", "VULNETIX_ORG_ID": org, "VVD_ORG": org, "VVD_SECRET": "s"}, method: auth.DirectAPIKey},
		{name: "sigv4 env", env: map[string]string{"VVD_ORG": org, "VVD_SECRET": "s"}, method: auth.SigV4},
		{name: "sigv4 org flag", flagOrg: org, env: map[string]string{"VVD_SECRET": "s"}, method: auth.SigV4},
		{name: "sigv4 without org", env: map[string]string{"VVD_SECRET": "s"}, err: "VVD_ORG"},
		{name: "sigv4 bad org", env: map[string]string{"VVD_ORG": "nope", "VVD_SECRET": "s"}, err: "valid UUID"},
		{name: "apikey without org", env: map[string]string{"VULNETIX_API_KEY": "k"}, err: "VULNETIX_ORG_ID"},
		{name: "nothing", err: "VVD_SECRET"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := noninteractiveCredentials(c.flagKey, c.flagOrg, env(c.env))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want it to mention %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Method != c.method || got.OrgID != org {
				t.Fatalf("got %+v", got)
			}
			if c.method == auth.SigV4 && (got.Secret != "s" || got.APIKey != "") {
				t.Fatalf("sigv4 creds = %+v", got)
			}
		})
	}
}
