package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/pkg/auth"
	pfw "github.com/vulnetix/cli/v4/pkg/packagefirewall"
)

const statusCanary = "CANARY-secret-7d41c0ffee"

// statusEnv isolates HOME, the working directory and every credential source.
func statusEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(auth.CredentialsDirEnv, filepath.Join(home, ".vulnetix"))
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("GOPROXY", "")
	t.Setenv("NETRC", filepath.Join(home, ".netrc"))
	for _, k := range []string{"VULNETIX_API_TOKEN", "VULNETIX_API_KEY", "VULNETIX_ORG_ID", "VVD_ORG", "VVD_SECRET"} {
		t.Setenv(k, "")
	}
	t.Chdir(t.TempDir())
	return home
}

func writeStatusFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runCobra(t *testing.T, c *cobra.Command, run func(*cobra.Command, []string) error) string {
	t.Helper()
	var out bytes.Buffer
	c.SetOut(&out)
	t.Cleanup(func() { c.SetOut(nil) })
	if err := run(c, nil); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestPackageFirewallStatusJSON(t *testing.T) {
	host := auth.PackageFirewallMachine()
	cases := []struct {
		name        string
		setup       func(t *testing.T, home string)
		offline     bool
		addon       addonStatus
		wantConf    map[string]string // id -> path
		wantEntitle string
	}{
		{
			name:        "nothing configured, no credential",
			wantConf:    map[string]string{},
			wantEntitle: pfwUnknown,
		},
		{
			name: "npm, pypi and go configured, entitled",
			setup: func(t *testing.T, home string) {
				writeStatusFile(t, filepath.Join(home, ".npmrc"), "registry=https://"+host+"/npm/\n//"+host+"/:_auth="+statusCanary+"\n")
				writeStatusFile(t, filepath.Join(home, ".config", "pip", "pip.conf"), "[global]\nindex-url = https://org:"+statusCanary+"@"+host+"/pypi/simple\n")
				writeStatusFile(t, filepath.Join(home, ".bashrc"), "# Vulnetix Package Firewall\nexport GOPROXY=\"https://"+host+"|https://proxy.golang.org|direct\"\n")
				t.Setenv("VULNETIX_API_KEY", statusCanary)
				t.Setenv("VULNETIX_ORG_ID", "org-1")
			},
			addon:       addonStatus{Known: true, Enforced: true, Entitled: true},
			wantConf:    map[string]string{"npm": "~/.npmrc", "pypi": "~/.config/pip/pip.conf", "go": "~/.bashrc"},
			wantEntitle: pfwEntitled,
		},
		{
			name: "credential, not entitled",
			setup: func(t *testing.T, home string) {
				t.Setenv("VULNETIX_API_KEY", statusCanary)
				t.Setenv("VULNETIX_ORG_ID", "org-1")
			},
			addon:       addonStatus{Known: true, Enforced: true},
			wantConf:    map[string]string{},
			wantEntitle: pfwNotEntitled,
		},
		{
			name: "credential, lookup failed",
			setup: func(t *testing.T, home string) {
				t.Setenv("VULNETIX_API_KEY", statusCanary)
				t.Setenv("VULNETIX_ORG_ID", "org-1")
			},
			wantConf:    map[string]string{},
			wantEntitle: pfwUnknown,
		},
		{
			name: "offline skips the lookup",
			setup: func(t *testing.T, home string) {
				t.Setenv("VULNETIX_API_KEY", statusCanary)
				t.Setenv("VULNETIX_ORG_ID", "org-1")
				t.Setenv("GOPROXY", "https://"+host+"|direct")
			},
			offline:     true,
			addon:       addonStatus{Known: true, Entitled: true},
			wantConf:    map[string]string{"go": ""},
			wantEntitle: pfwUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := statusEnv(t)
			if tc.setup != nil {
				tc.setup(t, home)
			}
			called := false
			oldLookup := pfwAddonLookup
			pfwAddonLookup = func(*auth.Credentials) addonStatus { called = true; return tc.addon }
			oldOut, oldOff, oldProxy := packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL
			packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL = "json", tc.offline, "https://"+host
			t.Cleanup(func() {
				pfwAddonLookup = oldLookup
				packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL = oldOut, oldOff, oldProxy
			})

			out := runCobra(t, packageFirewallStatusCmd, runPackageFirewallStatus)
			if strings.Contains(out, statusCanary) {
				t.Fatalf("secret leaked: %s", out)
			}
			if tc.offline && called {
				t.Fatal("--offline made the add-on lookup")
			}
			var doc pfwStatusDoc
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out)
			}
			if doc.ProxyHost != host || doc.Entitlement != tc.wantEntitle {
				t.Fatalf("proxyHost=%q entitlement=%q", doc.ProxyHost, doc.Entitlement)
			}
			if len(doc.Ecosystems) != len(pfw.All()) {
				t.Fatalf("got %d ecosystems, want every one of %d", len(doc.Ecosystems), len(pfw.All()))
			}
			for _, e := range doc.Ecosystems {
				want, ok := tc.wantConf[e.ID]
				if e.Configured != ok || e.Path != want {
					t.Errorf("%s: configured=%v path=%q, want %v %q", e.ID, e.Configured, e.Path, ok, want)
				}
				if e.Configured && e.Scope != "user" && e.Scope != "env" {
					t.Errorf("%s: scope %q", e.ID, e.Scope)
				}
				if e.Label == "" {
					t.Errorf("%s: no label", e.ID)
				}
			}
			for _, k := range []string{`"proxyHost"`, `"ecosystems"`, `"entitlement"`, `"id"`, `"label"`, `"configured"`, `"scope"`, `"path"`} {
				if !strings.Contains(out, k) {
					t.Errorf("missing key %s", k)
				}
			}
		})
	}
}

func TestPackageFirewallStatusText(t *testing.T) {
	home := statusEnv(t)
	host := auth.PackageFirewallMachine()
	writeStatusFile(t, filepath.Join(home, ".npmrc"), "registry=https://"+host+"/npm/\n//"+host+"/:_auth="+statusCanary+"\n")
	// The --proxy-url default is read at package init, before TestMain pins the
	// brand, so set the host the files name explicitly.
	oldOut, oldOff, oldProxy := packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL
	packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL = "text", true, "https://"+host
	t.Cleanup(func() {
		packageFirewallStatusOutput, packageFirewallStatusOffline, packageFirewallStatusProxyURL = oldOut, oldOff, oldProxy
	})

	out := runCobra(t, packageFirewallStatusCmd, runPackageFirewallStatus)
	if strings.Contains(out, statusCanary) {
		t.Fatalf("secret leaked: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(pfw.All())+1 {
		t.Fatalf("want one line per ecosystem plus entitlement, got:\n%s", out)
	}
	if !strings.Contains(out, "npm        configured      ~/.npmrc") || !strings.HasSuffix(out, "entitlement unknown\n") {
		t.Fatalf("unexpected text:\n%s", out)
	}
}

func TestAuthStatusJSONNeverIncludesTheSecret(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, home string)
		want  authStatusDoc
	}{
		{
			name: "unauthenticated",
			want: authStatusDoc{PackageFirewall: authStatusPFWPart{Ecosystems: []string{}}},
		},
		{
			name: "env api key",
			setup: func(t *testing.T, home string) {
				t.Setenv("VULNETIX_API_KEY", statusCanary)
				t.Setenv("VULNETIX_ORG_ID", "org-1")
				host := auth.PackageFirewallMachine()
				writeStatusFile(t, filepath.Join(home, ".cargo", "config.toml"), "[registries.vulnetix]\nindex = \"sparse+https://"+host+"/cargo/\"\ntoken = \""+statusCanary+"\"\n")
			},
			want: authStatusDoc{Authenticated: true, OrgID: "org-1", Source: "env", Method: "apikey", PackageFirewall: authStatusPFWPart{Ecosystems: []string{"cargo"}}},
		},
		{
			name: "env bearer token",
			setup: func(t *testing.T, home string) {
				t.Setenv("VULNETIX_API_TOKEN", statusCanary)
			},
			want: authStatusDoc{Authenticated: true, Source: "env", Method: "token", PackageFirewall: authStatusPFWPart{Ecosystems: []string{}}},
		},
		{
			name: "home file",
			setup: func(t *testing.T, home string) {
				if err := auth.SaveCredentials(&auth.Credentials{OrgID: "org-2", APIKey: statusCanary, Method: auth.DirectAPIKey}, auth.StoreHome); err != nil {
					t.Fatal(err)
				}
			},
			want: authStatusDoc{Authenticated: true, OrgID: "org-2", Source: "home", Method: "apikey", PackageFirewall: authStatusPFWPart{Ecosystems: []string{}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := statusEnv(t)
			if tc.setup != nil {
				tc.setup(t, home)
			}
			old := authStatusOutput
			authStatusOutput = "json"
			t.Cleanup(func() { authStatusOutput = old })

			out := runCobra(t, authStatusCmd, authStatusCmd.RunE)
			if strings.Contains(out, statusCanary) || strings.Contains(out, statusCanary[len(statusCanary)-4:]) {
				t.Fatalf("secret (or its masked tail) leaked: %s", out)
			}
			var raw map[string]any
			if err := json.Unmarshal([]byte(out), &raw); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out)
			}
			if v, ok := raw["verified"]; !ok || v != nil {
				t.Errorf("verified = %v (present %v), want null", v, ok)
			}
			var got authStatusDoc
			_ = json.Unmarshal([]byte(out), &got)
			gb, _ := json.Marshal(got)
			wb, _ := json.Marshal(tc.want)
			if string(gb) != string(wb) {
				t.Errorf("got  %s\nwant %s", gb, wb)
			}
		})
	}
}

func TestHomeRelative(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "u")
	for in, want := range map[string]string{
		filepath.Join(home, ".npmrc"):          "~/.npmrc",
		filepath.Join(home, ".m2", "settings"): "~/.m2/settings",
		"/etc/pip.conf":                        "/etc/pip.conf",
		filepath.Join(home+"x", ".npmrc"):      filepath.Join(home+"x", ".npmrc"),
	} {
		if got := homeRelative(home, in); got != want {
			t.Errorf("homeRelative(%q) = %q, want %q", in, got, want)
		}
	}
}
