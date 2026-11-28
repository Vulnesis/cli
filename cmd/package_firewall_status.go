package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/brand"
	pfw "github.com/vulnetix/cli/v4/pkg/packagefirewall"
)

var (
	packageFirewallStatusOutput   string
	packageFirewallStatusOffline  bool
	packageFirewallStatusProxyURL string
)

// Entitlement values of `package-firewall status -o json`.
const (
	pfwEntitled    = "entitled"
	pfwNotEntitled = "not_entitled"
	pfwUnknown     = "unknown"
)

// pfwEcosystemState is one ecosystem in `package-firewall status -o json`.
// It names the config file that points at the firewall and never its content.
type pfwEcosystemState struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Configured bool   `json:"configured"`
	// Scope is "user" for a file under the home directory, "env" for the
	// process environment (Go's GOPROXY), and empty when not configured.
	Scope string `json:"scope"`
	// Path is home-relative ("~/.npmrc") when under $HOME.
	Path string `json:"path"`
}

// pfwStatusDoc is `vulnetix package-firewall status -o json`. Keys are stable.
type pfwStatusDoc struct {
	ProxyHost   string              `json:"proxyHost"`
	Ecosystems  []pfwEcosystemState `json:"ecosystems"`
	Entitlement string              `json:"entitlement"`
}

// pfwAddonLookup asks the console for the add-on state; replaced in tests.
var pfwAddonLookup = liveAddonStatus

var packageFirewallStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which package managers use the Package Firewall",
	Long: `Show, for every supported ecosystem, whether its package manager is configured
to use the Vulnetix Package Firewall, and whether the org holds the add-on.

No credential, token or file content is printed. --offline skips the add-on
lookup (entitlement "unknown").

Examples:
  vulnetix package-firewall status
  vulnetix package-firewall status -o json --offline`,
	Args: cobra.NoArgs,
	RunE: runPackageFirewallStatus,
}

func init() {
	packageFirewallStatusCmd.Flags().StringVarP(&packageFirewallStatusOutput, "output", "o", "text", "Output format: text or json")
	packageFirewallStatusCmd.Flags().BoolVar(&packageFirewallStatusOffline, "offline", false, "Skip the add-on entitlement lookup (entitlement is \"unknown\")")
	packageFirewallStatusCmd.Flags().StringVar(&packageFirewallStatusProxyURL, "proxy-url", brand.URL(packageFirewallDefaultProxy), "Package Firewall proxy URL (host to detect)")
	packageFirewallCmd.AddCommand(packageFirewallStatusCmd)
}

func runPackageFirewallStatus(cmd *cobra.Command, _ []string) error {
	format := strings.ToLower(strings.TrimSpace(packageFirewallStatusOutput))
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown output format %q (want text or json)", packageFirewallStatusOutput)
	}
	proxyURL := strings.TrimSpace(packageFirewallStatusProxyURL)
	if proxyURL == "" {
		proxyURL = brand.URL(packageFirewallDefaultProxy)
	}
	host, err := parseProxyHost(proxyURL)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	doc := pfwStatusDoc{
		ProxyHost:   host,
		Ecosystems:  pfwEcosystemStates(home, host),
		Entitlement: pfwUnknown,
	}
	if !packageFirewallStatusOffline {
		doc.Entitlement = pfwEntitlement()
	}
	if format == "json" {
		return writeJSONDoc(cmd.OutOrStdout(), doc)
	}
	w := cmd.OutOrStdout()
	for _, e := range doc.Ecosystems {
		state := "not configured"
		if e.Configured {
			state = "configured"
		}
		line := fmt.Sprintf("%-10s %-15s", e.ID, state)
		if e.Path != "" {
			line += " " + e.Path
		} else if e.Scope == "env" {
			line += " (environment)"
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	fmt.Fprintf(w, "entitlement %s\n", doc.Entitlement)
	return nil
}

// pfwEntitlement maps the console's add-on answer. Without a credential, or
// when the lookup fails or times out, the answer is unknown.
func pfwEntitlement() string {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil {
		return pfwUnknown
	}
	st := pfwAddonLookup(creds)
	switch {
	case !st.Known:
		return pfwUnknown
	case st.Entitled:
		return pfwEntitled
	default:
		return pfwNotEntitled
	}
}

// pfwEcosystemStates is every known ecosystem, configured or not, in
// pfw.All() order. Files are read only to look for the proxy host.
func pfwEcosystemStates(home, host string) []pfwEcosystemState {
	detected := map[string]pfw.Detected{}
	for _, d := range pfw.Detect(home, host) {
		detected[d.Ecosystem.ID] = d
	}
	out := make([]pfwEcosystemState, 0, len(pfw.All()))
	for _, eco := range pfw.All() {
		s := pfwEcosystemState{ID: eco.ID, Label: eco.DisplayName}
		if d, ok := detected[eco.ID]; ok && d.Configured {
			s.Configured, s.Scope, s.Path = true, "user", homeRelative(home, d.Path)
		} else if eco.ID == "go" {
			s.Configured, s.Scope, s.Path = goFirewallConfigured(home, host)
		}
		out = append(out, s)
	}
	return out
}

// goFirewallConfigured reports Go: GOPROXY in the environment naming the
// firewall, else a GOPROXY line naming it in the shell rc that
// `package-firewall go` writes.
func goFirewallConfigured(home, host string) (bool, string, string) {
	if strings.Contains(os.Getenv("GOPROXY"), host) {
		return true, "env", ""
	}
	path, _, err := shellConfigPath()
	if err != nil {
		return false, "", ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "GOPROXY") && strings.Contains(line, host) {
			return true, "user", homeRelative(home, path)
		}
	}
	return false, "", ""
}

// homeRelative writes a path under home as "~/...".
func homeRelative(home, path string) string {
	if home == "" || path == "" {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	if rel == "." {
		return "~"
	}
	return "~/" + filepath.ToSlash(rel)
}

func writeJSONDoc(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// configuredEcosystemIDs is the ids of the ecosystems that use the firewall.
func configuredEcosystemIDs(home, host string) []string {
	ids := []string{}
	for _, e := range pfwEcosystemStates(home, host) {
		if e.Configured {
			ids = append(ids, e.ID)
		}
	}
	return ids
}
