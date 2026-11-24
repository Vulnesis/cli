package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestGoModKeepsGoInstallWorking guards the documented `go install
// github.com/vulnetix/cli/v4@latest` channel. go install refuses a module
// whose go.mod has an exclude or replace directive ("must not contain
// directives that would cause it to be interpreted differently than if it
// were the main module"). An exclude added for a local proxy that refuses an
// old version (v4.26.2's test-go-install failed this way) belongs in that
// proxy's fallback, GOPROXY=<firewall>|https://proxy.golang.org|direct, not in
// go.mod.
func TestGoModKeepsGoInstallWorking(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		for _, d := range []string{"exclude", "replace"} {
			if line == d+" (" || strings.HasPrefix(line, d+" ") {
				t.Errorf("go.mod:%d: %q directive breaks go install: %s", n, d, line)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
