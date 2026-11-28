package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/provision"
)

func runStatus(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	old := statusOut
	statusOut = &buf
	t.Cleanup(func() { statusOut = old })
	err := statusCmd(args)

	return buf.String(), err
}

func TestStatusJSON(t *testing.T) {
	const canary = "CANARY-sensor-secret-9f3e"
	cases := []struct {
		name     string
		enrolled bool
		active   string
		wantExit bool
	}{
		{name: "enrolled and active", enrolled: true, active: "active"},
		{name: "not enrolled, inactive", enrolled: false, active: "inactive", wantExit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys, _ := withFakeSystem(t)
			sys.active, sys.enabled = tc.active, "enabled"
			configDir, stateDir := t.TempDir(), t.TempDir()
			store := provision.Store{Dir: configDir}
			if tc.enrolled {
				if err := store.SaveCredential(provision.Credential{Scheme: "Sensor", Value: canary, DeviceUUID: "dev-1"}); err != nil {
					t.Fatal(err)
				}
				snap := provision.Snapshot{
					Profile:    provision.ProfileRef{UUID: "p-1", Name: "Laptops"},
					Config:     provision.Config{Mode: "guard", Protection: provision.Hardened},
					ConfigEtag: "etag-7",
				}
				b, _ := json.Marshal(snap)
				if err := os.WriteFile(store.ConfigPath(), b, 0o644); err != nil {
					t.Fatal(err)
				}
				at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
				hb, _ := json.Marshal(healthState{Version: "4.1.0", At: at})
				_ = os.WriteFile(filepath.Join(stateDir, healthStamp), hb, 0o644)
				saveUpdateState(stateDir, updateState{CheckedAt: at, Latest: "4.2.0", Held: "major"})
			}

			out, err := runStatus(t, "--config-dir", configDir, "--state-dir", stateDir, "-o", "json")
			var code exitCode
			if tc.wantExit != errors.As(err, &code) || (tc.wantExit && code != 3) {
				t.Fatalf("err = %v, want exit 3: %v", err, tc.wantExit)
			}
			if strings.Contains(out, canary) {
				t.Fatalf("credential leaked into status JSON: %s", out)
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out)
			}
			for _, k := range []string{"installed", "version", "enrolled", "profile", "protection", "mode", "configEtag", "service", "guard", "health", "update"} {
				if _, ok := doc[k]; !ok {
					t.Errorf("missing key %q", k)
				}
			}
			if doc["enrolled"] != tc.enrolled || doc["installed"] != true {
				t.Errorf("enrolled/installed = %v/%v", doc["enrolled"], doc["installed"])
			}
			svc := doc["service"].(map[string]any)
			if svc["active"] != (tc.active == "active") || svc["enabled"] != true {
				t.Errorf("service = %v", svc)
			}
			if tc.enrolled {
				if doc["profile"] != "p-1" || doc["mode"] != "guard" || doc["protection"] != provision.Hardened || doc["configEtag"] != "etag-7" {
					t.Errorf("profile fields = %v", doc)
				}
				h := doc["health"].(map[string]any)
				if h["version"] != "4.1.0" || h["at"] != "2026-11-21T10:00:00Z" {
					t.Errorf("health = %v", h)
				}
				u := doc["update"].(map[string]any)
				if u["latest"] != "4.2.0" || u["held"] != "major" {
					t.Errorf("update = %v", u)
				}
			} else if doc["health"] != nil || doc["update"] != nil || doc["profile"] != "" {
				t.Errorf("unenrolled doc = %v", doc)
			}
		})
	}
}

func TestStatusTextUnchanged(t *testing.T) {
	sys, _ := withFakeSystem(t)
	sys.active, sys.enabled = "active", "enabled"
	out, err := runStatus(t, "--config-dir", t.TempDir(), "--state-dir", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "enrolled     false\nprofile      none (") || !strings.HasSuffix(out, "service      active, enabled\n") {
		t.Fatalf("text output changed:\n%s", out)
	}
}

func TestStatusRejectsUnknownOutput(t *testing.T) {
	withFakeSystem(t)
	if _, err := runStatus(t, "--config-dir", t.TempDir(), "-o", "yaml"); err == nil {
		t.Fatal("want an error for -o yaml")
	}
}
