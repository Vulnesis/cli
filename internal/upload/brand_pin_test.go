package upload

import (
	"github.com/vulnetix/cli/v4/pkg/brand"
	"os"
	"testing"
)

// These tests assert Vulnetix URLs. Vulnesis is the default brand (pkg/brand
// covers it); pin Vulnetix before anything reads the brand.
func TestMain(m *testing.M) {
	os.Setenv("VULNETIX_BRAND", "vulnetix")
	brand.Set(brand.Vulnetix)
	os.Exit(m.Run())
}
