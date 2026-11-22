package cmd

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

// noninteractiveCredentials picks the credential for `auth login
// --noninteractive`: an org-scoped ApiKey from --api-key or VULNETIX_API_KEY
// (with --org-id or VULNETIX_ORG_ID), else a SigV4 secret from VVD_ORG and
// VVD_SECRET, the same variables LoadCredentials reads. The SigV4 secret is
// taken from the environment only, so it never appears in a process list.
func noninteractiveCredentials(flagKey, flagOrg string, getenv func(string) string) (*auth.Credentials, error) {
	if key := firstNonEmpty(flagKey, getenv("VULNETIX_API_KEY")); key != "" {
		org := firstNonEmpty(flagOrg, getenv("VULNETIX_ORG_ID"))
		if org == "" {
			return nil, fmt.Errorf("missing org for noninteractive ApiKey login: pass --org-id or set VULNETIX_ORG_ID")
		}
		if _, err := uuid.Parse(org); err != nil {
			return nil, fmt.Errorf("--org-id must be a valid UUID, got: %s", org)
		}
		return &auth.Credentials{OrgID: org, APIKey: stripOrgPrefix(org, key), Method: auth.DirectAPIKey}, nil
	}
	if secret := getenv("VVD_SECRET"); secret != "" {
		org := firstNonEmpty(flagOrg, getenv("VVD_ORG"))
		if org == "" {
			return nil, fmt.Errorf("missing org for noninteractive SigV4 login: set VVD_ORG (or pass --org-id)")
		}
		if _, err := uuid.Parse(org); err != nil {
			return nil, fmt.Errorf("VVD_ORG must be a valid UUID, got: %s", org)
		}
		return &auth.Credentials{OrgID: org, Secret: secret, Method: auth.SigV4}, nil
	}
	return nil, fmt.Errorf("missing credentials for noninteractive login. Get your ApiKey and Org ID from your Vulnetix VDB account, then pass --api-key and --org-id (or set VULNETIX_API_KEY and VULNETIX_ORG_ID), or set VVD_ORG and VVD_SECRET for a SigV4 secret")
}
