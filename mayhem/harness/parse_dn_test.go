package harness

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// f.Data is the raw input: go-118-fuzz-build's testing shim, which replaces "testing" at build time.
func FuzzParseDN(f *testing.F) {
	_, _ = ldap.ParseDN(string(f.Data))
}
