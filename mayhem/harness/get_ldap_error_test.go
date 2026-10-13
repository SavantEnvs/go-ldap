package harness

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// f.Data is the raw input: go-118-fuzz-build's testing shim, which replaces "testing" at build time.
// f.Fuzz would wrap it in a go-fuzz-headers encoding and mangle the BER.
func FuzzGetLDAPError(f *testing.F) {
	packet, err := ber.ReadPacket(bytes.NewReader(f.Data))
	if err != nil {
		return
	}
	_ = ldap.GetLDAPError(packet)
}
