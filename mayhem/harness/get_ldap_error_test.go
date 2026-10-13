package harness

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

func FuzzGetLDAPError(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := ber.ReadPacket(bytes.NewReader(data))
		if err != nil {
			return
		}
		_ = ldap.GetLDAPError(packet)
	})
}
