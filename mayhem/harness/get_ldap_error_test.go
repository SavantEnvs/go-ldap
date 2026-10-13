package ldap

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Mayhem keeps only the first ~1 KB of a crash's stderr, which libFuzzer's banner and the runtime's
// own frames use up before the panicking line; print the project's frames up front, then re-panic.
func printAppFrames() {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	var b strings.Builder
	b.WriteString("goroutine 1 [running]:\n")
	for {
		fr, more := frames.Next()
		if !strings.HasPrefix(fr.Function, "runtime.") {
			fmt.Fprintf(&b, "%s(...)\n\t%s:%d\n", fr.Function, fr.File, fr.Line)
		}
		if !more {
			break
		}
	}
	fmt.Fprintln(os.Stderr, b.String())
}

// Named apart from upstream's own FuzzGetLDAPError, which FIX adds to this package.
// f.Data is the raw input: go-118-fuzz-build's testing shim, which replaces "testing" at build time.
// f.Fuzz would wrap it in a go-fuzz-headers encoding and mangle the BER.
func FuzzMinedGetLDAPError(f *testing.F) {
	defer func() {
		if r := recover(); r != nil {
			printAppFrames()
			panic(r)
		}
	}()
	packet, err := ber.ReadPacket(bytes.NewReader(f.Data))
	if err != nil {
		return
	}
	_ = GetLDAPError(packet)
}
