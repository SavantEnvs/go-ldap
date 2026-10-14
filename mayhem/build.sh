#!/usr/bin/env bash
#
# go-ldap mining layer build: builds the FuzzParseDN harness (mayhem/harness/parse_dn_test.go: ldap.ParseDN
# on the raw input) as a sanitized libFuzzer binary, replicating OSS-Fuzz's compile_native_go_fuzzer
# (go-118-fuzz-build path), and links it against the libFuzzer engine with clang + ASan.
#
# We produce:
#   /mayhem/fuzz_parse_dn
#
# DWARF gate (SPEC §6.2 item 10): Go's gc compiler always emits DWARF4 (no downgrade flag).
# The C/CGO shims compiled by clang default to DWARF5 with clang-19. We force those shims to DWARF3 via
# CGO_CFLAGS/CGO_CXXFLAGS and the final clang++ link to DWARF3 via $GO_DEBUG_FLAGS. The verify check uses the
# FIRST CU's DWARF version, which is the C shim at DWARF3.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An
# explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step. Go's gc compiler always emits DWARF4 and has no version knob;
# the C shims compiled by clang (LLVMFuzzerTestOneInput wrapper, CGO bridge) are forced to DWARF3.
# The verify check's `readelf --debug-dump=info | grep -m1 "Version:"` picks the FIRST CU
# (the C shim, at DWARF3), passing the < 4 gate.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# GOROOT/GOPATH/GOMODCACHE are pinned under /opt/toolchains in the Dockerfile ENV so they are
# correct regardless of $HOME. The module cache doubles as a FILE PROXY; set GOPROXY to prefer
# it, with network as fallback (offline re-run resolves from cache; first online build fills it).
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

# Mining layer: the harness lives in mayhem/harness/ and is built as its own throwaway module under
# mayhem-build/, with the v3 module replaced by the checkout (BASE has no ParseDN fuzzer under v3/). The same
# layer builds on BASE and on FIX, and the tree stays clean.
cd "$SRC/v3"
go version

mkdir -p "$SRC/mayhem-build"
H="$SRC/mayhem-build/harness"
rm -rf "$H" && mkdir -p "$H" && cp "$SRC"/mayhem/harness/*.go "$H"/
cd "$H"
go mod init mayhemharness
go mod edit -require github.com/go-ldap/ldap/v3@v3.0.0 -replace "github.com/go-ldap/ldap/v3=$SRC/v3"
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest 2>&1 | tail -2 || true

echo "=== building fuzz_parse_dn (FuzzParseDN, go-118-fuzz-build) ==="
go-118-fuzz-build -o "$SRC/mayhem-build/fuzz_parse_dn.a" -func FuzzParseDN "$H"

# Link: $GO_DEBUG_FLAGS ensures the C-shim CU (first in the binary) is at DWARF3.
$CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/fuzz_parse_dn.a" \
    -o /mayhem/fuzz_parse_dn
echo "built /mayhem/fuzz_parse_dn"

echo "build.sh complete:"
ls -la /mayhem/fuzz_parse_dn 2>&1 || true
