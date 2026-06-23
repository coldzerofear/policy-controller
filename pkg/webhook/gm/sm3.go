package gm

import "github.com/emmansun/gmsm/sm3"

// SM3 returns the SM3 hash of payload as a 32-byte slice.
//
// Backed by github.com/emmansun/gmsm/sm3, which we verified byte-by-byte
// against the gmctl Java CLI side (BouncyCastle SM3Digest) and the vendor
// wcspsdk Java SDK on the GM/T 0004-2012 official test vectors plus a
// 244-byte production-shape Simple Signing payload. See
// gm-sign-cli/spike-go/sm3-compat/ and docs/06 section 4.1 for fixtures.
//
// Pure Go, no cgo, arch-agnostic.
func SM3(payload []byte) []byte {
	sum := sm3.Sum(payload)
	return sum[:]
}
