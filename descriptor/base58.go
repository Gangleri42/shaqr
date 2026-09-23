// SPDX-License-Identifier: CC0-1.0

package descriptor

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
)

// base58Alphabet is the alphabet of Bitcoin addresses.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Digits holds the value of every character of the alphabet, and
// -1 for every other byte.
var base58Digits = func() (d [256]int8) {
	for i := range d {
		d[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		d[base58Alphabet[i]] = int8(i)
	}
	return d
}()

func isBase58(c byte) bool {
	return base58Digits[c] >= 0
}

// base58Encode writes b in base58: a 1 for each leading zero byte and
// the rest as a number. It divides in limbs of five digits.
func base58Encode(b []byte) string {
	const limb = 58 * 58 * 58 * 58 * 58
	var limbs []uint64 // base 58^5, the least significant first
	for _, c := range b {
		carry := uint64(c)
		for i := range limbs {
			carry += limbs[i] << 8
			limbs[i], carry = carry%limb, carry/limb
		}
		for ; carry > 0; carry /= limb {
			limbs = append(limbs, carry%limb)
		}
	}
	var digits []byte // the least significant first
	for _, l := range limbs {
		for range 5 {
			digits, l = append(digits, base58Alphabet[l%58]), l/58
		}
	}
	// The top limb wrote zeros above the number, and a leading zero
	// byte is a 1 too.
	digits = bytes.TrimRight(digits, "1")
	for _, c := range b {
		if c != 0 {
			break
		}
		digits = append(digits, '1')
	}
	slices.Reverse(digits)
	return string(digits)
}

// base58Decode returns the bytes of s, whose characters must all be in
// the alphabet: a zero byte for each leading 1 and the rest as a number.
func base58Decode(s string) []byte {
	var b []byte // base 256, the least significant first
	for i := 0; i < len(s); i++ {
		carry := int(base58Digits[s[i]])
		for j := range b {
			carry += int(b[j]) * 58
			b[j], carry = byte(carry), carry>>8
		}
		for ; carry > 0; carry >>= 8 {
			b = append(b, byte(carry))
		}
	}
	zeros := len(s) - len(strings.TrimLeft(s, "1"))
	out := make([]byte, zeros, zeros+len(b))
	for i := len(b) - 1; i >= 0; i-- {
		out = append(out, b[i])
	}
	return out
}

// checkOf returns the first four bytes of the double SHA-256 of b, the
// check that base58check appends.
func checkOf(b []byte) []byte {
	h := sha256.Sum256(b)
	h = sha256.Sum256(h[:])
	return h[:4]
}

// encodeExtended writes the 78 bytes of an extended key as base58check.
func encodeExtended(raw []byte) string {
	return base58Encode(append(raw[:extendedLen:extendedLen], checkOf(raw)...))
}

// decodeExtended returns the 78 bytes that s writes as base58check, or
// nil when s is not the base58check of 78 bytes. The 82 bytes with the
// check take 82 to 112 characters, so a string of any other length is
// not decoded.
func decodeExtended(s string) []byte {
	if len(s) < 82 || len(s) > 112 {
		return nil
	}
	b := base58Decode(s)
	if len(b) != extendedLen+4 || !bytes.Equal(b[extendedLen:], checkOf(b[:extendedLen])) {
		return nil
	}
	return b[:extendedLen]
}
