// SPDX-License-Identifier: CC0-1.0

package shaqr

import "testing"

func TestMul(t *testing.T) {
	// FIPS 197, sections 4.2 and 4.2.1.
	if got := mul(0x57, 0x83); got != 0xc1 {
		t.Errorf("57*83 = %02x, want c1", got)
	}
	if got := mul(0x57, 0x13); got != 0xfe {
		t.Errorf("57*13 = %02x, want fe", got)
	}
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if mul(byte(a), byte(b)) != mul(byte(b), byte(a)) {
				t.Fatalf("%02x*%02x does not commute", a, b)
			}
		}
		if mul(byte(a), 1) != byte(a) || mul(byte(a), 0) != 0 {
			t.Fatalf("identity or zero fails for %02x", a)
		}
	}
}

func TestInv(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := mul(byte(a), inv(byte(a))); got != 1 {
			t.Errorf("%02x * inv = %02x", a, got)
		}
	}
}

func TestInterp(t *testing.T) {
	// f(x) = 7 + 3x + 9x^2
	f := func(x byte) byte { return 7 ^ mul(3, x) ^ mul(9, mul(x, x)) }
	xs := []byte{2, 5, 200}
	ys := [][]byte{{f(2)}, {f(5)}, {f(200)}}
	for x := 0; x < 256; x++ {
		if got := interp(nil, xs, ys, byte(x))[0]; got != f(byte(x)) {
			t.Fatalf("f(%d) = %02x, want %02x", x, got, f(byte(x)))
		}
	}
	if got := interp([]byte{0xaa}, xs, ys, 1); len(got) != 2 || got[0] != 0xaa || got[1] != f(1) {
		t.Errorf("interp appended %x to aa, want aa%02x", got, f(1))
	}
}
