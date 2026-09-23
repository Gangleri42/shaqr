// SPDX-License-Identifier: CC0-1.0

package shaqr

// Arithmetic in GF(2^8) modulo x^8+x^4+x^3+x+1, the AES field.
//
// mul takes the same time for all inputs. Shares are secret and short,
// so there are no log tables to leak through the cache or to speed
// things up.

func mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= a & -(b & 1)
		b >>= 1
		a = a<<1 ^ 0x1b&-(a>>7)
	}
	return p
}

// inv returns a^254, which is 1/a for nonzero a.
func inv(a byte) byte {
	b := mul(a, a) // a^2
	c := mul(b, a) // a^3
	b = mul(c, c)  // a^6
	b = mul(b, b)  // a^12
	c = mul(b, c)  // a^15
	b = mul(b, b)  // a^24
	b = mul(b, b)  // a^48
	b = mul(b, c)  // a^63
	b = mul(b, b)  // a^126
	b = mul(b, a)  // a^127
	return mul(b, b)
}

// A basis holds what the weights for distinct xs share whatever the
// target x: the inverse of every denominator, the product over j != i of
// xs[i] + xs[j]. Given it, the weights at one target take O(len(xs))
// steps, so the weights at k targets take O(k^2) and not O(k^3).
type basis struct {
	xs, dinv []byte
}

func newBasis(xs []byte) basis {
	dinv := make([]byte, len(xs))
	for i, xi := range xs {
		den := byte(1)
		for j, xj := range xs {
			if j != i {
				den = mul(den, xi^xj)
			}
		}
		dinv[i] = inv(den)
	}
	return basis{xs, dinv}
}

// weights returns w such that f(x) = sum of w[i]*f(xs[i]) for every
// polynomial f of degree below len(xs). When x is one of the xs its
// weight is 1 and the others are 0. Otherwise w[i] is P / (x + xs[i])
// times dinv[i], where P is the product of x + xs[j] over all j: the w_i
// of SPEC.md, Interpolation.
func (b basis) weights(x byte) []byte {
	w := make([]byte, len(b.xs))
	p := byte(1)
	for i, xi := range b.xs {
		// The xs and x are share indices, which are public.
		if xi == x {
			w[i] = 1
			return w
		}
		p = mul(p, x^xi)
	}
	for i, xi := range b.xs {
		w[i] = mul(mul(p, inv(x^xi)), b.dinv[i])
	}
	return w
}

// weights returns the weights of the distinct xs at x.
func weights(xs []byte, x byte) []byte {
	return newBasis(xs).weights(x)
}

// interp appends to dst the values at x of the polynomials through the
// points (xs[i], ys[i][j]), one polynomial per byte position j, and
// returns the extended slice. All ys have the same length. Appending lets
// a caller build a share in place, or keep key material in one buffer
// that it can erase.
func interp(dst, xs []byte, ys [][]byte, x byte) []byte {
	return apply(dst, weights(xs, x), ys)
}

// apply appends to dst the sum of w[i]*ys[i], byte position by byte
// position, and returns the extended slice.
func apply(dst, w []byte, ys [][]byte) []byte {
	n := len(dst)
	dst = append(dst, make([]byte, len(ys[0]))...)
	out := dst[n:]
	for i, wi := range w {
		// The weights depend on share indices only, which are public.
		if wi == 0 {
			continue
		}
		for j, y := range ys[i] {
			out[j] ^= mul(wi, y)
		}
	}
	return dst
}
