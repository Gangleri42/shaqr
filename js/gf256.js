// SPDX-License-Identifier: CC0-1.0

// Arithmetic in GF(2^8) modulo x^8+x^4+x^3+x+1, the AES field (SPEC.md,
// Field). Addition is XOR.
//
// mul uses no tables and does not branch on its operands. Shares are
// secret and short, so there are no log tables to leak through the cache
// or to speed things up.

export function mul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    p ^= a & -(b & 1);
    b >>= 1;
    a = (a << 1) ^ (0x11b & -(a >> 7));
  }
  return p;
}

// inv returns a^254, which is 1/a for nonzero a. The loop branches on the
// bits of the exponent, which are fixed.
export function inv(a) {
  let p = 1;
  for (let e = 254; e > 0; e >>= 1) {
    if (e & 1) p = mul(p, a);
    a = mul(a, a);
  }
  return p;
}

// basis returns the weights of the distinct xs as a function of the
// target x: w such that f(x) = XOR of w[i]*f(xs[i]) for every polynomial
// f of degree below xs.length. It computes the inverse of every
// denominator, the product over j != i of xs[i] + xs[j], once, so that
// the weights at one target take O(xs.length) steps and those at k
// targets O(k^2) and not O(k^3). When x is one of the xs its weight is 1
// and the others are 0. Otherwise w[i] is P / (x + xs[i]) times the
// inverse of the denominator, where P is the product of x + xs[j] over
// all j: the w_i of SPEC.md, Interpolation.
export function basis(xs) {
  const dinv = xs.map((xi, i) => {
    let den = 1;
    for (const [j, xj] of xs.entries()) {
      if (j !== i) den = mul(den, xi ^ xj);
    }
    return inv(den);
  });
  return (x) => {
    const w = new Array(xs.length).fill(0);
    let p = 1;
    // The xs and x are share indices, which are public.
    for (const [i, xi] of xs.entries()) {
      if (xi === x) {
        w[i] = 1;
        return w;
      }
      p = mul(p, x ^ xi);
    }
    return xs.map((xi, i) => mul(mul(p, inv(x ^ xi)), dinv[i]));
  };
}

// interp writes into out the values at x of the polynomials through the
// points (xs[i], ys[i][j]), one polynomial per byte position j (SPEC.md,
// Interpolation), and returns out. Every ys[i] is at least as long as
// out. Writing into a view lets a caller build a share in place, or keep
// key material in one buffer that it can erase.
export function interp(out, xs, ys, x) {
  return apply(out, basis(xs)(x), ys);
}

// apply writes into out the XOR of w[i]*ys[i], byte position by byte
// position, and returns out.
export function apply(out, w, ys) {
  out.fill(0);
  for (const [i, wi] of w.entries()) {
    // The weights depend on share indices only, which are public.
    if (wi === 0) continue;
    const y = ys[i];
    for (let j = 0; j < out.length; j++) out[j] ^= mul(wi, y[j]);
  }
  return out;
}
