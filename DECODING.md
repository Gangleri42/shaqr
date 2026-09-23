# shaQR: Berlekamp-Welch decoding of wrong shares

A note, not part of the specification. It describes an option for receivers,
changes nothing in the format, and the reference does not implement it.
`py/bw_sketch.py` is a sketch of the decoder for one byte position that checks
what is said here.

## What it is for

The subset search in "Finding a bad share" (SPEC.md) is exponential in the
worst case. With m shares held and e of them wrong, a clean k-subset exists as
long as e <= m - k, but when the wrong shares are scattered it can take most of
the C(m, k) subsets to find it. Berlekamp-Welch decoding finds the wrong shares
directly, in polynomial time, as long as

```
e <= (m - k) / 2        rounded down
```

With 20 shares held at k = 10 it corrects any 5 wrong shares, wherever they
sit.

## Why it applies

Take one byte position of the share body. Across the held shares its values
are f(x_1) .. f(x_m) for a polynomial f of degree below k. That is a
Reed-Solomon codeword with some symbols missing, and a wrong share is a symbol
error in it. McEliece and Sarwate pointed this out for Shamir's scheme in
1981. It holds for the key part and for the data part, since both are values
of polynomials of degree below k at the share's x.

## The algorithm for one byte position

Let y_i be the byte that share x_i holds, and let e = (m - k) / 2 rounded
down. Look for two polynomials

```
E(x) = x^e + a_(e-1) x^(e-1) + .. + a_0              the error locator
Q(x) = q_(k+e-1) x^(k+e-1) + .. + q_0
```

with Q(x_i) = y_i * E(x_i) for every held share. Moving the known term to the
right gives m linear equations in the k + 2e unknowns q_j and a_j:

```
sum over j < k+e of  q_j * x_i^j   +   y_i * sum over j < e of  a_j * x_i^j   =   y_i * x_i^e
```

Addition is XOR, so there are no signs to keep track of. Solve the system by
Gaussian elimination over GF(2^8). When fewer than e shares are wrong it has
more than one solution, and any of them will do, for instance the one with
the free unknowns set to zero. Then

```
f(x) = Q(x) / E(x)
```

and the division leaves no remainder. If the system has no solution, or the
division leaves a remainder, more than e shares are wrong at this position and
the decoder has failed.

The reason it works is short. Let E vanish at every x_i whose y_i is wrong.
Then Q = f * E satisfies all m equations, so a solution exists. For any
solution, Q - f * E has degree below k + e and is zero at the m - e or more
positions where y_i is right. Since m - e >= k + e, it is the zero polynomial,
and Q / E = f.

## Using it in a receiver

1. Combine the first k shares as usual. There is something to correct only
   when the id fails and spare shares are held.
2. Decode every byte position of the body. A forged share may differ from the
   true one in a single byte, so decoding a few positions and trusting the
   rest is not enough.
3. At each of the 32 positions of the key part, S is f(0) and R_i is f(i)
   for i = 1 .. k-1. C_i is f(i) at the positions of the data part, for
   i = 1 .. k.
4. Verify the id. It stays the judge. With more than e wrong shares the
   decoder can return a wrong polynomial instead of failing, and the id
   rejects it. The receiver then falls back on the subset search, which can
   succeed with up to m - k wrong shares.
5. The wrong shares are those whose body differs from the decoded polynomials
   at their x. The id has passed, and it fixes both polynomials, so this
   blame is right for the key part as well as the data part (see Finding a bad
   share in SPEC.md).

## Cost

One elimination per byte position, on a matrix of m rows and k + 2e columns,
is about m^3 field multiplications. The k + e columns on the left hold powers
of x_i and are the same at every position, so that part of the work can be
done once. For 20 shares of 345 bytes the total is a few million
multiplications. For 255 shares it is slow on a microcontroller and no
trouble anywhere else. In code it is an elimination routine and a polynomial
division, around a hundred lines.

## Beyond half the spares

Berlekamp-Welch stops at (m - k) / 2 because past that point the codeword
nearest to what was received need not be the right one. Here the id can tell
right from wrong, so a decoder that returns a short list of candidates would
be enough. Sudan's algorithm, and its improvement by Guruswami and Sudan,
produce such lists and reach further. They take a good deal more work to
implement, and the subset search already covers small sets.

## Sources

I. S. Reed and G. Solomon, "Polynomial Codes over Certain Finite Fields",
Journal of the Society for Industrial and Applied Mathematics 8(2), 1960,
300-304.

R. J. McEliece and D. V. Sarwate, "On Sharing Secrets and Reed-Solomon Codes",
Communications of the ACM 24(9), 1981, 583-584.

P. Gemmell and M. Sudan, "Highly Resilient Correctors for Polynomials",
Information Processing Letters 43(4), 1992, 169-174. The algorithm as a linear
system in E and Q, the form given above, follows this paper.

M. Sudan, "Decoding of Reed Solomon Codes beyond the Error-Correction Bound",
Journal of Complexity 13(1), 1997, 180-193.

V. Guruswami and M. Sudan, "Improved Decoding of Reed-Solomon and
Algebraic-Geometry Codes", IEEE Transactions on Information Theory 45(6),
1999, 1757-1767.
