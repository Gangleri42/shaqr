# SPDX-License-Identifier: CC0-1.0
# Berlekamp-Welch decoding of one byte position, as DECODING.md describes it.
# A sketch that checks the note. It is not part of the reference.
import random

def gmul(a, b):
    # GF(2^8), polynomial 0x11B
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r

def ginv(a):
    assert a
    r, e = 1, 254
    while e:
        if e & 1:
            r = gmul(r, a)
        a = gmul(a, a)
        e >>= 1
    return r

def gpow(a, n):
    r = 1
    for _ in range(n):
        r = gmul(r, a)
    return r

def solve(A, b):
    # Gaussian elimination over GF(2^8). Free unknowns are set to 0.
    # Returns None if the system has no solution.
    rows, cols = len(A), len(A[0])
    M = [A[i][:] + [b[i]] for i in range(rows)]
    pivots, r = [], 0
    for c in range(cols):
        p = next((i for i in range(r, rows) if M[i][c]), None)
        if p is None:
            continue
        M[r], M[p] = M[p], M[r]
        inv = ginv(M[r][c])
        M[r] = [gmul(inv, v) for v in M[r]]
        for i in range(rows):
            if i != r and M[i][c]:
                f = M[i][c]
                M[i] = [v ^ gmul(f, w) for v, w in zip(M[i], M[r])]
        pivots.append(c)
        r += 1
    if any(row[-1] for row in M[r:]):
        return None
    x = [0] * cols
    for i, c in enumerate(pivots):
        x[c] = M[i][-1]
    return x

def polydiv(num, den):
    # coefficients from low to high. Returns (quotient, remainder).
    num = num[:]
    q = [0] * (len(num) - len(den) + 1)
    inv = ginv(den[-1])
    for i in range(len(q) - 1, -1, -1):
        c = gmul(num[i + len(den) - 1], inv)
        q[i] = c
        for j, d in enumerate(den):
            num[i + j] ^= gmul(c, d)
    return q, num[:len(den) - 1]

def decode(xs, ys, k):
    # xs: share indices held, ys: the byte each holds at one position.
    # Returns the k coefficients of f, low to high, or None on failure.
    m = len(xs)
    e = (m - k) // 2
    A = [[gpow(x, j) for j in range(k + e)] + [gmul(y, gpow(x, j)) for j in range(e)]
         for x, y in zip(xs, ys)]
    b = [gmul(y, gpow(x, e)) for x, y in zip(xs, ys)]
    sol = solve(A, b)
    if sol is None:
        return None
    Q, E = sol[:k + e], sol[k + e:] + [1]
    f, rem = polydiv(Q, E)
    if any(rem):
        return None
    return f[:k]

def evaluate(f, x):
    r = 0
    for c in reversed(f):
        r = gmul(r, x) ^ c
    return r

if __name__ == '__main__':
    random.seed(1)
    k, m = 10, 20
    for wrong in range(8):
        good = 0
        for _ in range(50):
            f = [random.randrange(256) for _ in range(k)]
            xs = random.sample(range(1, 256), m)
            ys = [evaluate(f, x) for x in xs]
            for i in random.sample(range(m), wrong):
                ys[i] ^= random.randrange(1, 256)
            good += decode(xs, ys, k) == f
        print('%d wrong of %d held, k = %d: %d of 50 decoded' % (wrong, m, k, good))
