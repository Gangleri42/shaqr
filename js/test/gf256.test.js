// SPDX-License-Identifier: CC0-1.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mul, inv, interp } from '../gf256.js';

test('mul', () => {
  // FIPS 197, sections 4.2 and 4.2.1.
  assert.equal(mul(0x57, 0x83), 0xc1);
  assert.equal(mul(0x57, 0x13), 0xfe);
  for (let a = 0; a < 256; a++) {
    assert.equal(mul(a, 1), a);
    assert.equal(mul(a, 0), 0);
    for (let b = 0; b < 256; b++) {
      if (mul(a, b) !== mul(b, a)) assert.fail(`${a}*${b} does not commute`);
    }
  }
});

test('inv', () => {
  for (let a = 1; a < 256; a++) assert.equal(mul(a, inv(a)), 1, `a = ${a}`);
});

test('interp', () => {
  // f(x) = 7 + 3x + 9x^2
  const f = (x) => 7 ^ mul(3, x) ^ mul(9, mul(x, x));
  const xs = [2, 5, 200];
  const ys = xs.map((x) => [f(x)]);
  const out = new Uint8Array(1);
  for (let x = 0; x < 256; x++) assert.equal(interp(out, xs, ys, x)[0], f(x), `x = ${x}`);
});
