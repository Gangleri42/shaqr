// SPDX-License-Identifier: CC0-1.0

// Runs testdata/vectors.json, which the Go package writes. The format is
// described in vectors_test.go. Every valid set is rebuilt from its inputs
// and compared text for text, and every invalid and text case goes through
// decode, group, combine and audit as a receiver would use them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { split, combine, audit, group, encode, decode, tag, ShaqrError } from '../shaqr.js';

const vectors = JSON.parse(readFileSync(new URL('../../testdata/vectors.json', import.meta.url), 'utf8'));

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));

// splitVector makes the set a valid vector describes: an open set, a
// sealed session set with the r of the vector, or a derived set when a
// sealed set has none.
function splitVector(v) {
  let options = { r: unhex(v.r_hex), minLen: v.pad_to };
  if (v.format === 'open') options = { open: true };
  else if (v.r_hex === '') options = { derived: true };
  return split(unhex(v.payload_hex), v.type.charCodeAt(0), v.k, v.n, options);
}

for (const v of vectors.valid) {
  test(`valid: ${v.name}`, async () => {
    const shares = await splitVector(v);
    assert.deepEqual(shares.map(encode), v.shares);
    assert.equal(shares[0][0], v.format === 'open' ? 2 : 1);
    assert.equal(hex(shares[0].subarray(3, 19)), v.id_hex);
    assert.equal(tag(shares[0]), v.tag);
    for (const held of [v.shares.slice(0, v.k), v.shares.slice(v.n - v.k)]) {
      const read = decode(held.join('\n'));
      assert.deepEqual(read.rejected, []);
      const got = await combine(read.shares);
      assert.equal(String.fromCharCode(got.type), v.type);
      assert.equal(hex(got.payload), v.payload_hex);
    }
  });
}

// receive recovers what it can from text as a receiver would, and says
// what it reports, in the words of the vectors.
async function receive(text) {
  const recovered = [];
  const rejected = [];
  const read = decode(text);
  for (const err of read.rejected) rejected.push(err.code);
  const { sets, rejected: refused } = await group(read.shares);
  const disputes = new Set();
  for (const { index, error } of refused) {
    if (error.code === 'disputed') {
      // Report each x once: format, k, x and id, and the length.
      const sh = read.shares[index];
      const at = `${hex(sh.subarray(0, 19))} ${sh.length}`;
      if (disputes.has(at)) continue;
      disputes.add(at);
    }
    rejected.push(error.code);
  }
  for (const set of sets) {
    try {
      const { type, payload } = await combine(set);
      recovered.push({ type: String.fromCharCode(type), payload_hex: hex(payload) });
      for (const x of await audit(set)) rejected.push('bad-share');
    } catch (err) {
      if (!(err instanceof ShaqrError)) throw err;
      rejected.push(err.code);
    }
  }
  return { recovered, rejected: rejected.sort() };
}

for (const v of vectors.invalid) {
  test(`invalid: ${v.name}`, async () => {
    assert.deepEqual(await receive(v.text), v.expect);
  });
}

for (const v of vectors.text) {
  test(`text: ${v.name}`, () => {
    const read = decode(v.input);
    assert.deepEqual(read.shares.map(hex), v.shares_hex);
    assert.equal(read.rejected.length, v.rejected);
    for (const err of read.rejected) assert.equal(err.code, 'not-decoded');
  });
}
