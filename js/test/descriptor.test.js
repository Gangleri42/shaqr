// SPDX-License-Identifier: CC0-1.0

// Runs testdata/descriptors.json, which the Go package descriptor writes,
// and checks the BIP 380 checksum against the examples of BIP 380.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonical, checksum, fingerprint, quorum, verify, DescriptorError } from '../descriptor.js';

const read = (name) => JSON.parse(readFileSync(new URL(`../../testdata/${name}`, import.meta.url), 'utf8'));
const vectors = read('descriptors.json');

for (const v of vectors.canonical) {
  test(`canonical: ${v.name}`, () => {
    if (v.error) {
      assert.throws(() => canonical(v.input), (err) => err instanceof DescriptorError && err.code === v.error);
      return;
    }
    assert.equal(canonical(v.input), v.canonical);
    assert.equal(canonical(v.canonical), v.canonical);
  });
}

for (const v of vectors.quorum) {
  test(`quorum: ${v.name}`, () => {
    const q = quorum(v.input);
    assert.equal(q !== null, v.ok);
    if (q !== null) {
      assert.equal(q.k, v.k);
      assert.equal(q.keys.length, v.n);
      assert.deepEqual(q.keys.map(fingerprint), v.fingerprints);
    }
  });
}

test('checksum: the examples of BIP 380', () => {
  assert.equal(checksum('raw(deadbeef)'), '89f8spxm');
  assert.equal(checksum('addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)'), '02wpgw69');
  assert.equal(checksum('wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'), '8zl0zxma');
  assert.throws(() => checksum('raw(dead\x01beef)'), DescriptorError);
});

test('verify', () => {
  verify('raw(deadbeef)#89f8spxm');
  const code = (code) => (err) => err instanceof DescriptorError && err.code === code;
  assert.throws(() => verify('raw(deadbeef)'), code('no-checksum'));
  for (const bad of ['raw(deadbeef)#89f8spxm\n', 'raw(deadbeef)#89f8spx', 'raw(deadbeef)#', 'raw(deedbeef)#89f8spxm']) {
    assert.throws(() => verify(bad), code('checksum'), bad);
  }
});

test('fingerprint', () => {
  const xpub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
  const hexG = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  assert.equal(fingerprint(`[D34DB33F/48h/0h/0h/2h]${xpub}/<0;1>/*`), 'd34db33f');
  assert.equal(fingerprint(`[0badc0de]${hexG}`), '0badc0de');
  assert.equal(fingerprint(`${xpub}/0/*`), '');
  assert.equal(fingerprint(`[d34db33]${hexG}`), '');
  assert.equal(fingerprint(`[nothexok/1h]${hexG}`), '');
});

test('the descriptor of vectors.json is in canonical form', () => {
  const v = read('vectors.json').valid.find((c) => c.type === 'D');
  const desc = Buffer.from(v.payload_hex, 'hex').toString('latin1');
  verify(desc);
  assert.equal(canonical(desc), desc);
  const q = quorum(desc);
  assert.equal(q.k, v.k);
  assert.equal(q.keys.length, v.n);
});
