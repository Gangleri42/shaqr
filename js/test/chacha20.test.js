// SPDX-License-Identifier: CC0-1.0

// ChaCha20 against the test vectors of RFC 8439, and against the ChaCha20
// of OpenSSL that node:crypto offers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { chacha20 } from '../chacha20.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (s) => new Uint8Array(Buffer.from(s.replace(/\s/g, ''), 'hex'));
const count = (n) => Uint8Array.from({ length: n }, (_, i) => i);
const zeros = (n) => new Uint8Array(n);

test('RFC 8439 2.3.2, the block function', () => {
  const block = chacha20(count(32), unhex('000000090000004a00000000'), 1, 64);
  assert.equal(hex(block), hex(unhex(`
    10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
    d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e`)));
});

test('RFC 8439 2.4.2, encryption', () => {
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const stream = chacha20(count(32), unhex('000000000000004a00000000'), 1, plaintext.length);
  assert.equal(hex(plaintext.map((b, i) => b ^ stream[i])), hex(unhex(`
    6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
    f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
    07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
    5af90bbf74a35be6b40b8eedf2785e42874d`)));
});

// RFC 8439 A.1, the block function: key, nonce, counter and block.
const blocks = [
  [zeros(32), zeros(12), 0, `
    76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7
    da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586`],
  [zeros(32), zeros(12), 1, `
    9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed
    29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f`],
  [unhex('00'.repeat(31) + '01'), zeros(12), 1, `
    3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a
    8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0`],
  [unhex('00ff' + '00'.repeat(30)), zeros(12), 2, `
    72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca
    13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096`],
  [zeros(32), unhex('00'.repeat(11) + '02'), 0, `
    c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7
    8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d`],
];

for (const [i, [key, nonce, counter, want]] of blocks.entries()) {
  test(`RFC 8439 A.1, test vector ${i + 1}`, () => {
    assert.equal(hex(chacha20(key, nonce, counter, 64)), hex(unhex(want)));
  });
}

test('the keystream of node:crypto, for random keys, nonces and lengths', () => {
  for (let i = 0; i < 200; i++) {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const counter = randomBytes(4).readUInt32LE() >>> 8;
    const length = Math.floor(Math.random() * 700);
    // OpenSSL takes the counter, little endian, and then the nonce as one
    // 16 byte IV.
    const iv = Buffer.alloc(16);
    iv.writeUInt32LE(counter);
    nonce.copy(iv, 4);
    const cipher = createCipheriv('chacha20', key, iv);
    const want = Buffer.concat([cipher.update(Buffer.alloc(length)), cipher.final()]);
    assert.equal(hex(chacha20(key, nonce, counter, length)), hex(want));
  }
});
