// SPDX-License-Identifier: CC0-1.0

// ChaCha20 as RFC 8439 defines it in sections 2.1 to 2.4, without
// Poly1305. shaQR needs no more than the keystream.

// The four constant words, "expand 32-byte k" in ASCII.
const sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

const rotl = (v, n) => (v << n) | (v >>> (32 - n));

// quarterRound works on s in place. s is a Uint32Array, so every sum
// wraps modulo 2^32.
function quarterRound(s, a, b, c, d) {
  s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}

// chacha20 returns length bytes of the keystream for a 32 byte key, a 12
// byte nonce and the blocks counter, counter+1, ... (section 2.4). The
// block counter is 32 bits wide, so length must not exceed
// 64 * (2^32 - counter). The state and each block are erased once used,
// and the keystream is the only copy left.
export function chacha20(key, nonce, counter, length) {
  const init = new Uint32Array(16);
  const keyWords = new DataView(key.buffer, key.byteOffset, 32);
  const nonceWords = new DataView(nonce.buffer, nonce.byteOffset, 12);
  init.set(sigma);
  for (let i = 0; i < 8; i++) init[4 + i] = keyWords.getUint32(4 * i, true);
  init[12] = counter;
  for (let i = 0; i < 3; i++) init[13 + i] = nonceWords.getUint32(4 * i, true);

  const out = new Uint8Array(length);
  const s = new Uint32Array(16);
  const block = new Uint8Array(64);
  const blockWords = new DataView(block.buffer);
  for (let at = 0; at < length; at += 64) {
    s.set(init);
    for (let i = 0; i < 10; i++) {
      quarterRound(s, 0, 4, 8, 12);
      quarterRound(s, 1, 5, 9, 13);
      quarterRound(s, 2, 6, 10, 14);
      quarterRound(s, 3, 7, 11, 15);
      quarterRound(s, 0, 5, 10, 15);
      quarterRound(s, 1, 6, 11, 12);
      quarterRound(s, 2, 7, 8, 13);
      quarterRound(s, 3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) blockWords.setUint32(4 * i, s[i] + init[i], true);
    out.set(block.subarray(0, Math.min(64, length - at)), at);
    init[12]++;
  }
  init.fill(0);
  s.fill(0);
  block.fill(0);
  return out;
}
