// SPDX-License-Identifier: CC0-1.0

// Random sets split and recovered, and how the API treats bad input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import {
  split, combine, shareAt, audit, group, parseHeader, encode, decode, scan, tag,
  internals, ShaqrError, TypeBytes, TypeText,
} from '../shaqr.js';

const bytes = (n) => new Uint8Array(randomBytes(n));

// pick returns k of the shares, in random order.
function pick(shares, k) {
  const left = [...shares];
  return Array.from({ length: k }, () => left.splice(randomInt(left.length), 1)[0]);
}

// messy writes shares as a hand might type them back: mixed case, wrapped
// over lines, with labels.
function messy(shares) {
  return shares.map((sh) => {
    const text = [...encode(sh)].map((c) => (randomInt(2) ? c.toLowerCase() : c)).join('');
    return `${tag(sh)} plate\n  ${text.replace(/(.{1,17})/g, '$1\n\t ')}\n`;
  }).join('');
}

// forge changes byte i of a share and gives it a check that matches.
function forge(share, i) {
  const f = new Uint8Array(share);
  f[i] ^= 0x01;
  const n = f.length - 4;
  f.set(createHash('sha256').update('shaQR v1 check').update(f.subarray(0, n)).digest().subarray(0, 4), n);
  return f;
}

const code = (c) => (err) => err instanceof ShaqrError && err.code === c;

test('random sets split and recovered', async () => {
  for (let i = 0; i < 200; i++) {
    const n = randomInt(20) === 0 ? 255 : randomInt(2, 21);
    const k = randomInt(2, Math.min(n, 12) + 1);
    const payload = bytes(randomInt(300));
    const type = randomInt(256);
    const options = [{}, { derived: true }, { minLen: randomInt(200) }][randomInt(3)];
    const about = `case ${i}: ${k}-of-${n}, ${payload.length} bytes, ${JSON.stringify(options)}`;

    const shares = await split(payload, type, k, n, options);
    const minLen = options.minLen ?? 0;
    const sealed = Math.max(payload.length + 2, minLen);
    assert.equal(shares[0].length, 55 + Math.ceil(sealed / k), about);
    if (options.derived) {
      assert.deepEqual(await split(payload, type, k, n, options), shares, about);
    }

    const held = pick(shares, k);
    const read = decode(messy(held));
    assert.deepEqual(read.rejected, [], about);
    assert.deepEqual(read.shares, held, about);
    const got = await combine(read.shares);
    assert.equal(got.type, type, about);
    assert.deepEqual(got.payload, payload, about);

    const x = randomInt(1, n + 1);
    assert.deepEqual(await shareAt(pick(shares, k), x), shares[x - 1], about);
  }
});

test('a forged share among spares is found and named', async () => {
  const payload = bytes(40);
  const shares = await split(payload, TypeBytes, 3, 6);
  for (let x = 1; x <= 6; x++) {
    for (const at of [19, 19 + 31, 51, shares[0].length - 5]) {
      const held = shares.map((sh, i) => (i === x - 1 ? forge(sh, at) : sh));
      assert.deepEqual((await combine(held)).payload, payload);
      assert.deepEqual(await audit(held), [x]);
      const others = held.filter((sh, i) => i !== x - 1);
      await assert.rejects(combine([...pick(others, 2), held[x - 1]]), code('id'));
    }
  }
});

test('shares of two sets, a copy and a disputed x', async () => {
  const a = await split(new TextEncoder().encode('set a'), TypeText, 2, 3);
  const b = await split(new TextEncoder().encode('set b'), TypeText, 2, 3);
  const forged = forge(a[1], 52);
  const { sets, rejected } = await group([b[2], a[0], a[0], forged, a[1], b[0], a[2]]);
  assert.equal(sets.length, 2);
  assert.deepEqual(sets[0], [b[2], b[0]]);
  assert.deepEqual(rejected.map((r) => [r.index, r.error.code]), [[3, 'disputed'], [4, 'disputed']]);
  assert.equal(new TextDecoder().decode((await combine(sets[1])).payload), 'set a');
  assert.deepEqual(await audit(sets[1]), [2]);
  await assert.rejects(combine([a[0], forged, a[1]]), (err) => {
    return code('too-few')(err) && err.message.endsWith('1 of 2, not counting 1 disputed x');
  });
  await assert.rejects(combine([a[0], b[1]]), code('set'));
  await assert.rejects(combine([]), code('too-few'));
});

test('step 1 comes before step 2: a damaged share after two sets is damaged', async () => {
  const a = await split(new TextEncoder().encode('set a'), TypeText, 2, 3);
  const b = await split(new TextEncoder().encode('set b'), TypeText, 2, 3);
  const damaged = new Uint8Array(a[1]);
  damaged[30] ^= 1;
  for (const held of [[a[0], b[1], damaged], [a[0], damaged, b[1]]]) {
    await assert.rejects(combine(held), code('check'));
    await assert.rejects(audit(held), code('check'));
    await assert.rejects(shareAt(held, 2), code('check'));
  }
});

test('a too-few error says which x values are held and disputed', async () => {
  const shares = await split(new TextEncoder().encode('too few'), TypeText, 3, 5);
  const other = forge(shares[3], 40);
  await assert.rejects(combine([shares[3], shares[0], shares[0], other]), (err) => {
    assert.ok(code('too-few')(err));
    assert.equal(err.message, 'shaqr: not enough shares: 1 of 3, not counting 1 disputed x');
    assert.deepEqual([err.k, err.held, err.disputed], [3, [1], [4]]);
    return true;
  });
});

test('step 6 of splitting catches a share that a fault made wrong', async () => {
  const { build, verify, seal, sealedLen, crypt } = internals;
  const payload = new TextEncoder().encode('step six');
  const k = 3;
  const n = 5;
  const take = bytes(32 * k);
  const c = crypt(take.subarray(0, 32), seal(TypeText, payload, sealedLen(payload.length, k, 0)));
  const good = await build(k, n, take, c);
  await verify(good, TypeText, payload, k);
  for (let i = 0; i < n; i++) {
    for (const at of [19 + 5, 19 + 32 + 1]) {
      const bad = [...good];
      bad[i] = forge(bad[i], at);
      await assert.rejects(verify(bad, TypeText, payload, k), Error, `fault at byte ${at} of share ${i + 1}`);
    }
  }

  // A fault in C before the id was computed passes the id, and the
  // comparison with the input catches it.
  c[4] ^= 1;
  await assert.rejects(verify(await build(k, n, take, c), TypeText, payload, k), Error, 'fault in C');
  await assert.rejects(verify(good, TypeBytes, payload, k), Error, 'wrong type');
  const swapped = [good[1], good[0], ...good.slice(2)];
  await assert.rejects(verify(swapped, TypeText, payload, k), Error, 'shares out of order');
});

test('split erases its secrets when WebCrypto fails', async () => {
  const subtle = crypto.subtle;
  const sign = subtle.sign;
  let msg;
  subtle.sign = async (algorithm, key, data) => {
    msg = data;
    throw new Error('no WebCrypto today');
  };
  try {
    const payload = new TextEncoder().encode('erased on the way out');
    await assert.rejects(split(payload, TypeText, 2, 3), /no WebCrypto today/);
    assert.ok(msg.length > payload.length);
    assert.ok(msg.every((v) => v === 0), 'msg, which holds the payload, is not erased');
  } finally {
    subtle.sign = sign;
  }
});

test('scan says where each share starts and what ended it', async () => {
  const shares = await split(new TextEncoder().encode('typed by hand'), TypeText, 2, 2);
  const [a, b] = shares.map(encode);
  const text = `# plate 1, café\n${a.slice(0, 40).toLowerCase()}\n${a.slice(40, 62)}8${a.slice(62)}\n` +
    `# plate 2\n${b.slice(0, 30)}\n\u3000${b.slice(30)}\n` +
    'SHAQR:AAA\n';
  const found = scan(text);
  assert.deepEqual(found.map((f) => [f.line, f.endLine, f.stop, f.error === undefined]), [
    [2, 3, '8', true],
    [5, 7, undefined, true],
    [7, 8, undefined, false],
  ]);
  assert.equal(found[2].error.code, 'not-decoded');
  assert.deepEqual(found[1].share, shares[1]);

  // Characters outside ASCII before a share do not move its line.
  const more = `Ünïcödé\u3000lines\n${a.slice(0, 20)}\u00a0\n\u3000${a.slice(20, 40)}\u2028${a.slice(40)}\u205f\n` +
    `\u00a0\u00a0${b.slice(0, 31)}\u200b${b.slice(31)}\n`;
  const read = decode(more);
  assert.deepEqual(read.shares, [shares[0]]);
  assert.equal(read.rejected.length, 1);
  assert.match(read.rejected[0].message, /the share on line 4: 25 characters up to '\u200b' on line 4/);
});

test('the search for k shares that fit stops at its bound on work', async () => {
  const k = 254;
  const n = 255;
  const shares = await split(new TextEncoder().encode('bound'.repeat(60 * k)), TypeBytes, k, n, { derived: true });
  const wrong = shares.map((sh) => forge(sh, 3)); // every share claims the same other id
  await assert.rejects(combine(wrong), (err) => code('id')(err) && /the search stopped after/.test(err.message));
  const held = [forge(shares[0], 19 + 32 + 7), ...shares.slice(1)];
  assert.equal((await combine(held)).payload.length, 5 * 60 * k);
});

test('parseHeader', async () => {
  const shares = await split(bytes(10), TypeBytes, 2, 4);
  const h = await parseHeader(shares[3]);
  assert.deepEqual(h, { k: 2, x: 4, id: shares[0].subarray(3, 19), tag: tag(shares[0]) });
  const damaged = new Uint8Array(shares[3]);
  damaged[40] ^= 0x80;
  await assert.rejects(parseHeader(damaged), code('check'));
});

test('split and shareAt refuse what they cannot do', async () => {
  const payload = bytes(8);
  await assert.rejects(split(payload, TypeBytes, 1, 3), RangeError);
  await assert.rejects(split(payload, TypeBytes, 4, 3), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 256), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { derived: true, minLen: 32 }), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { r: bytes(16) }), RangeError);
  await assert.rejects(split(payload, 'U', 2, 3), TypeError);
  await assert.rejects(split('a string', TypeText, 2, 3), TypeError);
  const shares = await split(payload, TypeBytes, 2, 3);
  await assert.rejects(shareAt(shares, 0), RangeError);
  await assert.rejects(shareAt(shares, 256), RangeError);
});
