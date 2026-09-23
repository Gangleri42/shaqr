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

// reseal gives a share a check that matches, as a forger would.
function reseal(share) {
  const f = new Uint8Array(share);
  const n = f.length - 4;
  f.set(createHash('sha256').update('shaQR v1 check').update(f.subarray(0, n)).digest().subarray(0, 4), n);
  return f;
}

// forge changes byte i of a share and gives it a check that matches.
function forge(share, i) {
  const f = new Uint8Array(share);
  f[i] ^= 0x01;
  return reseal(f);
}

// relabel sets the format byte of a share and gives it a check that
// matches.
function relabel(share, format) {
  const f = new Uint8Array(share);
  f[0] = format;
  return reseal(f);
}

// subsets returns every k-subset of items.
function subsets(items, k) {
  if (k === 0) return [[]];
  if (items.length < k) return [];
  const [first, ...rest] = items;
  return [...subsets(rest, k - 1).map((sub) => [first, ...sub]), ...subsets(rest, k)];
}

const code = (c) => (err) => err instanceof ShaqrError && err.code === c;

test('random sets split and recovered', async () => {
  for (let i = 0; i < 200; i++) {
    const n = randomInt(20) === 0 ? 255 : randomInt(2, 21);
    const k = randomInt(2, Math.min(n, 12) + 1);
    const payload = bytes(randomInt(300));
    const type = randomInt(256);
    const options = [{}, { derived: true }, { minLen: randomInt(200) }, { open: true }][randomInt(4)];
    const about = `case ${i}: ${k}-of-${n}, ${payload.length} bytes, ${JSON.stringify(options)}`;

    const shares = await split(payload, type, k, n, options);
    const minLen = options.minLen ?? 0;
    const sealed = Math.max(payload.length + 2, minLen);
    assert.equal(shares[0].length, (options.open ? 23 : 55) + Math.ceil(sealed / k), about);
    assert.equal((await parseHeader(shares[0])).open, options.open === true, about);
    if (options.derived || options.open) {
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
  for (const [options, where] of [[{}, [19, 19 + 31, 51]], [{ open: true }, [19, 20]]]) {
    const shares = await split(payload, TypeBytes, 3, 6, options);
    for (const at of [...where, shares[0].length - 5]) {
      for (let x = 1; x <= 6; x++) {
        const held = shares.map((sh, i) => (i === x - 1 ? forge(sh, at) : sh));
        assert.deepEqual((await combine(held)).payload, payload);
        assert.deepEqual(await audit(held), [x]);
        const others = held.filter((sh, i) => i !== x - 1);
        await assert.rejects(combine([...pick(others, 2), held[x - 1]]), code('id'));
      }
    }
  }
});

test('open sets: every k-subset recovers and no smaller one does', async () => {
  for (let k = 2; k <= 10; k++) {
    for (const n of [k, k + 2, 255]) {
      const payload = bytes(randomInt(3 * k));
      const shares = await split(payload, TypeBytes, k, n, { open: true });
      assert.equal(shares[0].length, 23 + Math.ceil((payload.length + 2) / k));
      const tried = n > 20 ? shares.slice(n - k - 1) : shares;
      for (const sub of subsets(tried, k)) {
        assert.deepEqual((await combine(sub)).payload, payload, `${k}-of-${n}`);
      }
      for (const sub of subsets(tried, k - 1)) {
        await assert.rejects(combine(sub), code('too-few'), `${k}-of-${n}`);
      }
    }
  }
});

test('an open set is a function of the content type, the payload and k', async () => {
  const note = new TextEncoder().encode('Box 1207, Main Street branch; the key is with the lawyer');
  const shares = await split(note, TypeText, 2, 3, { open: true });
  // The output of the Go example of Splitter.Split with Open.
  assert.deepEqual(shares.map(encode), [
    'SHAQR:AIBACQG344HEXC24MX4UA2CAZLTIGOKVIJXXQIBRGIYDOLBAJVQWS3RAKN2HEZLFOQQGE4TBNZRWQLZHDPLA',
    'SHAQR:AIBAEQG344HEXC24MX4UA2CAZLTIGOJ3EB2GQZJANNSXSIDJOMQHO2LUNAQHI2DFEBWGC53ZMVZIAI2OXKQA',
    'SHAQR:AIBAGQG344HEXC24MX4UA2CAZLTIGOPI656ZDLZPLRLEGJFHSAPX3HNRRDSXNGTF4WQWA5DRSV65QM6P5AWA',
  ]);
  assert.equal(tag(shares[0]), '#40DB');
  assert.deepEqual((await split(note, TypeText, 2, 5, { open: true })).slice(0, 3), shares);
  // The first k shares hold the slices of sealed in the clear: T and the
  // payload, then the rest of the payload and 0x80.
  assert.deepEqual(shares[0].subarray(19, 48), Uint8Array.of(TypeText, ...note.subarray(0, 28)));
  assert.deepEqual(shares[1].subarray(19, 48), Uint8Array.of(...note.subarray(28), 0x80));

  const id = async (sh) => (await parseHeader(sh)).id;
  for (const other of [
    await split(note, TypeText, 3, 3, { open: true }),
    await split(note, TypeBytes, 2, 3, { open: true }),
    await split(note, TypeText, 2, 3, { derived: true }),
  ]) {
    assert.notDeepEqual(await id(other[0]), await id(shares[0]));
  }
});

test('open and sealed shares never form one set', async () => {
  const payload = new TextEncoder().encode('one payload in two formats');
  const sealed = await split(payload, TypeText, 2, 3, { derived: true });
  const open = await split(payload, TypeText, 2, 3, { open: true });
  const { sets, rejected } = await group([sealed[0], open[1], sealed[2], open[0]]);
  assert.deepEqual(sets, [[sealed[0], sealed[2]], [open[1], open[0]]]);
  assert.deepEqual(rejected, []);
  await assert.rejects(combine([sealed[0], open[1]]), code('set'));

  // A sealed share relabelled open, with a check that matches, lands in a
  // set of its own, and k of them fail the id.
  const flipped = sealed.map((sh) => relabel(sh, 2));
  assert.equal((await group([flipped[0], sealed[1], sealed[2]])).sets.length, 2);
  await assert.rejects(combine(flipped), code('id'));

  // An open share relabelled sealed is too short to be sealed, or fails
  // the id.
  await assert.rejects(parseHeader(relabel(open[0], 1)), code('malformed'));
  const long = await split(bytes(100), TypeBytes, 2, 2, { open: true });
  await assert.rejects(combine(long.map((sh) => relabel(sh, 1))), code('id'));
});

test('an open share below 24 bytes is dropped', async () => {
  const shares = await split(new Uint8Array(0), TypeBytes, 2, 3, { open: true });
  assert.equal(shares[0].length, 24);
  const short = reseal(shares[1].subarray(0, 23));
  const { sets, rejected } = await group([shares[0], short, shares[2]]);
  assert.deepEqual(rejected.map((r) => [r.index, r.error.code]), [[1, 'malformed']]);
  assert.deepEqual((await combine(sets[0])).payload, new Uint8Array(0));
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
  const sealed = seal(TypeText, payload, sealedLen(payload.length, k, 0));
  const key = bytes(32 * k);
  // An open set has an empty take, and C is sealed itself.
  for (const [name, take, c, where] of [
    ['sealed', key, crypt(key.subarray(0, 32), sealed), [19 + 5, 19 + 32 + 1]],
    ['open', new Uint8Array(0), new Uint8Array(sealed), [19, 19 + 2]],
  ]) {
    const good = await build(k, n, take, c);
    await verify(good, TypeText, payload, k);
    for (let i = 0; i < n; i++) {
      for (const at of where) {
        const bad = [...good];
        bad[i] = forge(bad[i], at);
        await assert.rejects(verify(bad, TypeText, payload, k), Error, `${name}: fault at byte ${at} of share ${i + 1}`);
      }
    }

    // A fault in C before the id was computed passes the id, and the
    // comparison with the input catches it.
    c[4] ^= 1;
    await assert.rejects(verify(await build(k, n, take, c), TypeText, payload, k), Error, `${name}: fault in C`);
    await assert.rejects(verify(good, TypeBytes, payload, k), Error, `${name}: wrong type`);
    const swapped = [good[1], good[0], ...good.slice(2)];
    await assert.rejects(verify(swapped, TypeText, payload, k), Error, `${name}: shares out of order`);
  }
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
  assert.deepEqual(h, { open: false, k: 2, x: 4, id: shares[0].subarray(3, 19), tag: tag(shares[0]) });
  const open = await split(bytes(10), TypeBytes, 3, 4, { open: true });
  assert.deepEqual(await parseHeader(open[1]), { open: true, k: 3, x: 2, id: open[0].subarray(3, 19), tag: tag(open[0]) });
  const damaged = new Uint8Array(shares[3]);
  damaged[40] ^= 0x80;
  await assert.rejects(parseHeader(damaged), code('check'));
  await assert.rejects(parseHeader(relabel(shares[0], 3)), code('other-version'));
  await assert.rejects(parseHeader(relabel(shares[0], 0)), code('other-version'));
});

test('split and shareAt refuse what they cannot do', async () => {
  const payload = bytes(8);
  await assert.rejects(split(payload, TypeBytes, 1, 3), RangeError);
  await assert.rejects(split(payload, TypeBytes, 4, 3), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 256), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { derived: true, minLen: 32 }), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { open: true, minLen: 32 }), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { open: true, derived: true }), RangeError);
  await assert.rejects(split(payload, TypeBytes, 2, 3, { r: bytes(16) }), RangeError);
  await assert.rejects(split(payload, 'U', 2, 3), TypeError);
  await assert.rejects(split('a string', TypeText, 2, 3), TypeError);
  const shares = await split(payload, TypeBytes, 2, 3);
  await assert.rejects(shareAt(shares, 0), RangeError);
  await assert.rejects(shareAt(shares, 256), RangeError);
});
