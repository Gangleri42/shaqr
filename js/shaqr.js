// SPDX-License-Identifier: CC0-1.0

// shaQR, Draft 4 of SPEC.md: k-of-n secret sharing in which a share is
// about 1/k the size of the secret. The construction is Krawczyk's
// "Secret Sharing Made Short". This module follows the API of the Go
// package, and its functions name the steps of SPEC.md that they carry
// out: shares are Uint8Arrays, and encode and decode convert them to and
// from the text form that goes into QR codes.
//
// SHA-256 and HMAC-SHA256 come from WebCrypto, so every function that
// computes a check or an id returns a promise. Browsers offer WebCrypto
// only to pages served over HTTPS or from localhost.

import { chacha20 } from './chacha20.js';
import { apply, basis, interp } from './gf256.js';

// Content types. Other values are reserved.
export const TypeBytes = 0x42; // B
export const TypeText = 0x55; // U, UTF-8 text, not normalized
export const TypeDescriptor = 0x44; // D, packed descriptor, DESCRIPTOR.md

// Formats, the first byte of every share.
const formatSealed = 0x01;
const formatOpen = 0x02;

const keyLen = 32;
const idLen = 16;
const checkLen = 4;
const hdrLen = 3 + idLen;

// keyPart returns the length of the key part of a share of the given
// format: keyLen in a sealed set, nothing in an open one.
const keyPart = (format) => (format === formatOpen ? 0 : keyLen);

// minShare returns the length of the shortest share of the given format:
// header, key part, one byte of data and check.
const minShare = (format) => hdrLen + keyPart(format) + 1 + checkLen;

// maxSealed is the length of one ChaCha20 stream, which bounds the sealed
// payload.
const maxSealed = 2 ** 38;

// maxSubsets bounds the lexicographic part of the search that combine
// makes when it holds spare shares and the first k do not verify.
const maxSubsets = 1024;

// maxWork bounds the whole of that search, runs included, in field
// multiplications (see fits), whatever k and the length of the shares
// are: about a second of work in Go, a few here.
const maxWork = 2 ** 27;

const ascii = (s) => new TextEncoder().encode(s);
const seedKey = ascii('shaQR v1 seed');
const idLabel = ascii('shaQR v1 id');
const checkLabel = ascii('shaQR v1 check');

const reasons = {
  'not-decoded': 'malformed text',
  check: 'share check failed',
  'other-version': 'share made by another version',
  malformed: 'malformed share',
  disputed: 'different shares with the same x',
  set: 'shares are not one set',
  'too-few': 'not enough shares',
  id: 'set id does not match',
  padding: 'bad padding',
};

// A ShaqrError reports a share or a set that recovery cannot use. Its
// code is one of the words testdata/vectors.json uses:
//
//   not-decoded    text after SHAQR: that does not decode (decode)
//   check          a share that fails its check
//   other-version  a share whose check matches and whose format is neither
//                  1, sealed, nor 2, open
//   malformed      a sealed share shorter than 56 bytes or an open one
//                  shorter than 24, or a share with x = 0 or k < 2
//   disputed       two or more different shares with the same x (group)
//   set            shares of more than one set (combine)
//   too-few        fewer than k undisputed x values
//   id             no k shares match the set id
//   padding        a set that passes the id and fails unsealing
//
// A too-few error from a set also has k, the threshold, held, the
// undisputed x values held, and disputed, the disputed x values, both in
// ascending order, as the TooFewError of the Go package has.
export class ShaqrError extends Error {
  constructor(code, detail) {
    super(`shaqr: ${reasons[code]}${detail ? `: ${detail}` : ''}`);
    this.name = 'ShaqrError';
    this.code = code;
  }
}

// split returns n shares of payload, a Uint8Array, any k of which recover
// it. Share i of the result has x = i + 1, and type is the content type,
// one byte. The options:
//
//   open     makes an open set: no key and no encryption, so that every
//            share is 32 bytes shorter and shows part of the payload. Use
//            it only for data that must survive lost shares and need not
//            stay private. An open set is a function of the content type,
//            the payload and k. It has no r, so open with derived is an
//            error, and it ignores r.
//   derived  makes a derived set: r is empty, and the set is a function of
//            the content type, the payload and k, so that it can be made
//            again later. Anyone with one share can then test guesses at
//            the payload. Use it only for payloads with at least 128 bits
//            an attacker cannot know. It ignores r.
//   minLen   pads the sealed payload to at least this many bytes, to hide
//            the length of short secrets. A derived or open set gets no
//            padding beyond what sealing needs, so derived or open with
//            minLen above 0 is an error.
//   r        the 32 bytes of r for a session set. Without it split draws
//            them from crypto.getRandomValues. Pass it only to reproduce a
//            set, as the test vectors do.
//
// Before it returns, split reads every share back from its text and
// recovers the payload from the k shares with the highest x (SPEC.md,
// Splitting, step 6), so a fault in the computation gives an error and no
// shares.
export async function split(payload, type, k, n, { open = false, derived = false, minLen = 0, r } = {}) {
  if (!(payload instanceof Uint8Array)) throw new TypeError('shaqr: the payload must be a Uint8Array');
  if (!isByte(type)) throw new TypeError(`shaqr: the content type ${type} is not one byte`);
  if (!(Number.isInteger(k) && Number.isInteger(n) && k >= 2 && k <= n && n <= 255)) {
    throw new RangeError(`shaqr: invalid threshold ${k} of ${n}`);
  }
  if (!Number.isInteger(minLen) || minLen < 0) throw new RangeError(`shaqr: invalid minLen ${minLen}`);
  if (open && derived) throw new RangeError('shaqr: an open set has no r and is not derived');
  if (open && minLen > 0) throw new RangeError('shaqr: an open set takes no padding');
  if (derived && minLen > 0) throw new RangeError('shaqr: a derived set takes no padding');
  const size = sealedLen(payload.length, k, minLen);
  if (size > maxSealed) throw new RangeError(`shaqr: ${size} sealed bytes exceed one ChaCha20 stream`);
  if (open) {
    const shares = await build(k, n, new Uint8Array(0), seal(type, payload, size));
    return selfChecked(shares, type, payload, k);
  }

  // Every secret is declared here and erased in finally, on the way out
  // of a failure too, such as WebCrypto missing from an insecure page.
  let rand, sealed, msg, seed, take;
  try {
    rand = random(derived, r);
    sealed = seal(type, payload, size);
    msg = concat([rand.length], rand, [k], sealed);
    seed = await hmac(seedKey, msg);
    take = stream(seed, keyLen * k);
    // take holds S and the R_i. The keystream under S turns into C in
    // place (see crypt), so it leaves nothing else to erase.
    const shares = await build(k, n, take, crypt(take.subarray(0, keyLen), sealed));
    return await selfChecked(shares, type, payload, k);
  } finally {
    erase(rand, sealed, msg, seed, take);
  }
}

// selfChecked runs step 6 of splitting on a new set and returns the set,
// or throws what verify found.
async function selfChecked(shares, type, payload, k) {
  try {
    await verify(shares, type, payload, k);
  } catch (err) {
    throw new Error(`shaqr: the new set fails its own check: ${err.message}`, { cause: err });
  }
  return shares;
}

const isByte = (v) => Number.isInteger(v) && v >= 0 && v <= 255;

// random returns r: nothing for a derived set, else a copy of the
// caller's 32 bytes or 32 fresh ones, in a buffer split can erase.
function random(derived, r) {
  if (derived) return new Uint8Array(0);
  if (r === undefined) return crypto.getRandomValues(new Uint8Array(32));
  if (!(r instanceof Uint8Array) || r.length !== 32) throw new RangeError('shaqr: r must be 32 bytes');
  return new Uint8Array(r);
}

// build computes the set id and shares 1 to n from take, the key
// polynomial at 0 .. k-1, and C (SPEC.md, Splitting, steps 4 and 5). take
// is empty only in an open set, whose C is sealed itself and whose shares
// have no key part.
async function build(k, n, take, c) {
  const format = take.length === 0 ? formatOpen : formatSealed;
  const id = await setID(format, k, take, c);
  const kp = keyPart(format);
  const b = c.length / k;
  const keyXs = Array.from({ length: k }, (_, i) => i);
  const dataXs = keyXs.map((i) => i + 1);
  const keyYs = keyXs.map((i) => take.subarray(kp * i, kp * (i + 1)));
  const dataYs = keyXs.map((i) => c.subarray(b * i, b * (i + 1)));
  const shares = [];
  for (let x = 1; x <= n; x++) {
    const sh = header(format, k, x, id, kp + b);
    if (kp > 0) interp(sh.subarray(hdrLen, hdrLen + kp), keyXs, keyYs, x);
    interp(sh.subarray(hdrLen + kp, hdrLen + kp + b), dataXs, dataYs, x);
    shares.push(await withCheck(sh));
  }
  return shares;
}

// header returns a share with format, k, x and id written and room for a
// body of bodyLen bytes and the check.
function header(format, k, x, id, bodyLen) {
  const sh = new Uint8Array(hdrLen + bodyLen + checkLen);
  sh.set([format, k, x]);
  sh.set(id, 3);
  return sh;
}

// withCheck writes the check of a share into its last four bytes and
// returns the share.
async function withCheck(sh) {
  const n = sh.length - checkLen;
  sh.set(await check(sh.subarray(0, n)), n);
  return sh;
}

// verify is step 6 of splitting. A fault in the code that made the shares
// also made their check and id, so only a recovery exposes it: verify
// reads every share back from its text, recovers the payload from the k
// shares with the highest x, and compares every share byte for byte with
// what the recovered polynomials give at its x.
async function verify(shares, type, payload, k) {
  const read = decode(shares.map(encode).join('\n'));
  if (read.rejected.length > 0 || read.shares.length !== shares.length) {
    throw new Error('the shares do not survive their text form');
  }
  for (const [i, sh] of read.shares.entries()) {
    if (!equal(sh, shares[i])) throw new Error(`share ${i + 1} does not survive its text form`);
  }

  const s = await newSet(read.shares.slice(-k));
  const sol = await solve(s);
  try {
    const got = unseal(s, sol);
    const same = got.type === type && equal(got.payload, payload);
    erase(got.payload);
    if (!same) throw new Error('the recovered payload differs from the input');
    for (const [i, sh] of shares.entries()) {
      if (!equal(await at(s, sol, i + 1), sh)) {
        throw new Error(`share ${i + 1} is off the recovered polynomials`);
      }
    }
  } finally {
    erase(sol.take);
  }
}

// combine recovers the content type and payload from k or more shares of
// one set, as { type, payload }. Every share must pass step 1 of
// recovering, and the result must match the set id, or combine throws a
// ShaqrError and gives no data. Shares of more than one set are an error
// too; group sorts them out beforehand.
//
// Exact copies of a share count once. Where two or more different shares
// have the same x, combine leaves that x out and goes on if k other x
// values remain. When fewer remain, SPEC.md allows a receiver to try the
// disputed shares in turn; combine does not, and throws too-few.
//
// Given spare shares, combine survives shares that pass their check and
// are wrong all the same: it tries runs of k consecutive shares, then
// k-subsets in lexicographic order, runs included, up to 1024 of them,
// until one matches the id. The whole search stops at a bound on its
// work, so with a large k and long shares it tries fewer, down to the
// first run alone, and throws id with a message that says it stopped.
// audit names the wrong shares.
export async function combine(shares) {
  const s = await newSet(shares);
  const sol = await solve(s);
  try {
    return unseal(s, sol);
  } finally {
    erase(sol.take);
  }
}

// shareAt returns the share with index x of the set the given shares
// belong to. It needs k shares that pass the id, and it does not decrypt:
// a set whose payload fails unsealing still gives shares, which recover to
// the same error. The caller holds a quorum and should treat the occasion
// like a recovery. shareAt replaces a lost share or adds one.
export async function shareAt(shares, x) {
  if (!Number.isInteger(x) || x < 1 || x > 255) throw new RangeError(`shaqr: invalid share index ${x}`);
  const s = await newSet(shares);
  const sol = await solve(s);
  try {
    return await at(s, sol, x);
  } finally {
    erase(sol.take);
  }
}

// audit returns, in ascending order, the x of every given share that is
// off the set's polynomials, a disputed x included when a share held at it
// is off. It needs k shares that pass the id, as combine does, and finds
// nothing to compare unless it has more. The id commits to take and C,
// which fix the key polynomial and the data polynomial, so the blame is
// right whenever the id passes.
export async function audit(shares) {
  const s = await newSet(shares);
  const sol = await solve(s);
  try {
    const bad = new Set();
    for (const sh of [...s.shares, ...s.disputed]) {
      if (!equal(await at(s, sol, sh.x), sh.raw)) bad.add(sh.x);
    }
    return [...bad].sort((a, b) => a - b);
  } finally {
    erase(sol.take);
  }
}

// group sorts shares into sets by format, k, id and length, in order of
// first appearance (SPEC.md, Recovering, steps 1 to 3), and returns
// { sets, rejected }. Shares of different sets are never combined, so a
// share scanned from the wrong plate lands in a set of its own and spoils
// nothing.
//
// A share that fails step 1 is rejected and joins no set. Where a set
// holds two or more different shares with the same x, each of them is
// rejected with the code disputed and stays in its set all the same:
// combine leaves that x out, and can then say how many other x values
// remain. rejected lists { index, error } in input order, where index is
// the position of the share in the input. A set may hold fewer than k
// shares, which combine reports.
export async function group(shares) {
  const groups = new Map();
  const rejected = [];
  for (const [index, raw] of shares.entries()) {
    let sh;
    try {
      sh = await parse(raw);
    } catch (error) {
      if (!(error instanceof ShaqrError)) throw error;
      rejected.push({ index, error });
      continue;
    }
    const key = `${sh.format} ${sh.k} ${hex(sh.id)} ${raw.length}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ sh, index });
  }

  const sets = [];
  for (const members of groups.values()) {
    const bad = disputed(members.map((m) => m.sh));
    for (const { sh, index } of members) {
      if (bad.has(sh.x)) {
        rejected.push({ index, error: new ShaqrError('disputed', `x = ${sh.x} of set ${tag(sh.raw)}`) });
      }
    }
    sets.push(members.map((m) => m.sh.raw));
  }
  rejected.sort((a, b) => a.index - b.index);
  return { sets, rejected };
}

// parseHeader verifies a share as step 1 of recovering does and returns
// its public part, { open, k, x, id, tag }, where open is true for a
// share of an open set, whose format byte is 2. A scanner that calls it
// on each share as it is read names a damaged share while its holder is
// still there to try again.
export async function parseHeader(share) {
  const sh = await parse(share);
  return { open: sh.format === formatOpen, k: sh.k, x: sh.x, id: new Uint8Array(sh.id), tag: tag(share) };
}

// tag returns the tag of the set a share belongs to: "#" and the first two
// bytes of the id as four upper-case hex digits, as in #B962. Tools use it
// to label shares and to name sets. It reads the id without verifying the
// share; parseHeader verifies it first.
export function tag(share) {
  return `#${hex(share.subarray(3, 5)).toUpperCase()}`;
}

// parse is step 1 of recovering for one decoded share: check first, then
// the format, then the fields that no share of its format can have. It
// throws a ShaqrError for a share that fails.
async function parse(raw) {
  const n = raw.length - checkLen;
  if (n < 0) throw new ShaqrError('check', `${raw.length} bytes cannot hold one`);
  if (!equal(await check(raw.subarray(0, n)), raw.subarray(n))) throw new ShaqrError('check');
  if (n > 0 && raw[0] !== formatSealed && raw[0] !== formatOpen) {
    throw new ShaqrError('other-version', `format ${raw[0]}`);
  }
  // A check alone is shorter than a share of either format.
  if (raw.length < minShare(raw[0])) throw new ShaqrError('malformed', `${raw.length} bytes`);
  const sh = { format: raw[0], k: raw[1], x: raw[2], id: raw.subarray(3, hdrLen), body: raw.subarray(hdrLen, n), raw };
  if (sh.k < 2) throw new ShaqrError('malformed', `k = ${sh.k}`);
  if (sh.x === 0) throw new ShaqrError('malformed', 'x = 0');
  return sh;
}

// disputed returns the x values at which shares holds two or more
// different shares.
function disputed(shares) {
  const first = new Map();
  const bad = new Set();
  for (const sh of shares) {
    const prev = first.get(sh.x);
    if (prev === undefined) first.set(sh.x, sh.raw);
    else if (!equal(prev, sh.raw)) bad.add(sh.x);
  }
  return bad;
}

// newSet parses shares that should all belong to one set and prepares
// them for recovery (SPEC.md, Recovering, steps 1 to 3). A set holds
// format, k, id and the body length, the shares recovery may use, one for
// each undisputed x and in order of x, and apart from them every share
// held at a disputed x.
async function newSet(raws) {
  if (raws.length === 0) throw new ShaqrError('too-few');
  const all = [];
  for (const [i, raw] of raws.entries()) {
    try {
      all.push(await parse(raw));
    } catch (err) {
      if (err instanceof ShaqrError) err.message += ` (share ${i + 1} of ${raws.length})`;
      throw err;
    }
  }
  const [{ format, k, id, body }] = all;
  if (all.some((sh) => sh.format !== format || sh.k !== k || !equal(sh.id, id) || sh.body.length !== body.length)) {
    throw new ShaqrError('set');
  }

  const bad = disputed(all);
  const held = new Map();
  const shelved = [];
  for (const sh of all) {
    if (bad.has(sh.x)) shelved.push(sh);
    else if (!held.has(sh.x)) held.set(sh.x, sh);
  }
  const shares = [...held.values()].sort((a, b) => a.x - b.x);
  if (shares.length < k) {
    const others = bad.size > 0 ? `, not counting ${bad.size} disputed x` : '';
    const err = new ShaqrError('too-few', `${shares.length} of ${k}${others}`);
    err.k = k;
    err.held = shares.map((sh) => sh.x);
    err.disputed = [...bad].sort((a, b) => a - b);
    throw err;
  }
  return { format, k, id, bodyLen: body.length, shares, disputed: shelved };
}

// solve finds k shares whose key polynomial and C match the set id
// (SPEC.md, Recovering, steps 4 and 5). It returns take, the key
// polynomial at 0 .. k-1, which is empty in an open set, C as c, and the
// shares that gave them, or throws id. It tries the k-subsets that
// subsets yields, in order, until their work reaches maxWork; it always
// tries the first. When the bound stops it early, the id error says so.
async function solve(s) {
  const { format, k } = s;
  const take = new Uint8Array(keyPart(format) * k);
  const c = new Uint8Array((s.bodyLen - keyPart(format)) * k);
  let tried = 0;
  let work = 0;
  for (const idx of subsets(k, s.shares.length)) {
    if (work >= maxWork) {
      erase(take);
      throw new ShaqrError('id', `the search stopped after ${tried} subsets, at its bound on work`);
    }
    tried++;
    const held = idx.map((i) => s.shares[i]);
    work += fits(k, held, take, c);
    if (equal(await setID(format, k, take, c), s.id)) return { take, c, held };
  }
  erase(take);
  throw new ShaqrError('id');
}

// fits interpolates take and c, which hold k values each, from the held
// shares, for solve to match against the set id, and returns roughly how
// many field multiplications that took: k*k for the denominators of the
// basis and 12 for each of its k inverses, up to 14k for the weights at
// each target, and one per byte for every nonzero weight. A target that
// is one of the held x values has one nonzero weight and any other has k,
// so a subset costs up to about k*k*bodyLen. The count is the one the Go
// package makes. An open set has no key part, and its take stays empty.
function fits(k, held, take, c) {
  const kp = take.length / k;
  const dataLen = c.length / k;
  const w = basis(held.map((sh) => sh.x));
  const keys = held.map((sh) => sh.body.subarray(0, kp));
  const data = held.map((sh) => sh.body.subarray(kp));
  const nonzero = (ws) => ws.filter((v) => v !== 0).length;
  let work = k * (k + 12);
  if (kp > 0) {
    for (let i = 0; i < k; i++) {
      const wi = w(i);
      apply(take.subarray(kp * i, kp * (i + 1)), wi, keys);
      work += 14 * k + nonzero(wi) * kp;
    }
  }
  for (let i = 1; i <= k; i++) {
    const wi = w(i);
    apply(c.subarray(dataLen * (i - 1), dataLen * i), wi, data);
    work += 14 * k + nonzero(wi) * dataLen;
  }
  return work;
}

// subsets yields the k-subsets of the positions 0 .. m-1 that solve
// tries, in order. First comes every run of k consecutive positions,
// wrapping around, starting with the k lowest x. A run that avoids the
// wrong shares exists whenever they sit next to each other and number no
// more than the spares, which covers one wrong share at any k. Then come
// k-subsets in lexicographic order, runs included, up to maxSubsets of
// them.
function* subsets(k, m) {
  const runs = m === k ? 1 : m;
  for (let start = 0; start < runs; start++) {
    yield Array.from({ length: k }, (_, i) => (start + i) % m);
  }
  const idx = Array.from({ length: k }, (_, i) => i);
  for (let tries = 0; tries < maxSubsets && next(idx, m); tries++) yield [...idx];
}

// next advances idx to the following k-subset of 0 .. m-1 in
// lexicographic order and reports whether there was one.
function next(idx, m) {
  const k = idx.length;
  for (let i = k - 1; i >= 0; i--) {
    if (idx[i] < m - k + i) {
      idx[i]++;
      for (let j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
      return true;
    }
  }
  return false;
}

// at returns the share at x of the polynomials through the shares that
// solve picked.
async function at(s, sol, x) {
  const sh = header(s.format, s.k, x, s.id, s.bodyLen);
  const xs = sol.held.map((h) => h.x);
  const ys = sol.held.map((h) => h.body);
  interp(sh.subarray(hdrLen, hdrLen + s.bodyLen), xs, ys, x);
  return withCheck(sh);
}

// sealedLen returns L, the length of the sealed payload: the payload and
// two bytes, at least minLen, rounded up to a multiple of k.
function sealedLen(payloadLen, k, minLen) {
  const n = Math.max(payloadLen + 2, minLen);
  return n + ((k - (n % k)) % k);
}

// seal returns T ‖ payload ‖ 0x80 followed by zero bytes up to size
// (SPEC.md, Splitting, step 1).
function seal(type, payload, size) {
  const s = new Uint8Array(size);
  s[0] = type;
  s.set(payload, 1);
  s[1 + payload.length] = 0x80;
  return s;
}

// unseal returns { type, payload } from what solve found in the set s
// (SPEC.md, Recovering, step 6). It decrypts C under S, the first 32
// bytes of take, in a sealed set and takes C as sealed in an open one,
// then strips trailing zero bytes and one 0x80 and splits off the content
// type. The payload it returns is a copy, and it erases the rest.
function unseal(s, sol) {
  const sealed = s.format === formatOpen ? sol.c : crypt(sol.take.subarray(0, keyLen), sol.c);
  try {
    let end = sealed.length;
    while (end > 0 && sealed[end - 1] === 0) end--;
    if (end === 0 || sealed[end - 1] !== 0x80) throw new ShaqrError('padding', 'no 0x80 after the payload');
    if (end === 1) throw new ShaqrError('padding', 'nothing before the 0x80');
    return { type: sealed[0], payload: sealed.slice(1, end - 1) };
  } finally {
    erase(sealed);
  }
}

// stream returns the first n bytes of the ChaCha20 keystream for a 32 byte
// key, a nonce of 12 zero bytes and block counter 0, 1, 2, ... The nonce
// can stay fixed because no key encrypts more than one message.
const stream = (key, n) => chacha20(key, new Uint8Array(12), 0, n);

// crypt returns data XOR stream(key, data.length), which encrypts and
// decrypts alike. The keystream turns into the result in place, so no
// copy of it is left behind.
function crypt(key, data) {
  const out = stream(key, data.length);
  for (let i = 0; i < out.length; i++) out[i] ^= data[i];
  return out;
}

// setID is step 4 of splitting. take is the key polynomial at 0 .. k-1,
// so the id commits to the whole key polynomial and not only to S. In an
// open set take is empty.
async function setID(format, k, take, c) {
  return (await sha256(idLabel, [format, k], take, c)).slice(0, idLen);
}

async function check(bytes) {
  return (await sha256(checkLabel, bytes)).slice(0, checkLen);
}

// sha256 hashes the parts joined, and erases the joined copy.
async function sha256(...parts) {
  const msg = concat(...parts);
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
  } finally {
    erase(msg);
  }
}

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// equal compares two byte strings without stopping at the first
// difference.
function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const hex = (bytes) => Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('');

// erase zeroes secrets once they are no longer needed, and skips those
// still undefined. JavaScript cannot promise more: the engine may have
// moved or copied them, and WebCrypto keeps its own copies of what it
// hashes.
function erase(...secrets) {
  for (const s of secrets) s?.fill(0);
}

// internals holds private functions for the tests in js/test, which
// check step 6 of splitting as the Go tests do. It is not part of the
// API and may change at any time.
export const internals = { build, verify, seal, sealedLen, crypt };

// Text form (SPEC.md).

const prefix = 'SHAQR:';
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// whiteSpace matches what a receiver deletes inside a share: a character
// with the Unicode White_Space property, the set unicode.IsSpace has in
// Go. Every other character outside base32 ends a share.
const whiteSpace = /^\p{White_Space}$/u;

// encode returns the text form of a share: the prefix and the share in
// upper-case RFC 4648 base32 with no padding and no white space. Every
// character is in the QR alphanumeric set.
export function encode(share) {
  let text = prefix;
  let acc = 0;
  let bits = 0;
  for (const byte of share) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      text += alphabet[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  // The unused low bits of the last character are zero.
  if (bits > 0) text += alphabet[(acc << (5 - bits)) & 31];
  return text;
}

// decode finds every share in text, which may hold shares of any number of
// sets beside labels and other text, decodes it (SPEC.md, Text form), and
// returns { shares, rejected }. Case does not matter, in the prefix
// either; only ASCII letters change case. A share starts after SHAQR: and
// runs to the next SHAQR:, to the first character that is neither base32
// nor white space, or to the end of text. White space inside a share is
// deleted, and text outside shares is ignored. White space is any
// character with the Unicode White_Space property: the ASCII white space,
// the non-breaking space that pasted text can carry, the ideographic
// space and the others.
//
// A share whose text does not decode goes into rejected, as a ShaqrError
// with the code not-decoded that gives its line, and the other shares are
// decoded all the same. decode does not verify checks: group, combine and
// parseHeader do. scan says where it found each share.
export function decode(text) {
  const shares = [];
  const rejected = [];
  for (const f of scan(text)) {
    if (f.error) rejected.push(f.error);
    else shares.push(f.share);
  }
  return { shares, rejected };
}

// scan finds the shares in text and decodes them as decode does, in order,
// and says where it found each, so that a tool can name the line of a
// share that does not decode or fails its check, and the character that
// cut it short. It returns one { share, error, line, stop, endLine } for
// each share: share, or error when its text does not decode; line, the
// line its SHAQR: is on, counting from 1; stop, the character, neither
// base32 nor white space, that ended the share, or undefined when the
// next SHAQR: or the end of the text did; and endLine, the line of
// whichever ended it. Lines are counted by line feeds.
export function scan(text) {
  // Only ASCII letters change case, so offsets into text still hold.
  const up = text.replace(/[a-z]+/g, (s) => s.toUpperCase());
  const found = [];
  const lines = (from, to) => up.slice(from, to).split('\n').length - 1;
  let line = 1;
  let counted = 0;
  for (let start = up.indexOf(prefix); start >= 0; ) {
    const next = up.indexOf(prefix, start + prefix.length);
    const end = next < 0 ? up.length : next;
    line += lines(counted, start);
    counted = start;
    const { chars, at, stop } = cut(up, start + prefix.length, end);
    const f = { share: undefined, error: undefined, line, stop, endLine: line + lines(start, at) };
    if ([1, 3, 6].includes(chars.length % 8)) {
      const upTo = stop === undefined ? '' : ` up to '${stop}' on line ${f.endLine}`;
      const why = `${chars.length} characters${upTo}, a length that base32 does not produce`;
      f.error = new ShaqrError('not-decoded', `the share on line ${line}: ${why}`);
    } else {
      f.share = fromBase32(chars);
    }
    found.push(f);
    start = next;
  }
  return found;
}

// cut returns the base32 characters of the share that starts at up[from],
// with white space deleted, the offset at which it ends, before up[end]
// at the latest, and the character that ends it, if one does. up is in
// upper case.
function cut(up, from, end) {
  let chars = '';
  let at = from;
  while (at < end) {
    const c = String.fromCodePoint(up.codePointAt(at));
    if (alphabet.includes(c)) chars += c;
    else if (!whiteSpace.test(c)) return { chars, at, stop: c };
    at += c.length;
  }
  return { chars, at: end };
}

// fromBase32 decodes base32 characters of a length that base32 produces.
// It ignores the unused low bits of the last character.
function fromBase32(chars) {
  const out = new Uint8Array(Math.floor((chars.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const c of chars) {
    acc = (acc << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = acc >> bits;
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}
