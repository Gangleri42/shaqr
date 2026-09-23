// SPDX-License-Identifier: CC0-1.0

// The little that a descriptor backup (DESCRIPTOR.md) needs to know about
// output descriptors: the BIP 380 checksum, the canonical form, the packed
// payload and the quorum of a multisig. It mirrors package descriptor of
// the Go reference and does not depend on the rest of this module. pack
// and unpack return promises, since base58check needs SHA-256 from
// WebCrypto.
//
// It scans a descriptor into calls, tap trees and the leaf arguments
// between them, and does not parse descriptors in general. It does not
// check that a fragment gets the arguments it takes, that a key or a path
// is valid, or what a miniscript means. Square and angle brackets are not
// tracked, since in BIP 380 they hold no commas, parentheses or braces.
// Text after the ")" of a call, such as the derivation after a BIP 390
// musig(), stays as written.
//
// Parentheses and braces may nest at most 1000 deep, which is far above
// the 128 levels of a BIP 341 tap tree and any practical miniscript, and
// a descriptor that nests deeper is refused as invalid. The bound keeps
// the recursion of this module, and so its stack, small on hostile input,
// and the Go package has the same one, so that the two refuse the same
// descriptors.

// A DescriptorError has the code checksum for a checksum that does not
// match, no-checksum for a missing one where verify requires it,
// not-packed for bytes that unpack to a descriptor but are not the packed
// form of it, and invalid for anything else.
export class DescriptorError extends Error {
  constructor(code, message) {
    super(`descriptor: ${message}`);
    this.name = 'DescriptorError';
    this.code = code;
  }
}

const invalid = (message) => new DescriptorError('invalid', message);

const inputCharset =
  "0123456789()[],'/*abcdefgh@:$%{}" +
  'IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~' +
  'ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const checksumCharset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const generator = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(c, v) {
  const top = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(v);
  for (const [i, g] of generator.entries()) {
    if ((top >> BigInt(i)) & 1n) c ^= g;
  }
  return c;
}

// checksum returns the eight character BIP 380 checksum of a descriptor
// given without one.
export function checksum(desc) {
  let c = 1n;
  let cls = 0;
  let n = 0;
  for (const ch of desc) {
    const pos = inputCharset.indexOf(ch);
    if (pos < 0) throw invalid(`character ${JSON.stringify(ch)} is not allowed`);
    c = polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    if (++n === 3) {
      c = polymod(c, cls);
      cls = 0;
      n = 0;
    }
  }
  if (n > 0) c = polymod(c, cls);
  for (let i = 0; i < 8; i++) c = polymod(c, 0);
  c ^= 1n;

  let sum = '';
  for (let i = 0; i < 8; i++) sum += checksumCharset[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  return sum;
}

// verify throws a DescriptorError unless desc ends in "#" and its right
// checksum, as the text that pack takes must. It trims nothing, since a
// recovered text goes to wallet software byte for byte.
export function verify(desc) {
  const i = desc.lastIndexOf('#');
  if (i < 0) throw new DescriptorError('no-checksum', 'no checksum');
  if (desc.slice(i + 1) !== checksum(desc.slice(0, i))) {
    throw new DescriptorError('checksum', 'checksum does not match');
  }
}

// canonical returns the canonical form of a descriptor with its checksum
// (DESCRIPTOR.md, Canonical form), the text that pack turns into the
// payload of a descriptor backup. It deletes white space, verifies a
// checksum that is present, writes hardened steps as h, and origin
// fingerprints and hex keys in lower case, writes the children of every
// extended key outside a musig() as /<0;1>/* when they are absent, /0/* or
// /<0;1>/*, sorts the keys of every sortedmulti and sortedmulti_a, and
// computes the checksum afresh. Two exports of one wallet then give one
// text, and so one payload and one set.
export function canonical(desc) {
  desc = deleteSpace(desc);
  const i = desc.lastIndexOf('#');
  if (i >= 0) {
    verify(desc);
    desc = desc.slice(0, i);
  }
  const e = parse(desc);
  if (e.name === '' || e.name === '{') throw invalid('not a script expression');
  canonicalize(e);
  const text = print(e);
  return `${text}#${checksum(text)}`;
}

// quorum reads the threshold k and the keys of a descriptor that has a
// single multi, sortedmulti, multi_a or sortedmulti_a holding every key
// expression of the descriptor (DESCRIPTOR.md, Threshold), and returns
// { k, keys }. keys are the key expressions of that multi in the order of
// desc. For the canonical form that is the order of the payload, and share
// x goes on the plate of keys[x - 1]. quorum returns null for every other
// descriptor, a tr() with an internal key among them, and the caller must
// then get k and n from the user. It ignores white space and a checksum
// and does not verify it.
export function quorum(desc) {
  desc = deleteSpace(desc);
  const i = desc.lastIndexOf('#');
  if (i >= 0) desc = desc.slice(0, i);
  let e;
  try {
    e = parse(desc);
  } catch (err) {
    if (err instanceof DescriptorError) return null;
    throw err;
  }
  const all = calls(e);
  const multis = all.filter((c) => multi.has(fragment(c.name)));
  if (multis.length !== 1) return null;
  const [m] = multis;
  const [threshold, ...rest] = m.args;
  const keys = keysOf(m);
  const total = all.reduce((n, c) => n + keysOf(c).length, 0);
  const numeric = threshold.name === '' && /^[0-9]+$/.test(threshold.text);
  if (!numeric || keys.length !== rest.length || keys.length !== total) return null;
  const k = Number(threshold.text);
  return k >= 1 && k <= keys.length ? { k, keys } : null;
}

// fingerprint returns the origin fingerprint of a key expression in lower
// case, or '' for a key with no origin or with one that is not 8 hex
// digits.
export function fingerprint(key) {
  const fp = originFingerprint(keyParts(key)[0]);
  return /^[0-9a-fA-F]{8}$/.test(fp) ? fp.toLowerCase() : '';
}

const deleteSpace = (s) => s.replace(/\p{White_Space}/gu, '');

// An expr is a descriptor as the scanner sees it: a call name(args) with
// the text that follows its ")", a tap tree {args}, or a leaf, an argument
// with neither parentheses nor braces, such as a key expression, a number
// or a hash. name is the call's name with its wrappers, "{" for a tap tree
// and "" for a leaf, and text is the leaf or the text after a call's ")".

const structure = /[(){},]/;
const closer = { '(': ')', '{': '}' };

// maxDepth is how deep parentheses and braces may nest.
const maxDepth = 1000;

// parse scans s into an expr. It checks that parentheses and braces nest,
// no deeper than maxDepth, and that nothing but a call's name comes before
// its "(". One pass over s finds the bracket that closes each open one and
// the commas at its level, before any recursion, and building the expr
// from them reads every character once more, so parse takes time linear
// in the length of s.
function parse(s) {
  const closeAt = new Map();
  const commas = new Map();
  const open = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '(' || c === '{') {
      if (open.length === maxDepth) throw invalid(`parentheses and braces nest deeper than ${maxDepth}`);
      open.push(i);
    } else if (c === ')' || c === '}') {
      const o = open.pop();
      if (o === undefined || closer[s[o]] !== c) throw invalid('parentheses and braces do not nest');
      closeAt.set(o, i);
    } else if (c === ',' && open.length > 0) {
      const o = open[open.length - 1];
      if (!commas.has(o)) commas.set(o, []);
      commas.get(o).push(i);
    }
  }
  if (open.length > 0) throw invalid('parentheses and braces do not nest');

  // build returns the expr of s[lo:hi], the whole descriptor or one
  // argument of a call or tap tree.
  const build = (lo, hi) => {
    let at = lo;
    while (at < hi && !'(){},'.includes(s[at])) at++;
    if (at === hi) return { name: '', args: [], text: s.slice(lo, hi) };
    let name = s.slice(lo, at);
    if (s[at] === '{' && at === lo) name = '{';
    else if (s[at] !== '(' || at === lo) throw invalid(`"${s[at]}" out of place`);
    const end = closeAt.get(at);
    const args = [];
    let start = at + 1;
    for (const c of [...(commas.get(at) ?? []), end]) {
      args.push(build(start, c));
      start = c + 1;
    }
    const text = s.slice(end + 1, hi);
    if (structure.test(text) || (name === '{' && text !== '')) throw invalid(`text after "${s[end]}"`);
    return { name, args, text };
  };
  return build(0, s.length);
}

// print returns the text of e. It joins the pieces once, so that it takes
// time linear in the length of the text however deep it nests.
function print(e) {
  const pieces = [];
  const write = (x) => {
    if (x.name === '') {
      pieces.push(x.text);
      return;
    }
    pieces.push(x.name === '{' ? '{' : `${x.name}(`);
    x.args.forEach((a, i) => {
      if (i > 0) pieces.push(',');
      write(a);
    });
    pieces.push(x.name === '{' ? '}' : `)${x.text}`);
  };
  write(e);
  return pieces.join('');
}

// calls returns e and every call and tap tree inside it, parents first. It
// does not return leaves.
function calls(e, out = []) {
  if (e.name === '') return out;
  out.push(e);
  for (const a of e.args) calls(a, out);
  return out;
}

// fragment returns the name of a call without its miniscript wrappers, pk
// for v:pk.
const fragment = (name) => name.slice(name.lastIndexOf(':') + 1);

const multi = new Set(['multi', 'sortedmulti', 'multi_a', 'sortedmulti_a']);
const sorted = new Set(['sortedmulti', 'sortedmulti_a']);

// notKeys are the fragments whose arguments are hashes, addresses or
// script bytes, never keys.
const notKeys = new Set(['sha256', 'hash256', 'ripemd160', 'hash160', 'addr', 'raw']);

// keysOf returns the arguments of e that are key expressions.
const keysOf = (e) => e.args.filter((a) => isKey(e.name, a)).map((a) => a.text);

// isKey reports whether the argument a of a call is a key expression.
// Every leaf is one except a number and an argument of notKeys, so a key
// in a fragment this module does not know still counts, and quorum errs on
// the side of asking the user. A hex key is told from a hash by where it
// stands, not by its text.
const isKey = (call, a) => a.name === '' && /[^0-9]/.test(a.text) && !notKeys.has(fragment(call));

// canonicalize applies rules 1 to 3 of DESCRIPTOR.md, Canonical form, to
// the arguments of e and everything inside them. musig is whether e is
// inside a musig().
function canonicalize(e, musig = false) {
  musig ||= fragment(e.name) === 'musig';
  for (const a of e.args) {
    if (isKey(e.name, a)) a.text = canonicalKey(a.text, musig);
    else canonicalize(a, musig);
  }
  if (sorted.has(fragment(e.name))) e.args = [e.args[0], ...e.args.slice(1).sort(byKey)];
}

// receiveChange holds the spellings of the children that exporters use
// for a wallet's receive and change branches.
const receiveChange = new Set(['', '/0/*', '/<0;1>/*']);

// canonicalKey applies rules 1 and 2 to a key expression, and only rule 1
// when musig is set: a key inside a musig() keeps its children. A ' marks
// only a hardened step in BIP 380, so it becomes h wherever it stands. A
// fingerprint is hex, so only ASCII letters change case.
function canonicalKey(key, musig) {
  let [origin, k, children] = keyParts(key.replaceAll("'", 'h'));
  const fp = originFingerprint(origin);
  if (fp !== '') origin = `[${fp.replace(/[A-Z]+/g, (s) => s.toLowerCase())}${origin.slice(1 + fp.length)}`;
  if (/^(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{66})$/.test(k)) k = k.toLowerCase();
  if (extended(k) && receiveChange.has(children) && !musig) children = multipath;
  return origin + k + children;
}

// byKey orders the keys of a sortedmulti by their origin and key, the
// text without the children, and then by the full text. Every character
// of a valid descriptor is ASCII, so comparing strings compares bytes.
function byKey(a, b) {
  const ta = print(a);
  const tb = print(b);
  const [oa, ka] = keyParts(ta);
  const [ob, kb] = keyParts(tb);
  return compare(oa + ka, ob + kb) || compare(ta, tb);
}

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// keyParts cuts a key expression into its origin "[...]", the key and
// its children "/...". The origin and the children can be "".
function keyParts(s) {
  let origin = '';
  const close = s.indexOf(']');
  if (s.startsWith('[') && close >= 0) {
    origin = s.slice(0, close + 1);
    s = s.slice(close + 1);
  }
  const slash = s.indexOf('/');
  return slash < 0 ? [origin, s, ''] : [origin, s.slice(0, slash), s.slice(slash)];
}

// originFingerprint returns the fingerprint of an origin "[fp/path]" as
// written, or "" for no origin.
function originFingerprint(origin) {
  if (origin === '') return '';
  return origin.slice(1, 1 + origin.slice(1).search(/[/\]]/));
}

// extended reports whether key is a BIP 32 extended key, which BIP 380
// writes with the prefixes xpub and xprv, or tpub and tprv on the test
// networks. SLIP 132 prefixes such as zpub are not valid in a descriptor,
// and their children stay as given, like those of hex keys and WIF keys.
const extended = (key) => /^[xt](pub|prv)/.test(key);

// The markers that start the tokens of a packed descriptor. A key token
// has the marker markKey + 4 * kind + 2 * implied + parity.
const markKey = 0x80;
const markGeneric = 0x90; // any other extended key, all 78 bytes
const markOrigin = 0x91; // fingerprint, number of steps, steps
const markSamePath = 0x92; // fingerprint, and the steps of the last origin token
const markChildren = 0x93; // the children /<0;1>/*
const markHex32 = 0x94; // a hex key of 32 bytes
const markHex33 = 0x95; // a hex key of 33 bytes

// multipath is the text that markChildren stands for.
const multipath = '/<0;1>/*';

// versions are the BIP 32 versions of the four kinds of key token: xpub
// and tpub, whose keys are public, and xprv and tprv.
const versions = [0x0488b21e, 0x043587cf, 0x0488ade4, 0x04358394];

// pack returns a promise of the packed payload of a descriptor backup
// (DESCRIPTOR.md, Packed payload), a Uint8Array, from a descriptor with its
// checksum, as canonical returns it. Key origins, extended keys, hex keys
// and the children /<0;1>/* become binary tokens, and the "#" and checksum
// are dropped. pack verifies the checksum and throws a DescriptorError as
// verify does. It does not check that desc is canonical, since a receiver
// packs what it unpacked to check it, and that need not be canonical
// either.
export async function pack(desc) {
  verify(desc);
  return packText(desc.slice(0, -9));
}

// packText packs s, a descriptor without its "#" and checksum. At each
// offset it writes the bytes of the first rule of DESCRIPTOR.md that
// matches. steps are those of the last origin token, and originEnd is the
// offset where that token ended, or -1 before the first.
async function packText(s) {
  const out = [];
  let steps = [];
  let originEnd = -1;
  for (let i = 0; i < s.length; ) {
    const origin = matchOrigin(s, i);
    if (origin) {
      pushOrigin(out, origin, originEnd >= 0 && origin.steps.join() === steps.join());
      steps = origin.steps;
      i = originEnd = i + origin.n;
      continue;
    }
    const key = await matchExtended(s, i);
    if (key) {
      pushKey(out, key.raw, originEnd === i ? steps : null);
      i += key.n;
      continue;
    }
    const hex = matchHex(s, i);
    if (hex) {
      out.push(markHex32 + hex.length - 32, ...hex);
      i += 2 * hex.length;
    } else if (s.startsWith(multipath, i)) {
      out.push(markChildren);
      i += multipath.length;
    } else {
      out.push(s.charCodeAt(i++));
    }
  }
  return new Uint8Array(out);
}

// pushOrigin writes an origin token, with markSamePath when same is set:
// the last origin token had the same steps.
function pushOrigin(out, origin, same) {
  out.push(same ? markSamePath : markOrigin, ...origin.fp);
  if (same) return;
  pushNumber(out, origin.steps.length);
  for (const v of origin.steps) pushNumber(out, v);
}

// pushNumber writes v as unsigned LEB128.
function pushNumber(out, v) {
  for (; v >= 0x80; v = Math.floor(v / 0x80)) out.push((v % 0x80) | 0x80);
  out.push(v);
}

// pushKey writes the token of the 78 bytes of an extended key. steps are
// those of the origin token right before it, or null when there is none.
function pushKey(out, raw, steps) {
  const m = keyMarker(raw);
  if (m < 0) out.push(markGeneric, ...raw);
  else if (steps && implied(raw, steps)) {
    out.push(m + 2, ...raw.subarray(5, 9), ...raw.subarray(13, 45), ...raw.subarray(46));
  } else out.push(m, ...raw.subarray(4, 45), ...raw.subarray(46));
}

// keyMarker returns the marker of a key token for raw with the implied bit
// clear, or -1 for a key of another version, or whose first key byte does
// not fit its kind, which packs as markGeneric.
function keyMarker(raw) {
  const kind = versions.indexOf(uint32(raw, 0));
  const first = raw[45];
  if ((kind === 0 || kind === 1) && (first === 2 || first === 3)) return markKey + 4 * kind + first - 2;
  if ((kind === 2 || kind === 3) && first === 0) return markKey + 4 * kind;
  return -1;
}

// implied reports whether the steps of an origin give the depth and the
// child number of an extended key.
const implied = (raw, steps) => raw[4] === steps.length && uint32(raw, 9) === childNumber(steps);

// childNumber returns the BIP 32 child number of the last of steps, its
// index plus 2^31 when it is hardened, or 0 when there are no steps.
function childNumber(steps) {
  if (steps.length === 0) return 0;
  const v = steps[steps.length - 1];
  return Math.floor(v / 2) + (v % 2) * 2 ** 31;
}

const uint32 = (b, at) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const uint32Bytes = (v) => [v >>> 24, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];

// originRule matches "[", eight lower-case hex digits, any number of steps
// and "]", where a step is "/", a decimal index with no leading zero, and
// an optional "h".
const originRule = /\[([0-9a-f]{8})((?:\/(?:0|[1-9][0-9]*)h?)*)\]/y;

// matchOrigin matches rule 1 at s[i]: an origin whose indexes are below
// 2^31. It returns the fingerprint, each step as 2 * index + 1 when it has
// h and 2 * index when it does not, and the length of the match, or null.
function matchOrigin(s, i) {
  originRule.lastIndex = i;
  const m = originRule.exec(s);
  if (!m) return null;
  const steps = [];
  for (const [, index, h] of m[2].matchAll(/\/([0-9]+)(h?)/g)) {
    if (Number(index) >= 2 ** 31) return null;
    steps.push(2 * Number(index) + (h ? 1 : 0));
  }
  return { fp: fromHex(m[1]), steps, n: m[0].length };
}

// matchExtended matches rule 2 at s[i]: the base58 characters from there
// to the first that is not base58, where s[i - 1] is not base58 either,
// when they are the base58check of 78 bytes. It returns a promise of those
// bytes and the number of characters, or of null.
async function matchExtended(s, i) {
  if (i > 0 && isBase58(s[i - 1])) return null;
  let j = i;
  while (j < s.length && isBase58(s[j])) j++;
  const raw = await decodeExtended(s.slice(i, j));
  return raw && { raw, n: j - i };
}

// matchHex matches rule 3 at s[i]: the lower-case hex digits from there to
// the first character that is not one, where s[i - 1] is not one either,
// when there are 64 or 66 of them. It returns their bytes, or null.
function matchHex(s, i) {
  if (i > 0 && isHexDigit(s[i - 1])) return null;
  let j = i;
  while (j < s.length && isHexDigit(s[j])) j++;
  return j - i === 64 || j - i === 66 ? fromHex(s.slice(i, j)) : null;
}

const isHexDigit = (c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
const fromHex = (s) => Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// unpack returns a promise of the descriptor with its checksum that a
// packed payload, a Uint8Array, holds (DESCRIPTOR.md, Packed payload). It
// packs that text again and throws a DescriptorError with the code
// not-packed when the bytes differ from packed, so that every descriptor
// has one packed form. Bytes that do not unpack at all throw one with the
// code invalid.
export async function unpack(packed) {
  const u = new Unpacker(packed);
  while (u.i < packed.length) await u.next();
  const s = u.pieces.join('');
  const sum = checksum(s);
  const again = await packText(s);
  if (again.length !== packed.length || again.some((b, i) => b !== packed[i])) {
    throw new DescriptorError('not-packed', 'not the packed form of its descriptor');
  }
  return `${s}#${sum}`;
}

// An Unpacker reads the tokens of p from offset i and collects their text
// in pieces. steps are those of the last origin token, null before the
// first, and afterOrigin is whether it is the token read last.
class Unpacker {
  constructor(p) {
    this.p = p;
    this.i = 0;
    this.pieces = [];
    this.steps = null;
    this.afterOrigin = false;
  }

  // next reads one token.
  async next() {
    const c = this.p[this.i++];
    const afterOrigin = this.afterOrigin;
    this.afterOrigin = false;
    if (c < markKey) this.pieces.push(String.fromCharCode(c));
    else if (c < markGeneric) this.pieces.push(await this.key(c, afterOrigin));
    else if (c === markGeneric) this.pieces.push(await encodeExtended(this.take(78)));
    else if (c === markOrigin || c === markSamePath) this.origin(c === markSamePath);
    else if (c === markChildren) this.pieces.push(multipath);
    else if (c === markHex32 || c === markHex33) this.pieces.push(toHex(this.take(32 + c - markHex32)));
    else throw unusedMarker(c);
  }

  // take reads the next n bytes.
  take(n) {
    if (n > this.p.length - this.i) throw invalid('packed token truncated');
    this.i += n;
    return this.p.subarray(this.i - n, this.i);
  }

  // number reads an unsigned LEB128 number below 2^32, which takes at most
  // five bytes.
  number() {
    let v = 0;
    for (let shift = 0; shift < 35; shift += 7) {
      const [b] = this.take(1);
      v += (b & 0x7f) * 2 ** shift;
      if (b >= 0x80) continue;
      if (v >= 2 ** 32) break;
      return v;
    }
    throw invalid('packed number not below 2^32 in five bytes');
  }

  // origin reads an origin token and collects it as "[fingerprint/steps]"
  // with h. same marks a markSamePath token, which takes the steps of the
  // last origin token.
  origin(same) {
    const fp = this.take(4);
    if (same && this.steps === null) throw noOrigin();
    if (!same) this.steps = this.readSteps();
    this.afterOrigin = true;
    const steps = this.steps.map((v) => `/${Math.floor(v / 2)}${v % 2 ? 'h' : ''}`);
    this.pieces.push(`[${toHex(fp)}${steps.join('')}]`);
  }

  // readSteps reads the number of steps and the steps of a markOrigin
  // token. Every step takes a byte, so a count above the bytes left is
  // refused before it allocates.
  readSteps() {
    const count = this.number();
    if (count > this.p.length - this.i) throw invalid('packed token truncated');
    return Array.from({ length: count }, () => this.number());
  }

  // key reads the key token with marker c and returns a promise of the key
  // as base58check. afterOrigin is whether an origin token came right
  // before it, which gives the depth and child number when the token
  // implies them. A depth is a byte, so no key implies more steps than 255.
  async key(c, afterOrigin) {
    const kind = (c - markKey) >> 2;
    const parity = c & 1;
    if (kind >= 2 && parity === 1) throw unusedMarker(c);
    let head;
    if (c & 2) {
      if (!afterOrigin || this.steps.length > 255) throw noOrigin();
      head = [this.steps.length, ...this.take(4), ...uint32Bytes(childNumber(this.steps))];
    } else {
      head = [...this.take(9)];
    }
    const rest = this.take(64);
    const first = kind < 2 ? 2 + parity : 0;
    const raw = [...uint32Bytes(versions[kind]), ...head, ...rest.subarray(0, 32), first, ...rest.subarray(32)];
    return encodeExtended(new Uint8Array(raw));
  }
}

const unusedMarker = (c) => invalid(`unused marker 0x${c.toString(16)}`);
const noOrigin = () => invalid('packed token needs an origin token before it');

// base58Alphabet is the alphabet of Bitcoin addresses.
const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58Digits = new Map(Array.from(base58Alphabet, (c, i) => [c, BigInt(i)]));
const isBase58 = (c) => base58Digits.has(c);

// base58Encode writes b in base58: a 1 for each leading zero byte and the
// rest as a number.
function base58Encode(b) {
  let n = 0n;
  for (const c of b) n = (n << 8n) | BigInt(c);
  let digits = '';
  for (; n > 0n; n /= 58n) digits = base58Alphabet[Number(n % 58n)] + digits;
  const zeros = b.findIndex((c) => c !== 0);
  return '1'.repeat(zeros < 0 ? b.length : zeros) + digits;
}

// base58Decode returns the bytes of s, whose characters must all be in the
// alphabet: a zero byte for each leading 1 and the rest as a number.
function base58Decode(s) {
  let n = 0n;
  for (const c of s) n = n * 58n + base58Digits.get(c);
  const bytes = [];
  for (; n > 0n; n >>= 8n) bytes.unshift(Number(n & 0xffn));
  const zeros = s.length - s.replace(/^1+/, '').length;
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

// checkOf returns a promise of the first four bytes of the double SHA-256
// of b, the check that base58check appends.
async function checkOf(b) {
  const h = await crypto.subtle.digest('SHA-256', await crypto.subtle.digest('SHA-256', b));
  return new Uint8Array(h, 0, 4);
}

// encodeExtended returns a promise of the 78 bytes of an extended key
// written as base58check.
async function encodeExtended(raw) {
  return base58Encode(new Uint8Array([...raw, ...(await checkOf(raw))]));
}

// decodeExtended returns a promise of the 78 bytes that s writes as
// base58check, or of null when s is not the base58check of 78 bytes. The
// 82 bytes with the check take 82 to 112 characters, so a string of any
// other length is not decoded.
async function decodeExtended(s) {
  if (s.length < 82 || s.length > 112) return null;
  const b = base58Decode(s);
  if (b.length !== 82) return null;
  const check = await checkOf(b.subarray(0, 78));
  return check.every((c, i) => c === b[78 + i]) ? b.slice(0, 78) : null;
}
