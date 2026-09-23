// SPDX-License-Identifier: CC0-1.0

// The little that a descriptor backup (DESCRIPTOR.md) needs to know about
// output descriptors: the BIP 380 checksum, the canonical form of the
// payload and the quorum of a multisig. It mirrors package descriptor of
// the Go reference and does not depend on the rest of this module.
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
// match, no-checksum for a missing one where verify requires it, and
// invalid for anything else.
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
// checksum, as a recovered descriptor payload must (DESCRIPTOR.md,
// Recovery). It trims nothing, since that text goes to wallet software
// byte for byte.
export function verify(desc) {
  const i = desc.lastIndexOf('#');
  if (i < 0) throw new DescriptorError('no-checksum', 'no checksum');
  if (desc.slice(i + 1) !== checksum(desc.slice(0, i))) {
    throw new DescriptorError('checksum', 'checksum does not match');
  }
}

// canonical returns the canonical form of a descriptor with its checksum,
// the payload of a descriptor backup (DESCRIPTOR.md, Payload). It deletes
// white space, verifies a checksum that is present, writes hardened steps
// as h and origin fingerprints in lower case, writes the children of every
// extended key as /<0;1>/* when they are absent, /0/* or /<0;1>/*, sorts
// the keys of every sortedmulti and sortedmulti_a, and computes the
// checksum afresh. Two exports of one wallet then give one payload, and so
// one derived set.
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

// canonicalize applies rules 1 to 3 of DESCRIPTOR.md, Payload, to the
// arguments of e and everything inside them.
function canonicalize(e) {
  for (const a of e.args) {
    if (isKey(e.name, a)) a.text = canonicalKey(a.text);
    else canonicalize(a);
  }
  if (sorted.has(fragment(e.name))) e.args = [e.args[0], ...e.args.slice(1).sort(byKey)];
}

// receiveChange holds the spellings of the children that exporters use
// for a wallet's receive and change branches.
const receiveChange = new Set(['', '/0/*', '/<0;1>/*']);

// canonicalKey applies rules 1 and 2 to a key expression. A ' marks only
// a hardened step in BIP 380, so it becomes h wherever it stands. A
// fingerprint is hex, so only ASCII letters change case.
function canonicalKey(key) {
  let [origin, k, children] = keyParts(key.replaceAll("'", 'h'));
  const fp = originFingerprint(origin);
  if (fp !== '') origin = `[${fp.replace(/[A-Z]+/g, (s) => s.toLowerCase())}${origin.slice(1 + fp.length)}`;
  if (extended(k) && receiveChange.has(children)) children = '/<0;1>/*';
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
// networks. SLIP 132 prefixes such as zpub are not valid in a descriptor
// and are left as given, like hex keys and WIF keys.
const extended = (key) => /^[xt](pub|prv)/.test(key);
