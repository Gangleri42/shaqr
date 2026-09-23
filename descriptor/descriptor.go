// SPDX-License-Identifier: CC0-1.0

// Package descriptor has the little that a descriptor backup
// (DESCRIPTOR.md) needs to know about output descriptors: the BIP 380
// checksum, the canonical form, the packed payload and the quorum of a
// multisig.
//
// It scans a descriptor into calls, tap trees and the leaf arguments
// between them, and does not parse descriptors in general. It does not
// check that a fragment gets the arguments it takes, that a key or a
// path is valid, or what a miniscript means. Square and angle brackets
// are not tracked, since in BIP 380 they hold no commas, parentheses or
// braces. Text after the ")" of a call, such as the derivation after a
// BIP 390 musig(), stays as written.
//
// Parentheses and braces may nest at most 1000 deep, which is far above
// the 128 levels of a BIP 341 tap tree and any practical miniscript, and
// a descriptor that nests deeper is refused as invalid. The bound keeps
// the recursion of this package, and so its stack, small on hostile
// input, and the JavaScript descriptor.js has the same one, so that the
// two refuse the same descriptors.
package descriptor

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var (
	// ErrChecksum reports a descriptor whose checksum does not match.
	ErrChecksum = errors.New("descriptor: checksum does not match")
	// ErrNoChecksum reports a descriptor without the checksum that
	// Verify requires.
	ErrNoChecksum = errors.New("descriptor: no checksum")

	errNest = errors.New("descriptor: parentheses and braces do not nest")
	errDeep = fmt.Errorf("descriptor: parentheses and braces nest deeper than %d", maxDepth)
)

// maxDepth is how deep parentheses and braces may nest.
const maxDepth = 1000

const (
	inputCharset = "0123456789()[],'/*abcdefgh@:$%{}" +
		"IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
		"ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
	checksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

var generator = [5]uint64{0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd}

func polymod(c uint64, v int) uint64 {
	top := c >> 35
	c = (c&0x7ffffffff)<<5 ^ uint64(v)
	for i, g := range generator {
		if top>>i&1 != 0 {
			c ^= g
		}
	}
	return c
}

// Checksum returns the eight character BIP 380 checksum of a descriptor
// given without one.
func Checksum(desc string) (string, error) {
	c := uint64(1)
	cls, n := 0, 0
	for _, ch := range desc {
		pos := strings.IndexRune(inputCharset, ch)
		if pos < 0 {
			return "", fmt.Errorf("descriptor: character %q is not allowed", ch)
		}
		c = polymod(c, pos&31)
		cls = cls*3 + pos>>5
		if n++; n == 3 {
			c = polymod(c, cls)
			cls, n = 0, 0
		}
	}
	if n > 0 {
		c = polymod(c, cls)
	}
	for i := 0; i < 8; i++ {
		c = polymod(c, 0)
	}
	c ^= 1

	var sum [8]byte
	for i := range sum {
		sum[i] = checksumCharset[c>>(5*(7-i))&31]
	}
	return string(sum[:]), nil
}

// Verify requires desc to end in "#" and its right checksum, as the
// text that Pack takes must. It trims nothing, since a recovered text
// goes to wallet software byte for byte.
func Verify(desc string) error {
	i := strings.LastIndexByte(desc, '#')
	if i < 0 {
		return ErrNoChecksum
	}
	sum, err := Checksum(desc[:i])
	if err != nil {
		return err
	}
	if desc[i+1:] != sum {
		return ErrChecksum
	}
	return nil
}

// Canonical returns the canonical form of a descriptor with its
// checksum (DESCRIPTOR.md Canonical form), the text that Pack turns into
// the payload of a descriptor backup. It deletes white space, verifies a
// checksum that is present, writes hardened steps as h, and origin
// fingerprints and hex keys in lower case, writes the children of every
// extended key outside a musig() as /<0;1>/* when they are absent, /0/*
// or /<0;1>/*, sorts the keys of every sortedmulti and sortedmulti_a,
// and computes the checksum afresh. Two exports of one wallet then give
// one text, and so one payload and one set.
func Canonical(desc string) (string, error) {
	desc = deleteSpace(desc)
	if i := strings.LastIndexByte(desc, '#'); i >= 0 {
		if err := Verify(desc); err != nil {
			return "", err
		}
		desc = desc[:i]
	}
	e, err := parse(desc)
	if err != nil {
		return "", err
	}
	if e.name == "" || e.name == "{" {
		return "", errors.New("descriptor: not a script expression")
	}
	e.canonicalize(false)
	desc = e.String()
	sum, err := Checksum(desc)
	if err != nil {
		return "", err
	}
	return desc + "#" + sum, nil
}

// Quorum reads the threshold k and the keys of a descriptor that has a
// single multi, sortedmulti, multi_a or sortedmulti_a holding every key
// expression of the descriptor (DESCRIPTOR.md Threshold). keys are the
// key expressions of that multi in the order of desc. For the canonical
// form that is the order of the payload, and share x goes on the plate
// of keys[x-1]. ok is false for every other descriptor, a tr() with an
// internal key among them, and the caller must then get k and n from
// the user. Quorum ignores white space and a checksum and does not
// verify it.
func Quorum(desc string) (k int, keys []string, ok bool) {
	desc = deleteSpace(desc)
	if i := strings.LastIndexByte(desc, '#'); i >= 0 {
		desc = desc[:i]
	}
	e, err := parse(desc)
	if err != nil {
		return 0, nil, false
	}
	var multis []expr
	all := 0
	e.walk(func(c expr) {
		if multi[fragment(c.name)] {
			multis = append(multis, c)
		}
		all += len(c.keys())
	})
	if len(multis) != 1 {
		return 0, nil, false
	}
	m := multis[0]
	keys = m.keys()
	if len(keys) != all || len(keys) != len(m.args)-1 || m.args[0].name != "" {
		return 0, nil, false
	}
	// The threshold is decimal digits and nothing else: no sign.
	t := m.args[0].text
	if t == "" || strings.Trim(t, "0123456789") != "" {
		return 0, nil, false
	}
	k, err = strconv.Atoi(t)
	if err != nil || k < 1 || k > len(keys) {
		return 0, nil, false
	}
	return k, keys, true
}

// Fingerprint returns the origin fingerprint of a key expression in
// lower case, or "" for a key with no origin or with one that is not 8
// hex digits.
func Fingerprint(key string) string {
	origin, _, _ := keyParts(key)
	fp := originFingerprint(origin)
	if len(fp) != 8 || strings.Trim(fp, "0123456789abcdefABCDEF") != "" {
		return ""
	}
	return lowerASCII(fp)
}

// lowerASCII returns s with ASCII letters in lower case and every other
// byte as it was. strings.ToLower would also turn the Kelvin sign and
// the dotted capital I into ASCII letters, which a checksum then
// accepts.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
	return string(b)
}

func deleteSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// An expr is a descriptor as the scanner sees it: a call name(args)
// with the text that follows its ")", a tap tree {args}, or a leaf, an
// argument with neither parentheses nor braces, such as a key
// expression, a number or a hash.
type expr struct {
	name string // the call's name with its wrappers, "{" for a tap tree, "" for a leaf
	args []expr
	text string // a leaf, or the text after a call's ")"
}

// parse scans s into an expr. It checks that parentheses and braces
// nest, no deeper than maxDepth, and that nothing but a call's name comes
// before its "(". One pass over s finds the bracket that closes each open
// one and the commas at its level, before any recursion, and building the
// expr from them reads every byte once more, so parse takes time linear
// in the length of s.
func parse(s string) (expr, error) {
	sc := scan{s: s, closeAt: make(map[int]int), commas: make(map[int][]int)}
	var open []int
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '{':
			if len(open) == maxDepth {
				return expr{}, errDeep
			}
			open = append(open, i)
		case ')', '}':
			if len(open) == 0 || closer[s[open[len(open)-1]]] != s[i] {
				return expr{}, errNest
			}
			sc.closeAt[open[len(open)-1]] = i
			open = open[:len(open)-1]
		case ',':
			if len(open) > 0 {
				o := open[len(open)-1]
				sc.commas[o] = append(sc.commas[o], i)
			}
		}
	}
	if len(open) > 0 {
		return expr{}, errNest
	}
	return sc.expr(0, len(s))
}

var closer = map[byte]byte{'(': ')', '{': '}'}

// A scan is a descriptor with its brackets matched: closeAt maps the
// offset of every "(" and "{" to that of its ")" or "}", and commas maps
// it to the offsets of the commas between its arguments.
type scan struct {
	s       string
	closeAt map[int]int
	commas  map[int][]int
}

// expr builds the expr of s[lo:hi], the whole descriptor or one argument
// of a call or tap tree.
func (sc *scan) expr(lo, hi int) (expr, error) {
	s := sc.s
	i := strings.IndexAny(s[lo:hi], "(){},")
	if i < 0 {
		return expr{text: s[lo:hi]}, nil
	}
	open := lo + i
	e := expr{name: s[lo:open]}
	switch {
	case s[open] == '(' && open > lo:
	case s[open] == '{' && open == lo:
		e.name = "{"
	default:
		return expr{}, fmt.Errorf("descriptor: %q out of place", s[open])
	}
	end := sc.closeAt[open]
	start := open + 1
	for _, c := range append(sc.commas[open], end) {
		a, err := sc.expr(start, c)
		if err != nil {
			return expr{}, err
		}
		e.args = append(e.args, a)
		start = c + 1
	}
	e.text = s[end+1 : hi]
	if strings.ContainsAny(e.text, "(){},") || e.name == "{" && e.text != "" {
		return expr{}, fmt.Errorf("descriptor: text after %q", s[end])
	}
	return e, nil
}

func (e expr) String() string {
	var b strings.Builder
	e.write(&b)
	return b.String()
}

// write writes e to b, so that printing takes time linear in the length
// of the text however deep it nests.
func (e expr) write(b *strings.Builder) {
	switch e.name {
	case "":
		b.WriteString(e.text)
		return
	case "{":
		b.WriteByte('{')
	default:
		b.WriteString(e.name + "(")
	}
	for i, a := range e.args {
		if i > 0 {
			b.WriteByte(',')
		}
		a.write(b)
	}
	if e.name == "{" {
		b.WriteByte('}')
	} else {
		b.WriteString(")" + e.text)
	}
}

// walk calls f with e and every call and tap tree inside it, parents
// first. It does not call f with leaves.
func (e expr) walk(f func(expr)) {
	if e.name == "" {
		return
	}
	f(e)
	for _, a := range e.args {
		a.walk(f)
	}
}

// fragment returns the name of a call without its miniscript wrappers,
// pk for v:pk.
func fragment(name string) string {
	return name[strings.LastIndexByte(name, ':')+1:]
}

var (
	multi  = map[string]bool{"multi": true, "sortedmulti": true, "multi_a": true, "sortedmulti_a": true}
	sorted = map[string]bool{"sortedmulti": true, "sortedmulti_a": true}

	// notKeys are the fragments whose arguments are hashes, addresses
	// or script bytes, never keys.
	notKeys = map[string]bool{"sha256": true, "hash256": true, "ripemd160": true, "hash160": true, "addr": true, "raw": true}
)

// keys returns the arguments of e that are key expressions.
func (e expr) keys() []string {
	var keys []string
	for _, a := range e.args {
		if isKey(e.name, a) {
			keys = append(keys, a.text)
		}
	}
	return keys
}

// isKey reports whether the argument a of a call is a key expression.
// Every leaf is one except a number and an argument of notKeys, so a key
// in a fragment this package does not know still counts, and Quorum errs
// on the side of asking the user. A hex key is told from a hash by where
// it stands, not by its text.
func isKey(call string, a expr) bool {
	return a.name == "" && strings.Trim(a.text, "0123456789") != "" && !notKeys[fragment(call)]
}

// canonicalize applies rules 1 to 3 of DESCRIPTOR.md Canonical form to
// the arguments of e and everything inside them. musig is whether e is
// inside a musig().
func (e *expr) canonicalize(musig bool) {
	musig = musig || fragment(e.name) == "musig"
	for i := range e.args {
		a := &e.args[i]
		if isKey(e.name, *a) {
			a.text = canonicalKey(a.text, musig)
		} else {
			a.canonicalize(musig)
		}
	}
	if sorted[fragment(e.name)] {
		slices.SortFunc(e.args[1:], byKey)
	}
}

// receiveChange holds the spellings of the children that exporters use
// for a wallet's receive and change branches.
var receiveChange = map[string]bool{"": true, "/0/*": true, "/<0;1>/*": true}

// canonicalKey applies rules 1 and 2 to a key expression, and only rule
// 1 when musig is set: a key inside a musig() keeps its children. A '
// marks only a hardened step in BIP 380, so it becomes h wherever it
// stands.
func canonicalKey(key string, musig bool) string {
	origin, k, children := keyParts(strings.ReplaceAll(key, "'", "h"))
	if fp := originFingerprint(origin); fp != "" {
		origin = "[" + lowerASCII(fp) + origin[1+len(fp):]
	}
	if (len(k) == 64 || len(k) == 66) && strings.Trim(k, "0123456789abcdefABCDEF") == "" {
		k = lowerASCII(k)
	}
	if extended(k) && receiveChange[children] && !musig {
		children = multipath
	}
	return origin + k + children
}

// byKey orders the keys of a sortedmulti by their origin and key, the
// text without the children, and then by the full text.
func byKey(a, b expr) int {
	ta, tb := a.String(), b.String()
	oa, ka, _ := keyParts(ta)
	ob, kb, _ := keyParts(tb)
	return cmp.Or(strings.Compare(oa+ka, ob+kb), strings.Compare(ta, tb))
}

// keyParts cuts a key expression into its origin "[...]", the key and
// its children "/...". The origin and the children can be "".
func keyParts(s string) (origin, key, children string) {
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i >= 0 {
			origin, s = s[:i+1], s[i+1:]
		}
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return origin, s[:i], s[i:]
	}
	return origin, s, ""
}

// originFingerprint returns the fingerprint of an origin "[fp/path]" as
// written, or "" for no origin.
func originFingerprint(origin string) string {
	if origin == "" {
		return ""
	}
	return origin[1 : 1+strings.IndexAny(origin[1:], "/]")]
}

// extended reports whether key is a BIP 32 extended key, which BIP 380
// writes with the prefixes xpub and xprv, or tpub and tprv on the test
// networks. SLIP 132 prefixes such as zpub are not valid in a descriptor,
// and their children stay as given, like those of hex keys and WIF keys.
func extended(key string) bool {
	for _, p := range []string{"xpub", "xprv", "tpub", "tprv"} {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
