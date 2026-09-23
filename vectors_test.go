// SPDX-License-Identifier: CC0-1.0

package shaqr

// testdata/vectors.json holds the test vectors that every implementation
// of shaQR is meant to pass. This file writes it:
//
//	go test -run TestVectors -update
//
// rebuilds it from the inputs below. Without -update, TestVectors checks
// that the file is what the inputs give, rebuilds every valid set from
// the inputs in the file and compares the text byte for byte, and runs
// every invalid and text case through Decode, Group, Combine and Audit.
//
// testdata/README.md describes the file: its fields, and the words of
// expect.rejected, which reason gives for the errors of this package.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Gangleri42/shaqr/descriptor"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json from the inputs in vectors_test.go")

const vectorFile = "testdata/vectors.json"

type vectors struct {
	Valid   []validVector   `json:"valid"`
	Invalid []invalidVector `json:"invalid"`
	Text    []textVector    `json:"text"`
}

type validVector struct {
	Name    string   `json:"name"`
	Payload string   `json:"payload_hex"`
	Type    string   `json:"type"`
	Format  string   `json:"format"`
	K       int      `json:"k"`
	N       int      `json:"n"`
	R       string   `json:"r_hex"`
	PadTo   int      `json:"pad_to"`
	ID      string   `json:"id_hex"`
	Tag     string   `json:"tag"`
	Shares  []string `json:"shares"`
}

type invalidVector struct {
	Name   string  `json:"name"`
	Text   string  `json:"text"`
	Expect outcome `json:"expect"`
}

type outcome struct {
	Recovered []recovered `json:"recovered"`
	Rejected  []string    `json:"rejected"`
}

type recovered struct {
	Type    string `json:"type"`
	Payload string `json:"payload_hex"`
}

type textVector struct {
	Name     string   `json:"name"`
	Input    string   `json:"input"`
	Shares   []string `json:"shares_hex"`
	Rejected int      `json:"rejected"`
}

// wallet is a 2-of-3 descriptor of 457 bytes in the canonical form of
// DESCRIPTOR.md. Its keys are m/48h/0h/0h/2h of the BIP 39 test mnemonics
// "abandon .. about", "legal winner .. yellow" and "letter advice ..
// above", with no passphrase. Packed, it is 252 bytes.
const wallet = "wsh(sortedmulti(2," +
	"[28645006/48h/0h/0h/2h]xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6/<0;1>/*," +
	"[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*," +
	"[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/<0;1>/*" +
	"))#8rlnm9ua"

// validInputs are the inputs of the valid vectors. The invalid vectors
// cut up the sets of the first two, and the text vectors that of the
// first.
var validInputs = []validVector{
	{Name: "worked example of SPEC.md", Payload: hexOf("JBSWY3DPEHPK3PXP"), Type: "U", Format: "sealed", K: 2, N: 3, R: hex.EncodeToString(count(32))},
	{Name: "the payload of the worked example, open 2-of-3", Payload: hexOf("JBSWY3DPEHPK3PXP"), Type: "U", Format: "open", K: 2, N: 3},
	{Name: "empty payload", Payload: "", Type: "B", Format: "sealed", K: 2, N: 3, R: session("empty payload")},
	{Name: "empty payload, open 2-of-3: the shortest open share, 24 bytes", Payload: "", Type: "B", Format: "open", K: 2, N: 3},
	{Name: "password padded to 32", Payload: hexOf("correct horse"), Type: "U", Format: "sealed", K: 2, N: 3, R: session("password padded to 32"), PadTo: 32},
	{Name: "password padded to 32, 3-of-5", Payload: hexOf("correct horse"), Type: "U", Format: "sealed", K: 3, N: 5, R: session("password padded to 32, 3-of-5"), PadTo: 32},
	{Name: "descriptor of 457 bytes packed to 252, derived 2-of-3", Payload: packed(wallet), Type: "D", Format: "sealed", K: 2, N: 3},
	{Name: "descriptor of 457 bytes packed to 252, open 2-of-3", Payload: packed(wallet), Type: "D", Format: "open", K: 2, N: 3},
	{Name: "key of 32 bytes, 3-of-5", Payload: hex.EncodeToString(bytes.Repeat([]byte{0xa5, 0x5a}, 16)), Type: "B", Format: "sealed", K: 3, N: 5, R: session("key of 32 bytes, 3-of-5")},
	{Name: "text, open 3-of-5", Payload: hexOf("Meet at the old mill at noon, and bring the map."), Type: "U", Format: "open", K: 3, N: 5},
	{Name: "10-of-20", Payload: hex.EncodeToString(count(100)), Type: "B", Format: "sealed", K: 10, N: 20, R: session("10-of-20")},
	{Name: "k = n, 4-of-4", Payload: hexOf("four plates, all of them needed"), Type: "U", Format: "sealed", K: 4, N: 4, R: session("k = n, 4-of-4")},
	{Name: "2-of-255, one byte", Payload: "2a", Type: "B", Format: "sealed", K: 2, N: 255, R: session("2-of-255, one byte")},
	{Name: "2-of-255, one byte, open", Payload: "2a", Type: "B", Format: "open", K: 2, N: 255},
}

func hexOf(s string) string {
	return hex.EncodeToString([]byte(s))
}

// packed returns the packed payload of a descriptor with its checksum, in
// hex.
func packed(desc string) string {
	p, err := descriptor.Pack(desc)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p)
}

// session returns an r for a session set, fixed by the name of the vector.
func session(name string) string {
	r := sha256.Sum256([]byte("shaQR test vector r: " + name))
	return hex.EncodeToString(r[:])
}

// splitVector makes the set a valid vector describes.
func splitVector(v validVector) ([][]byte, error) {
	payload, err := hex.DecodeString(v.Payload)
	if err != nil {
		return nil, err
	}
	r, err := hex.DecodeString(v.R)
	if err != nil {
		return nil, err
	}
	open := v.Format == "open"
	sp := Splitter{Rand: bytes.NewReader(r), Open: open, Derived: len(r) == 0 && !open, MinLen: v.PadTo}
	return sp.Split(payload, v.Type[0], v.K, v.N)
}

// craft makes a derived-style set around sealed, which need not be the
// output of seal, so that a vector can hold a set with bad padding. It
// draws take as Split does.
func craft(sealed []byte, k, n int) [][]byte {
	_, take := drawTake(nil, k, sealed)
	return build(k, n, take, crypt(take[:keyLen], sealed))
}

// lines joins the text form of shares, one per line.
func lines(shares ...[]byte) string {
	var b strings.Builder
	for _, sh := range shares {
		b.WriteString(Encode(sh) + "\n")
	}
	return b.String()
}

// with returns a share with byte i set to v and a check that matches.
func with(sh []byte, i int, v byte) []byte {
	c := bytes.Clone(sh)
	c[i] = v
	return reseal(c)
}

func makeVectors(t *testing.T) *vectors {
	v := &vectors{}
	for _, in := range validInputs {
		shares, err := splitVector(in)
		if err != nil {
			t.Fatalf("%s: %v", in.Name, err)
		}
		h, _ := ParseHeader(shares[0])
		in.ID, in.Tag = hex.EncodeToString(h.ID[:]), h.Tag()
		for _, sh := range shares {
			in.Shares = append(in.Shares, Encode(sh))
		}
		v.Valid = append(v.Valid, in)
	}
	v.Invalid = invalidVectors(t)
	v.Text = textVectors(t)
	return v
}

func invalidVectors(t *testing.T) []invalidVector {
	a, err := splitVector(validInputs[0])
	if err != nil {
		t.Fatal(err)
	}
	o, err := splitVector(validInputs[1])
	if err != nil {
		t.Fatal(err)
	}
	b := mustSplit(t, &Splitter{Rand: bytes.NewReader(make([]byte, 32))}, []byte("another set"), TypeText, 2, 3)
	f := mustSplit(t, &Splitter{Rand: bytes.NewReader(bytes.Repeat([]byte{0xf0}, 32))}, []byte("framed"), TypeText, 2, 4)
	f = frame(f, []int{0, 1}, 0, 1)
	noMarker := craft([]byte("Uno marker\x00\x00"), 2, 2)
	markerOnly := craft([]byte{0x80, 0}, 2, 2)
	openNoMarker := build(2, 2, nil, []byte("Uno marker\x00\x00"))

	recA := recovered{"U", hexOf("JBSWY3DPEHPK3PXP")}
	flipped := bytes.Clone(a[0])
	flipped[30] ^= 1
	disputed := forge(a[1], hdrLen+keyLen+2)
	cutText := Encode(a[0])
	cutText = cutText[:len(cutText)-1] + "\n"

	cases := []struct {
		name      string
		text      string
		recovered []recovered
		rejected  []string
	}{
		{"check fails, the other shares go on", lines(flipped, a[1], a[2]), []recovered{recA}, []string{"check"}},
		{"check fails, too few left", lines(flipped, a[1]), nil, []string{"check", "too-few"}},
		{"format 0x03 with a valid check", lines(with(a[0], 0, 3), a[1], a[2]), []recovered{recA}, []string{"other-version"}},
		{"format 0x00 with a valid check", lines(with(o[0], 0, 0), o[1], o[2]), []recovered{recA}, []string{"other-version"}},
		{"x = 0", lines(with(a[0], 2, 0), a[1], a[2]), []recovered{recA}, []string{"malformed"}},
		{"k = 1", lines(with(a[0], 1, 1), a[1], a[2]), []recovered{recA}, []string{"malformed"}},
		{"a sealed share of 55 bytes", lines(checked(a[0][:hdrLen+keyLen]), a[1], a[2]), []recovered{recA}, []string{"malformed"}},
		{"an open share of 23 bytes", lines(checked(o[0][:hdrLen]), o[1], o[2]), []recovered{recA}, []string{"malformed"}},
		{"a sealed share relabelled open", lines(with(a[0], 0, 2), a[1], a[2]), []recovered{recA}, []string{"too-few"}},
		{"a sealed set relabelled open", lines(with(a[0], 0, 2), with(a[1], 0, 2)), nil, []string{"id"}},
		{"an open share relabelled sealed", lines(with(o[0], 0, 1), o[1], o[2]), []recovered{recA}, []string{"malformed"}},
		{"open and sealed shares of one payload, k of each", lines(a[0], o[1], a[2], o[0]), []recovered{recA, recA}, nil},
		{"open and sealed shares of one payload, one of each", lines(a[0], o[1]), nil, []string{"too-few", "too-few"}},
		{"disputed x and no other", lines(a[1], disputed), nil, []string{"disputed", "too-few"}},
		{"disputed x, recovery goes on", lines(a[0], a[1], disputed, a[2]), []recovered{recA}, []string{"bad-share", "disputed"}},
		{"forged share, id fails", lines(forge(a[0], hdrLen+keyLen+4), a[1]), nil, []string{"id"}},
		{"forged share, a spare share recovers", lines(forge(a[0], hdrLen+keyLen+4), a[1], a[2]), []recovered{recA}, []string{"bad-share"}},
		{"forged key part, a spare share recovers", lines(a[0], forge(a[1], hdrLen+6), a[2]), []recovered{recA}, []string{"bad-share"}},
		{"open set, forged share, id fails", lines(forge(o[0], hdrLen+4), o[1]), nil, []string{"id"}},
		{"open set, forged share, a spare share recovers", lines(forge(o[0], hdrLen+4), o[1], o[2]), []recovered{recA}, []string{"bad-share"}},
		{"two forgers keep S, id fails", lines(f[0], f[1]), nil, []string{"id"}},
		{"two forgers keep S, spare shares recover", lines(f...), []recovered{{"U", hexOf("framed")}}, []string{"bad-share", "bad-share"}},
		{"no 0x80", lines(noMarker...), nil, []string{"padding"}},
		{"nothing before the 0x80", lines(markerOnly...), nil, []string{"padding"}},
		{"open set, no 0x80", lines(openNoMarker...), nil, []string{"padding"}},
		{"a share of another set among a complete set", lines(a[0], b[1], a[1], a[2]), []recovered{recA}, []string{"too-few"}},
		{"a share of another length with the same id", lines(a[0], checked(append(bytes.Clone(a[1][:len(a[1])-checkLen]), 0)), a[2]), []recovered{recA}, []string{"too-few"}},
		{"two sets", lines(b[2], a[0], b[0], a[2]), []recovered{{"U", hexOf("another set")}, recA}, nil},
		{"the same share twice", lines(a[1], a[1]), nil, []string{"too-few"}},
		{"too few shares", lines(a[2]), nil, []string{"too-few"}},
		{"text that does not decode", cutText + lines(a[1], a[2]), []recovered{recA}, []string{"not-decoded"}},
		{"a share too short to hold a check", "SHAQR:AEBA\n" + lines(a[1], a[2]), []recovered{recA}, []string{"check"}},
		{"a check alone", lines(check(nil)), nil, []string{"malformed"}},
		{"a label in base32 runs into the share before it", Encode(a[0]) + "\nPlate 2\n" + lines(a[1], a[2]), []recovered{recA}, []string{"check"}},
	}
	var out []invalidVector
	for _, tc := range cases {
		want := outcome{Recovered: tc.recovered, Rejected: tc.rejected}
		if want.Recovered == nil {
			want.Recovered = []recovered{}
		}
		if want.Rejected == nil {
			want.Rejected = []string{}
		}
		slices.Sort(want.Rejected)
		out = append(out, invalidVector{tc.name, tc.text, want})
	}
	return out
}

func textVectors(t *testing.T) []textVector {
	a, err := splitVector(validInputs[0])
	if err != nil {
		t.Fatal(err)
	}
	t1, t2 := Encode(a[0]), Encode(a[1])
	wrapped := func(s, sep string) string {
		var parts []string
		for len(s) > 20 {
			parts = append(parts, s[:20])
			s = s[20:]
		}
		return strings.Join(append(parts, s), sep)
	}
	last := len(t1) - 1
	unused := t1[:last] + string(b32Alphabet[strings.IndexByte(b32Alphabet, t1[last])|7])
	// U+001C to U+001F, which Python's str.isspace takes for white space,
	// each inside a copy of the share.
	var separators string
	for c := '\u001c'; c <= '\u001f'; c++ {
		separators += t1[:6+43] + string(c) + t1[6+43:] + "\n"
	}
	// A dotless i, which Unicode upper-cases to I, in place of the first I
	// of the share.
	lower := strings.ToLower(t1)
	i := strings.IndexByte(lower[6:], 'i') + 6
	dotless := lower[:i] + "\u0131" + lower[i+1:]
	cutAt, err := b32.DecodeString(t1[6:i])
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		input    string
		shares   [][]byte
		rejected int
	}{
		{"lower case", strings.ToLower(t1), a[:1], 0},
		{"mixed case prefix", "ShaQr:" + t1[6:], a[:1], 0},
		{"wrapped over lines with indentation", "    " + wrapped(t1, "\n    ") + "\n", a[:1], 0},
		{"tabs and CRLF inside a share", "SHAQR:\t" + wrapped(t1[6:], "\r\n\t"), a[:1], 0},
		{"two shares on consecutive lines", t1 + "\n" + t2 + "\n", a[:2], 0},
		{"two shares with nothing between them", t1 + t2, a[:2], 0},
		{"tags before, between and after shares", "#B962 1/3\n" + t1 + "\n#B962 2/3\n" + t2 + " #B962\n", a[:2], 0},
		{"a label in base32 ruins the share before it", t1 + "\nBob 2 of 3\n" + t2 + "\n", a[1:2], 1},
		{"padding", t1 + "=\n", a[:1], 0},
		{"lengths of 1, 3 and 6 modulo 8", "SHAQR:A\nSHAQR:AAA\nSHAQR:AAAAAA\n", nil, 3},
		{"one character short", t1[:last] + "\n", nil, 1},
		{"a character outside base32 ends a share", t1[:6+43] + "1" + t1[6+43:], nil, 1},
		{"a non-breaking space inside a share", t1[:6+43] + "\u00a0" + t1[6+43:], a[:1], 0},
		{"an ideographic space inside a share", t1[:6+20] + "\u3000" + t1[6+20:], a[:1], 0},
		{"every Unicode white space character inside a share", spaced(t1), a[:1], 0},
		{"a zero-width space is not white space and ends a share", t1[:6+43] + "\u200b" + t1[6+43:], nil, 1},
		{"U+001C to U+001F are not white space and each ends a share", separators, nil, 4},
		{"a zero-width no-break space, U+FEFF, is not white space and ends a share", t1[:6+43] + "\ufeff" + t1[6+43:], nil, 1},
		{"a long s is not an s, so the prefix is not one", "\u017fhaqr:" + t1[6:], nil, 0},
		{"a dotless i is not the base32 I and ends a share", dotless, [][]byte{cutAt}, 0},
		{"unused bits set", unused, a[:1], 0},
		{"text outside shares", "Backup of 23 September:\n\n" + t1 + "\n\n(keep apart from the seed)\n", a[:1], 0},
		{"the prefix alone", "SHAQR:", [][]byte{{}}, 0},
	}
	var out []textVector
	for _, tc := range cases {
		shares := []string{}
		for _, sh := range tc.shares {
			shares = append(shares, hex.EncodeToString(sh))
		}
		out = append(out, textVector{tc.name, tc.input, shares, tc.rejected})
	}
	return out
}

const b32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// whiteSpace holds every character with the Unicode White_Space property.
const whiteSpace = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008" +
	"\u2009\u200a\u2028\u2029\u202f\u205f\u3000"

// TestWhiteSpace checks that whiteSpace is the set unicode.IsSpace
// accepts, the set Decode deletes, so that the vector built from it
// covers every character of it.
func TestWhiteSpace(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) != strings.ContainsRune(whiteSpace, r) {
			t.Errorf("%U: unicode.IsSpace %v", r, unicode.IsSpace(r))
		}
	}
}

// spaced puts one white space character after each character of a share's
// text past the prefix, every white space character in turn.
func spaced(text string) string {
	var b strings.Builder
	spaces := []rune(whiteSpace)
	b.WriteString(text[:6])
	for i, c := range text[6:] {
		b.WriteRune(c)
		b.WriteRune(spaces[i%len(spaces)])
	}
	return b.String()
}

// marshal writes vectors as indented JSON with every character outside
// ASCII escaped, so that no invisible character hides in the file.
func marshal(v *vectors) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for s := buf.String(); s != ""; {
		r, n := utf8.DecodeRuneInString(s)
		if r < utf8.RuneSelf {
			out.WriteByte(s[0])
		} else {
			fmt.Fprintf(&out, `\u%04x`, r)
		}
		s = s[n:]
	}
	return out.Bytes(), nil
}

// reason turns an error from Decode, Group or Combine into the word the
// vectors use for it.
func reason(err error) string {
	for _, r := range []struct {
		err  error
		word string
	}{
		{ErrText, "not-decoded"},
		{ErrCheck, "check"},
		{ErrVersion, "other-version"},
		{ErrShare, "malformed"},
		{ErrDisputed, "disputed"},
		{ErrTooFew, "too-few"},
		{ErrID, "id"},
		{ErrPadding, "padding"},
	} {
		if errors.Is(err, r.err) {
			return r.word
		}
	}
	return err.Error()
}

// receive recovers what it can from text as a receiver would, and says
// what it reports.
func receive(text string) outcome {
	out := outcome{Recovered: []recovered{}, Rejected: []string{}}
	raws, bad := Decode(text)
	for _, err := range bad {
		out.Rejected = append(out.Rejected, reason(err))
	}
	sets, rejected := Group(raws)
	disputes := make(map[string]bool)
	for _, r := range rejected {
		if errors.Is(r.Err, ErrDisputed) {
			// Report each x once: format, k, x and id, and the length.
			at := fmt.Sprint(raws[r.Index][:hdrLen], len(raws[r.Index]))
			if disputes[at] {
				continue
			}
			disputes[at] = true
		}
		out.Rejected = append(out.Rejected, reason(r.Err))
	}
	for _, set := range sets {
		typ, payload, err := Combine(set)
		if err != nil {
			out.Rejected = append(out.Rejected, reason(err))
			continue
		}
		out.Recovered = append(out.Recovered, recovered{string(typ), hex.EncodeToString(payload)})
		offSet, _ := Audit(set)
		for range offSet {
			out.Rejected = append(out.Rejected, "bad-share")
		}
	}
	slices.Sort(out.Rejected)
	return out
}

func TestVectors(t *testing.T) {
	want, err := marshal(makeVectors(t))
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(vectorFile, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("%s differs from what the inputs give; run go test -run TestVectors -update", vectorFile)
	}

	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, vec := range v.Valid {
		t.Run("valid/"+vec.Name, func(t *testing.T) { checkValid(t, vec) })
	}
	for _, vec := range v.Invalid {
		t.Run("invalid/"+vec.Name, func(t *testing.T) {
			got := receive(vec.Text)
			if !slices.Equal(got.Recovered, vec.Expect.Recovered) || !slices.Equal(got.Rejected, vec.Expect.Rejected) {
				t.Errorf("got %+v\nwant %+v", got, vec.Expect)
			}
		})
	}
	for _, vec := range v.Text {
		t.Run("text/"+vec.Name, func(t *testing.T) {
			raws, rejected := Decode(vec.Input)
			got := []string{}
			for _, raw := range raws {
				got = append(got, hex.EncodeToString(raw))
			}
			if !slices.Equal(got, vec.Shares) || len(rejected) != vec.Rejected {
				t.Errorf("Decode = %v, %d rejected %v\nwant %v, %d rejected", got, len(rejected), rejected, vec.Shares, vec.Rejected)
			}
		})
	}
}

// checkValid rebuilds a valid vector from its inputs, compares the text
// byte for byte, and recovers the payload from the text of the first k
// and of the last k shares.
func checkValid(t *testing.T, v validVector) {
	shares, err := splitVector(v)
	if err != nil {
		t.Fatal(err)
	}
	var text []string
	for _, sh := range shares {
		text = append(text, Encode(sh))
	}
	if !slices.Equal(text, v.Shares) {
		t.Errorf("shares differ from the vector\n got %v\nwant %v", text, v.Shares)
	}
	h, _ := ParseHeader(shares[0])
	if hex.EncodeToString(h.ID[:]) != v.ID || h.Tag() != v.Tag || h.Open != (v.Format == "open") {
		t.Errorf("id = %x, tag %s, open %v, want %s, %s, %s", h.ID, h.Tag(), h.Open, v.ID, v.Tag, v.Format)
	}
	for _, held := range [][]string{v.Shares[:v.K], v.Shares[v.N-v.K:]} {
		raws, rejected := Decode(strings.Join(held, "\n"))
		typ, got, err := Combine(raws)
		if rejected != nil || err != nil || string(typ) != v.Type || hex.EncodeToString(got) != v.Payload {
			t.Errorf("Combine = %c, %x, %v, %v", typ, got, err, rejected)
		}
	}
}
