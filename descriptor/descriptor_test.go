// SPDX-License-Identifier: CC0-1.0

package descriptor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

var update = flag.Bool("update", false, "write testdata/descriptors.json from the inputs in this file")

const vectorsFile = "../testdata/descriptors.json"

// Extended keys of the BIP 32 test vectors 1 and 2, and tpubs holding
// two of the same keys.
const (
	xpubV1M      = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	xpubV1H0     = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	xpubV1H01    = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
	xpubV1H012H  = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
	xpubV1H012H2 = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
	xpubV1Leaf   = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
	xpubV2M      = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	xprvV1M      = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	tpubV1M      = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"
	tpubV1H0     = "tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm"

	// The points G, 2G and 3G of secp256k1 as compressed hex keys.
	hexG  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	hex2G = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	hex3G = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

	// The unspendable internal key of BIP 341.
	hexNUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

// The 2-of-3 wallet that most tests write in many ways.
var (
	walletFingerprints = [3]string{"d34db33f", "0badc0de", "cafef00d"}
	walletXpubs        = [3]string{xpubV1H012H, xpubV1H012H2, xpubV1Leaf}
)

// walletKey writes key i of the wallet with the hardened marker hard
// ("h" or "'") and the children given.
func walletKey(i int, hard, children string) string {
	return "[" + walletFingerprints[i] + "/48" + hard + "/0" + hard + "/0" + hard + "/2" + hard + "]" +
		walletXpubs[i] + children
}

// upper writes the origin fingerprint of a key expression in upper case.
func upper(key string) string {
	return key[:1] + strings.ToUpper(key[1:9]) + key[9:]
}

func wallet(keys ...string) string {
	return "wsh(sortedmulti(2," + strings.Join(keys, ",") + "))"
}

func withSum(desc string) string {
	sum, _ := Checksum(desc)
	return desc + "#" + sum
}

// walletCanonical is the canonical form of the wallet, written by hand:
// keys by fingerprint, h, /<0;1>/*.
var walletCanonical = withSum(wallet(walletKey(1, "h", "/<0;1>/*"), walletKey(2, "h", "/<0;1>/*"), walletKey(0, "h", "/<0;1>/*")))

// wrap breaks s into lines of 60 characters, as a document or a screen
// shows a long descriptor.
func wrap(s string) string {
	var lines []string
	for len(s) > 60 {
		lines, s = append(lines, s[:60]), s[60:]
	}
	return strings.Join(append(lines, s), "\n")
}

// A canonicalCase has either the canonical text of its input and the
// packed payload of that text, in hex, or the error it gives: "checksum"
// for ErrChecksum, "invalid" for any other.
type canonicalCase struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	Canonical string `json:"canonical,omitempty"`
	Packed    string `json:"packed,omitempty"`
	Error     string `json:"error,omitempty"`
}

type quorumCase struct {
	Name         string   `json:"name"`
	Input        string   `json:"input"`
	K            int      `json:"k"`
	N            int      `json:"n"`
	OK           bool     `json:"ok"`
	Fingerprints []string `json:"fingerprints,omitempty"`
}

type vectors struct {
	Canonical []canonicalCase `json:"canonical"`
	Quorum    []quorumCase    `json:"quorum"`
	Pack      []packCase      `json:"pack"`
	Unpack    []unpackCase    `json:"unpack"`
}

// canonicalInputs are the inputs of the canonicalisation vectors. The
// first nine are the wallet and give one canonical text.
func canonicalInputs() []canonicalCase {
	mixed := wallet(upper(walletKey(2, "'", "/0/*")), walletKey(0, "h", ""), walletKey(1, "'", "/<0;1>/*"))
	miniscript := "wsh(or_d(multi(2," + walletKey(0, "'", "/0/*") + "," + walletKey(1, "'", "") +
		"),and_v(v:pkh(" + walletKey(2, "'", "/0/*") + "),older(52560))))"
	return []canonicalCase{
		{Name: "wallet, canonical", Input: walletCanonical},
		{Name: "wallet, no checksum, other key order", Input: wallet(walletKey(0, "h", "/<0;1>/*"), walletKey(1, "h", "/<0;1>/*"), walletKey(2, "h", "/<0;1>/*"))},
		{Name: "wallet, apostrophes", Input: wallet(walletKey(2, "'", "/<0;1>/*"), walletKey(1, "'", "/<0;1>/*"), walletKey(0, "'", "/<0;1>/*"))},
		{Name: "wallet, /0/* children", Input: wallet(walletKey(1, "h", "/0/*"), walletKey(0, "h", "/0/*"), walletKey(2, "h", "/0/*"))},
		{Name: "wallet, no children", Input: wallet(walletKey(0, "h", ""), walletKey(2, "h", ""), walletKey(1, "h", ""))},
		{Name: "wallet, upper-case fingerprints", Input: wallet(upper(walletKey(1, "h", "/<0;1>/*")), upper(walletKey(2, "h", "/<0;1>/*")), upper(walletKey(0, "h", "/<0;1>/*")))},
		{Name: "wallet, mixed spellings with the exporter's checksum", Input: withSum(mixed)},
		{Name: "wallet, white space and line breaks", Input: "wsh(sortedmulti(2,\n  " + walletKey(2, "h", "/0/*") + ",\n  " + walletKey(1, "h", "") + ",\n  " + walletKey(0, "'", "/<0;1>/*") + "\n))\n"},
		{Name: "wallet, wrapped over lines, checksum of the text without white space", Input: wrap(withSum(mixed))},
		{Name: "multi keeps the key order and unifies the children", Input: "wsh(multi(2," + upper(walletKey(0, "'", "/0/*")) + "," + walletKey(1, "h", "") + "," + walletKey(2, "h", "/<0;1>/*") + "))"},
		{Name: "sortedmulti_a in tr with an internal key", Input: "tr([aabbccdd/86h/0h/0h]" + xpubV2M + "/0/*,sortedmulti_a(2," + walletKey(2, "'", "") + "," + walletKey(0, "h", "/0/*") + "," + walletKey(1, "h", "/<0;1>/*") + "))"},
		{Name: "hex keys in lower case, without children", Input: "wsh(sortedmulti(2,[D34DB33F/48'/0'/0'/2']" + hex3G + "," + strings.ToUpper(hexG) + "," + hex2G + "))"},
		{Name: "an x-only hex key in lower case, a hash as given", Input: "tr(" + strings.ToUpper(hexNUMS) + ",and_v(v:pk(" + strings.ToUpper(hex2G[2:]) + "),sha256(" + strings.Repeat("AB", 32) + ")))"},
		{Name: "other children stay as given", Input: wallet(walletKey(0, "h", "/1/*"), walletKey(1, "h", "/*"), walletKey(2, "'", "/0/*'"))},
		{Name: "tpub keys", Input: "sh(wsh(sortedmulti(2,[11111111/48h/1h/0h/1h]" + tpubV1M + "/0/*,[00000000/48'/1'/0'/1']" + tpubV1H0 + ")))"},
		{Name: "xprv key", Input: "wpkh([aabbccdd/84'/0'/0']" + xprvV1M + "/0/*)"},
		{Name: "miniscript keeps its structure", Input: miniscript},
		{Name: "DESCRIPTOR.md Sizes, 2-of-3, 457 bytes", Input: sizes2of3},
		{Name: "tr(musig(A,B)/<0;1>/*) stays as it is", Input: "tr(musig(" + walletKey(0, "h", "") + "," + walletKey(1, "h", "") + ")/<0;1>/*)"},
		{Name: "musig() keys keep the children they have", Input: "tr(" + hexNUMS + ",pk(musig(" + walletKey(0, "'", "/0/*") + "," + walletKey(1, "h", "/<0;1>/*") + "," + walletKey(2, "h", "") + ")))"},
		{Name: "a key beside a musig() gains /<0;1>/*", Input: "tr(" + hexNUMS + ",{pk(musig(" + walletKey(0, "h", "") + "," + walletKey(1, "h", "") + ")/<0;1>/*),pk(" + walletKey(2, "h", "/0/*") + ")})"},
		{Name: "wrong checksum", Input: walletCanonical[:len(walletCanonical)-1] + "q"},
		{Name: "empty checksum", Input: wallet(walletKey(0, "h", "")) + "#"},
		{Name: "unbalanced parentheses", Input: "wsh(sortedmulti(2," + walletKey(0, "h", "") + ")"},
		{Name: "a key alone is not a descriptor", Input: walletKey(0, "h", "/0/*")},
		{Name: "wallet, a non-breaking and an ideographic space", Input: "wsh(\u00a0sortedmulti(2," + walletKey(2, "h", "") + ",\u3000" + walletKey(1, "h", "") + "," + walletKey(0, "h", "") + "))"},
		{Name: "a Kelvin sign in a fingerprint is not lower-cased into ASCII", Input: wallet(strings.Replace(walletKey(0, "h", ""), "3f", "3\u212a", 1), walletKey(1, "h", ""), walletKey(2, "h", ""))},
		{Name: "nesting 1000 deep", Input: nested(999, "wpkh("+hexG+")")},
		{Name: "nesting 1001 deep", Input: nested(1000, "wpkh("+hexG+")")},
	}
}

// nested wraps desc in depth calls a(...).
func nested(depth int, desc string) string {
	return strings.Repeat("a(", depth) + desc + strings.Repeat(")", depth)
}

func quorumInputs() []quorumCase {
	keys := func(n int) string {
		var k []string
		for i := range n {
			k = append(k, walletKey(i%3, "h", "/<0;1>/*"))
		}
		return strings.Join(k, ",")
	}
	return []quorumCase{
		{Name: "wallet, canonical", Input: walletCanonical},
		{Name: "multi, key order as given", Input: "wsh(multi(2," + keys(3) + "))"},
		{Name: "sh(wsh(multi)), keys without origin, white space", Input: "sh(wsh(multi( 3 , " + keys(2) + "," + xpubV1M + ",\n" + xpubV1H0 + "/0/*," + xpubV1H01 + ")))"},
		{Name: "hex keys", Input: "wsh(sortedmulti(2,[d34db33f/48h/0h/0h/2h]" + hex3G + "," + hexG + "," + hex2G + "))"},
		{Name: "multi with a hash lock", Input: "wsh(and_v(v:multi(2," + keys(3) + "),sha256(" + strings.Repeat("ab", 32) + ")))"},
		{Name: "DESCRIPTOR.md Sizes, 2-of-3", Input: sizes2of3},
		{Name: "DESCRIPTOR.md Sizes, 10-of-20", Input: sizes10of20},
		{Name: "tr internal key beside sortedmulti_a", Input: "tr([aabbccdd/86h/0h/0h]" + xpubV2M + "/<0;1>/*,sortedmulti_a(2," + keys(3) + "))"},
		{Name: "tr unspendable internal key", Input: "tr(" + hexNUMS + ",sortedmulti_a(2," + keys(3) + "))"},
		{Name: "two multi_a in a tap tree", Input: "tr(" + hexNUMS + ",{multi_a(1," + keys(1) + "),multi_a(2," + keys(2) + ")})"},
		{Name: "timelocked key beside a multi", Input: "wsh(or_d(multi(2," + keys(2) + "),and_v(v:pkh(" + walletKey(2, "h", "/<0;1>/*") + "),older(52560))))"},
		{Name: "single key", Input: "wpkh([aabbccdd/84h/0h/0h]" + xpubV2M + "/<0;1>/*)"},
		{Name: "threshold above the number of keys", Input: "wsh(multi(3," + keys(2) + "))"},
		{Name: "unbalanced parentheses", Input: "wsh(multi(2," + keys(2) + ")"},
		{Name: "a threshold with a sign", Input: "wsh(multi(+1," + keys(2) + "))"},
		{Name: "nesting 5000 deep", Input: nested(4998, "wsh(multi(2,"+keys(2)+"))")},
	}
}

// makeVectors runs the implementation on the inputs, for -update.
func makeVectors() vectors {
	var v vectors
	for _, c := range canonicalInputs() {
		out, err := Canonical(c.Input)
		switch {
		case errors.Is(err, ErrChecksum):
			c.Error = "checksum"
		case err != nil:
			c.Error = "invalid"
		default:
			p, _ := Pack(out)
			c.Canonical, c.Packed = out, hex.EncodeToString(p)
		}
		v.Canonical = append(v.Canonical, c)
	}
	for _, c := range quorumInputs() {
		var keys []string
		c.K, keys, c.OK = Quorum(c.Input)
		c.N = len(keys)
		for _, key := range keys {
			c.Fingerprints = append(c.Fingerprints, Fingerprint(key))
		}
		v.Quorum = append(v.Quorum, c)
	}
	for _, c := range packInputs() {
		if p, err := Pack(c.Text); err != nil {
			c.Error = "invalid"
		} else {
			c.Packed = hex.EncodeToString(p)
		}
		v.Pack = append(v.Pack, c)
	}
	v.Unpack = unpackInputs()
	return v
}

func TestMain(m *testing.M) {
	flag.Parse()
	if *update {
		if err := writeVectors(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func writeVectors() error {
	data, err := marshal(makeVectors())
	if err != nil {
		return err
	}
	return os.WriteFile(vectorsFile, data, 0o644)
}

// marshal writes vectors as indented JSON with every character outside
// ASCII escaped, so that no invisible character hides in the file, as
// the vectors of package shaqr are written.
func marshal(v vectors) ([]byte, error) {
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

// TestVectorsCurrent checks that testdata/descriptors.json is what the
// inputs in this file give, so that no input is missing from the file
// that the JS tests read.
func TestVectorsCurrent(t *testing.T) {
	want, err := marshal(makeVectors())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("%s differs from what the inputs give; run go test ./descriptor/ -update", vectorsFile)
	}
}

func loadVectors(t *testing.T) vectors {
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCanonicalVectors(t *testing.T) {
	for _, c := range loadVectors(t).Canonical {
		got, err := Canonical(c.Input)
		if c.Error != "" {
			if err == nil || errors.Is(err, ErrChecksum) != (c.Error == "checksum") {
				t.Errorf("%s: Canonical = %q, %v, want error %q", c.Name, got, err, c.Error)
			}
			continue
		}
		if err != nil || got != c.Canonical {
			t.Errorf("%s: Canonical = %q, %v\nwant %q", c.Name, got, err, c.Canonical)
			continue
		}
		if again, err := Canonical(got); again != got || err != nil {
			t.Errorf("%s: canonical text changes again: %q, %v", c.Name, again, err)
		}
		p, err := Pack(got)
		if err != nil || hex.EncodeToString(p) != c.Packed {
			t.Errorf("%s: Pack = %x, %v\nwant %s", c.Name, p, err, c.Packed)
			continue
		}
		if back, err := Unpack(p); back != got || err != nil {
			t.Errorf("%s: Unpack = %q, %v", c.Name, back, err)
		}
	}
}

func TestQuorumVectors(t *testing.T) {
	for _, c := range loadVectors(t).Quorum {
		k, keys, ok := Quorum(c.Input)
		var fps []string
		for _, key := range keys {
			fps = append(fps, Fingerprint(key))
		}
		if k != c.K || len(keys) != c.N || ok != c.OK || !reflect.DeepEqual(fps, c.Fingerprints) {
			t.Errorf("%s: Quorum = %d, %d keys, %v, fingerprints %q", c.Name, k, len(keys), ok, fps)
		}
	}
}

// TestOneWallet writes the wallet in every key order and every mix of
// children, hardened markers and fingerprint case, and wants one
// canonical text for all of them.
func TestOneWallet(t *testing.T) {
	children := []string{"", "/0/*", "/<0;1>/*"}
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		for mix := range 27 * 64 {
			spell, flags := mix%27, mix/27
			var keys []string
			for j, i := range order {
				hard := "h"
				if flags>>j&1 != 0 {
					hard = "'"
				}
				key := walletKey(i, hard, children[spell%3])
				spell /= 3
				if flags>>(j+3)&1 != 0 {
					key = upper(key)
				}
				keys = append(keys, key)
			}
			in := wallet(keys...)
			if got, err := Canonical(in); got != walletCanonical || err != nil {
				t.Fatalf("Canonical(%q) = %q, %v\nwant %q", in, got, err, walletCanonical)
			}
		}
	}
}

// TestSizes checks the wallets of DESCRIPTOR.md Sizes: each is
// canonical, and its text and packed payload have the lengths given
// there.
func TestSizes(t *testing.T) {
	tests := []struct {
		desc         string
		text, packed int
	}{
		{sizes2of3, 457, 252},
		{sizes3of5, 743, 404},
		{sizes10of20, 2889, 1545},
	}
	for _, tc := range tests {
		got, err := Canonical(tc.desc)
		if err != nil || got != tc.desc || len(got) != tc.text {
			t.Errorf("Canonical of the %d byte wallet = %d bytes, %v", tc.text, len(got), err)
		}
		if p, err := Pack(tc.desc); len(p) != tc.packed || err != nil {
			t.Errorf("Pack of the %d byte wallet = %d bytes, %v, want %d", tc.text, len(p), err, tc.packed)
		}
	}
}

func TestChecksum(t *testing.T) {
	tests := []struct{ desc, sum string }{
		{"raw(deadbeef)", "89f8spxm"},
		{"addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)", "02wpgw69"},
		{"wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", "8zl0zxma"},
	}
	for _, tc := range tests {
		got, err := Checksum(tc.desc)
		if err != nil || got != tc.sum {
			t.Errorf("Checksum(%q) = %q, %v, want %q", tc.desc, got, err, tc.sum)
		}
	}
	if _, err := Checksum("raw(dead\x01beef)"); err == nil {
		t.Error("control character accepted")
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		desc string
		err  error
	}{
		{"raw(deadbeef)#89f8spxm", nil},
		{"raw(deadbeef)", ErrNoChecksum},
		{"raw(deadbeef)#89f8spxm\n", ErrChecksum},
		{"raw(deadbeef)#89f8spx", ErrChecksum},
		{"raw(deadbeef)#", ErrChecksum},
		{"raw(deedbeef)#89f8spxm", ErrChecksum},
	}
	for _, tc := range tests {
		if err := Verify(tc.desc); !errors.Is(err, tc.err) {
			t.Errorf("Verify(%q) = %v, want %v", tc.desc, err, tc.err)
		}
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct{ key, fp string }{
		{"[D34DB33F/48h/0h/0h/2h]" + xpubV1M + "/<0;1>/*", "d34db33f"},
		{"[0badc0de]" + hexG, "0badc0de"},
		{xpubV1M + "/0/*", ""},
		{hexG, ""},
		{"[d34db33]" + hexG, ""},
		{"[nothexok/1h]" + hexG, ""},
		{"[d34db33\u212a]" + hexG, ""},
		{"[+34db33f]" + hexG, ""},
	}
	for _, tc := range tests {
		if got := Fingerprint(tc.key); got != tc.fp {
			t.Errorf("Fingerprint(%q) = %q, want %q", tc.key, got, tc.fp)
		}
	}
}
