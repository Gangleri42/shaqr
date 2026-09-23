// SPDX-License-Identifier: CC0-1.0

package descriptor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// A packCase is a canonical text and its packed payload, in hex.
type packCase struct {
	Name   string `json:"name"`
	Text   string `json:"text"`
	Packed string `json:"packed"`
}

// An unpackCase is a payload, in hex, that Unpack refuses, with the
// error it gives: "not-packed" for ErrNotPacked, "invalid" for any
// other.
type unpackCase struct {
	Name   string `json:"name"`
	Packed string `json:"packed"`
	Error  string `json:"error"`
}

// Versions of SLIP 132, which BIP 380 does not allow.
const (
	versionZpub      = 0x04B24746
	versionYpub      = 0x049D7CB2
	versionZpubMulti = 0x02AA7ED3
)

// alter writes an extended key again after f has changed its 78 bytes.
func alter(key string, f func(raw []byte)) string {
	raw := bytes.Clone(decodeExtended(key))
	f(raw)
	return encodeExtended(raw)
}

func withVersion(key string, version uint32) string {
	return alter(key, func(raw []byte) { binary.BigEndian.PutUint32(raw, version) })
}

// packInputs are the texts of the packing vectors. The makeVectors of
// descriptor_test.go packs them.
func packInputs() []packCase {
	liana := strings.Fields(lianaKeys)
	lianaWith := func(children string) string {
		return withSum("wsh(or_d(multi(2," + liana[0] + multipath + "," + liana[1] + multipath +
			"),and_v(v:pkh(" + liana[2] + children + "),older(52560))))")
	}
	tap := "sortedmulti_a(2," + keyList(tapKeys, multipath) + ")"
	uncompressed := alter(xpubV1M, func(raw []byte) { raw[offKey] = 4 })
	// The last character of the xpub one higher, so that its check fails.
	badCheck := xpubV1M[:len(xpubV1M)-1] + "9"
	return []packCase{
		{Name: "DESCRIPTOR.md Sizes, 2-of-3, 457 bytes", Text: sizes2of3},
		{Name: "DESCRIPTOR.md Sizes, 3-of-5, 743 bytes", Text: sizes3of5},
		{Name: "DESCRIPTOR.md Sizes, 10-of-20, 2889 bytes", Text: sizes10of20},
		{Name: "2-of-3 with three paths, as Sparrow exports it", Text: withSum("wsh(sortedmulti(2," + keyList(sparrowKeys, multipath) + "))")},
		{Name: "tr() with an internal key beside a sortedmulti_a", Text: withSum("tr(" + tapInternalKey + multipath + "," + tap + ")")},
		{Name: "tr() with the NUMS hex key", Text: withSum("tr(" + hexNUMS + "," + tap + ")")},
		{Name: "Liana, a timelocked recovery key", Text: lianaWith(multipath)},
		{Name: "Liana, the recovery key on /<2;3>/*", Text: lianaWith("/<2;3>/*")},
		{Name: "xprv of a master key after an origin without steps", Text: withSum("wpkh([3442193e]" + xprvV1M + multipath + ")")},
		{Name: "xprv after an origin that does not imply its depth", Text: withSum("wpkh([aabbccdd/84h/0h/0h]" + xprvV1M + multipath + ")")},
		{Name: "tprv", Text: withSum("wpkh([3442193e]" + withVersion(xprvV1M, versions[3]) + multipath + ")")},
		{Name: "tpub after an origin that implies its depth", Text: withSum("wpkh([3442193e/0h]" + tpubV1H0 + multipath + ")")},
		{Name: "SLIP-132 zpub, the generic marker", Text: withSum("wpkh([3442193e/0h]" + withVersion(xpubV1H0, versionZpub) + multipath + ")")},
		{Name: "xpub whose key byte is 04, the generic marker", Text: withSum("wpkh(" + uncompressed + multipath + ")")},
		{Name: "a key whose depth disagrees with its origin", Text: withSum("wpkh([00000001/48h/0h/0h/2h]" + xpubV1M + multipath + ")")},
		{Name: "a key whose child number disagrees with its origin", Text: withSum("wpkh([d34db33f/1h]" + xpubV1H0 + multipath + ")")},
		{Name: "a key without origin", Text: withSum("wpkh(" + xpubV1M + multipath + ")")},
		{Name: "two origins without steps, the second with the same steps", Text: withSum("wsh(multi(2,[3442193e]" + xpubV1M + multipath + ",[d34db33f]" + hexG + "))")},
		{Name: "a sha256 hash packs as hex", Text: withSum("wsh(and_v(v:pk(" + hex2G + "),sha256(" + strings.Repeat("ab", 32) + ")))")},
		{Name: "an upper-case sha256 hash stays text", Text: withSum("wsh(and_v(v:pk(" + hex2G + "),sha256(" + strings.Repeat("AB", 32) + ")))")},
		{Name: "70 hex digits stay text", Text: withSum("raw(" + strings.Repeat("ab", 35) + ")")},
		{Name: "an origin with a leading zero stays text", Text: withSum("wpkh([d34db33f/084h/0h/0h]" + xpubV1M + multipath + ")")},
		{Name: "an origin with an index of 2^31 stays text", Text: withSum("wpkh([d34db33f/2147483648]" + xpubV1M + multipath + ")")},
		{Name: "an extended key with a bad base58check stays text", Text: withSum("wpkh(" + badCheck + multipath + ")")},
		{Name: "an address stays text", Text: withSum("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)")},
	}
}

// byHand returns the pieces of the packed payload of
// wpkh([d34db33f/0h]xpub.../<0;1>/*), whose origin gives the depth and
// child number of its key, written from DESCRIPTOR.md without the
// packer: the origin token, the key token, the key token with depth and
// child number, and the 78 bytes of the key.
func byHand() (origin, key, explicit, raw string) {
	r := decodeExtended(xpubV1H0)
	parity := r[45] - 2
	origin = "\x91\xd3\x4d\xb3\x3f\x01\x01"
	key = string([]byte{0x82 + parity}) + string(r[5:9]) + string(r[13:45]) + string(r[46:])
	explicit = string([]byte{0x80 + parity}) + string(r[4:45]) + string(r[46:])
	return origin, key, explicit, string(r)
}

// unpackInputs are the payloads that Unpack must refuse, with the error
// it must give.
func unpackInputs() []unpackCase {
	origin, key, explicit, raw := byHand()
	b, _ := hex.DecodeString(hexG)
	hexKey := "\x95" + string(b)
	cases := []unpackCase{
		{Name: "the children left as text", Packed: "wpkh(" + origin + key + multipath + ")", Error: "not-packed"},
		{Name: "an origin left as text", Packed: "wpkh([d34db33f/0h]" + explicit + "\x93)", Error: "not-packed"},
		{Name: "an extended key left as text", Packed: "wpkh(" + origin + xpubV1H0 + "\x93)", Error: "not-packed"},
		{Name: "a hex key left as text", Packed: "wpkh(" + hexG + ")", Error: "not-packed"},
		{Name: "depth and child number where the origin implies them", Packed: "wpkh(" + origin + explicit + "\x93)", Error: "not-packed"},
		{Name: "the generic marker for an xpub", Packed: "wpkh(" + origin + "\x90" + raw + "\x93)", Error: "not-packed"},
		{Name: "a number with a needless byte", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x81\x00\x01" + key + "\x93)", Error: "not-packed"},
		{Name: "the steps written again where the last origin had them", Packed: "wsh(multi(2," + origin + key + "\x93,\x91\x0b\xad\xc0\xde\x01\x01" + hexKey + "))", Error: "not-packed"},
		{Name: "the unused marker 0x89", Packed: "wpkh(\x89" + key[1:] + "\x93)", Error: "invalid"},
		{Name: "the unused marker 0x96", Packed: "wpkh(\x96)", Error: "invalid"},
		{Name: "the unused marker 0xff", Packed: "wpkh(\xff)", Error: "invalid"},
		{Name: "a truncated origin token", Packed: "wpkh(\x91\xd3\x4d", Error: "invalid"},
		{Name: "a truncated key token", Packed: "wpkh(" + origin + key[:40], Error: "invalid"},
		{Name: "a truncated hex key", Packed: "wpkh(" + hexKey[:30], Error: "invalid"},
		{Name: "a truncated number", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x81", Error: "invalid"},
		{Name: "more steps than bytes left", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x05\x01)", Error: "invalid"},
		{Name: "a number of six bytes", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x80\x80\x80\x80\x80\x00" + key + "\x93)", Error: "invalid"},
		{Name: "a step of 2^32", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x01\x80\x80\x80\x80\x10" + key + "\x93)", Error: "invalid"},
		{Name: "an implied depth with no origin before", Packed: "wpkh(" + key + "\x93)", Error: "invalid"},
		{Name: "an implied depth of 256", Packed: "wpkh(\x91\xd3\x4d\xb3\x3f\x80\x02" + strings.Repeat("\x00", 256) + key + "\x93)", Error: "invalid"},
		{Name: "the same steps with no origin before", Packed: "wpkh(\x92\xd3\x4d\xb3\x3f" + explicit + "\x93)", Error: "invalid"},
		{Name: "a character the checksum does not allow", Packed: "wpkh(\x01" + origin + key + "\x93)", Error: "invalid"},
	}
	for i := range cases {
		cases[i].Packed = hex.EncodeToString([]byte(cases[i].Packed))
	}
	return cases
}

// TestByHand checks that Pack writes what DESCRIPTOR.md says for one
// key, as byHand writes it.
func TestByHand(t *testing.T) {
	origin, key, _, _ := byHand()
	want := "wpkh(" + origin + key + "\x93)"
	got, err := Pack(withSum("wpkh([d34db33f/0h]" + xpubV1H0 + multipath + ")"))
	if err != nil || string(got) != want {
		t.Errorf("Pack = %x, %v\nwant %x", got, err, want)
	}
}

func TestPackVectors(t *testing.T) {
	for _, c := range loadVectors(t).Pack {
		if got, err := Canonical(c.Text); got != c.Text || err != nil {
			t.Errorf("%s: text is not canonical: %q, %v", c.Name, got, err)
		}
		p, err := Pack(c.Text)
		if err != nil || hex.EncodeToString(p) != c.Packed {
			t.Errorf("%s: Pack = %x, %v\nwant %s", c.Name, p, err, c.Packed)
			continue
		}
		if got, err := Unpack(p); got != c.Text || err != nil {
			t.Errorf("%s: Unpack = %q, %v", c.Name, got, err)
		}
	}
}

func TestUnpackVectors(t *testing.T) {
	for _, c := range loadVectors(t).Unpack {
		p, _ := hex.DecodeString(c.Packed)
		got, err := Unpack(p)
		if err == nil || errors.Is(err, ErrNotPacked) != (c.Error == "not-packed") {
			t.Errorf("%s: Unpack = %q, %v, want error %q", c.Name, got, err, c.Error)
		}
	}
}

func TestPackChecksum(t *testing.T) {
	desc := withSum("wpkh(" + hexG + ")")
	if _, err := Pack(desc[:len(desc)-9]); !errors.Is(err, ErrNoChecksum) {
		t.Errorf("Pack without checksum: %v", err)
	}
	if _, err := Pack(desc[:len(desc)-1] + "q"); !errors.Is(err, ErrChecksum) {
		t.Errorf("Pack with a wrong checksum: %v", err)
	}
}

// TestRandom packs and unpacks 10,000 random canonical descriptors.
func TestRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 10000 {
		desc, err := Canonical(randomDescriptor(r))
		if err != nil {
			t.Fatal(err)
		}
		p, err := Pack(desc)
		if err != nil {
			t.Fatalf("Pack(%q): %v", desc, err)
		}
		if got, err := Unpack(p); got != desc || err != nil {
			t.Fatalf("Unpack(Pack(%q)) = %q, %v", desc, got, err)
		}
	}
}

// TestMutations changes, inserts and deletes bytes of packed payloads.
// A mutant that unpacks gives another descriptor, and packs to itself.
func TestMutations(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for range 500 {
		desc, _ := Canonical(randomDescriptor(r))
		p, _ := Pack(desc)
		for range 20 {
			q := bytes.Clone(p)
			switch i := r.IntN(len(q)); r.IntN(3) {
			case 0:
				q[i] ^= byte(1 + r.IntN(255))
			case 1:
				q = append(q[:i], append([]byte{byte(r.Uint32())}, q[i:]...)...)
			case 2:
				q = append(q[:i], q[i+1:]...)
			}
			got, err := Unpack(q)
			if err != nil {
				continue
			}
			if got == desc {
				t.Fatalf("a mutant of the payload of %q unpacks to it", desc)
			}
			if again, _ := Pack(got); !bytes.Equal(again, q) {
				t.Fatalf("Unpack accepted %x, which is not the packed form of %q", q, got)
			}
		}
	}
}

// FuzzUnpack wants Unpack not to panic, and to accept only the packed
// form of the text it returns.
func FuzzUnpack(f *testing.F) {
	for _, c := range packInputs() {
		p, _ := Pack(c.Text)
		f.Add(p)
	}
	for _, c := range unpackInputs() {
		p, _ := hex.DecodeString(c.Packed)
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, packed []byte) {
		desc, err := Unpack(packed)
		if err != nil {
			return
		}
		if again, err := Pack(desc); err != nil || !bytes.Equal(again, packed) {
			t.Fatalf("Unpack(%x) = %q, which packs to %x, %v", packed, desc, again, err)
		}
	})
}

// randomDescriptor writes a descriptor of random keys in the spellings
// exporters use, apostrophes, upper-case fingerprints, white space and
// all, for Canonical to make canonical.
func randomDescriptor(r *rand.Rand) string {
	keys := make([]string, 1+r.IntN(20))
	for i := range keys {
		keys[i] = randomKey(r)
	}
	all, rest := strings.Join(keys, ","), strings.Join(keys[1:], ",")
	k, kr := 1+r.IntN(len(keys)), 1+r.IntN(max(len(keys)-1, 1))
	var d string
	switch {
	case len(keys) == 1:
		d = fmt.Sprintf([]string{"wpkh(%s)", "pkh(%s)", "tr(%s)", "wsh(pk(%s))", "sh(wpkh(%s))"}[r.IntN(5)], keys[0])
	default:
		d = []string{
			fmt.Sprintf("wsh(sortedmulti(%d,%s))", k, all),
			fmt.Sprintf("wsh(multi(%d,%s))", k, all),
			fmt.Sprintf("sh(wsh(sortedmulti(%d,%s)))", k, all),
			fmt.Sprintf("tr(%s,sortedmulti_a(%d,%s))", keys[0], kr, rest),
			fmt.Sprintf("tr(%s,{multi_a(%d,%s),pk(%s)})", keys[0], kr, rest, randomKey(r)),
			fmt.Sprintf("wsh(or_d(multi(%d,%s),and_v(v:pkh(%s),older(%d))))", kr, rest, keys[0], 1+r.IntN(65535)),
			fmt.Sprintf("tr(%s,pk(musig(%s)/<0;1>/*))", randomHex(r, 32), all),
			fmt.Sprintf("tr(musig(%s))", all),
		}[r.IntN(8)]
	}
	if r.IntN(4) == 0 {
		d = withSum(d)
	}
	if r.IntN(10) == 0 {
		d = strings.ReplaceAll(d, ",", ", ")
	}
	return d
}

func randomHex(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return hex.EncodeToString(b)
}

// randomKey returns a key expression with or without an origin, and
// with a key of any kind the packer tells apart: extended keys of every
// version, some agreeing with their origin, some with a bad check or a
// bad key byte, and hex keys in either case.
func randomKey(r *rand.Rand) string {
	var steps []uint32
	origin := ""
	if r.IntN(2) == 0 {
		fp := randomHex(r, 4)
		if r.IntN(5) == 0 {
			fp = strings.ToUpper(fp)
		}
		origin, steps = "["+fp, []uint32{}
		for range r.IntN(7) {
			i := uint32(r.IntN(100))
			switch r.IntN(10) {
			case 0:
				i = r.Uint32() >> 1
			case 1:
				i = 48
			}
			step := fmt.Sprint(i)
			if r.IntN(50) == 0 {
				step = "0" + step
			}
			if r.IntN(10) < 7 {
				step += []string{"h", "'"}[r.IntN(2)]
				i |= 1 << 31
			}
			origin += "/" + step
			steps = append(steps, i)
		}
		origin += "]"
	}
	var key string
	switch n := r.IntN(40); {
	case n == 0:
		key = []string{"02", "03"}[r.IntN(2)] + randomHex(r, 32)
	case n == 1:
		key = strings.ToUpper("02" + randomHex(r, 32))
	case n == 2:
		key = randomHex(r, 32)
	case n == 3:
		key = randomExtended(r, versions[0], steps)
		key = key[:50] + string(base58Alphabet[(strings.IndexByte(base58Alphabet, key[50])+1)%58]) + key[51:]
	case n == 4:
		key = randomExtended(r, []uint32{versionZpub, versionYpub, versionZpubMulti}[r.IntN(3)], steps)
	case n == 5:
		key = alter(randomExtended(r, versions[0], steps), func(raw []byte) { raw[offKey] = 4 })
	case n < 10:
		key = randomExtended(r, versions[1+r.IntN(3)], steps)
	default:
		key = randomExtended(r, versions[0], steps)
	}
	children := ""
	if extended(key) || r.IntN(20) == 0 {
		children = []string{"", "", "/0/*", multipath, multipath, multipath, "/1/*", "/*", "/0h/*", "/<2;3>/*", "/*'", "/<0;1;2>/*", "/0/1/*", "/<0';1'>/*"}[r.IntN(14)]
	}
	return origin + key + children
}

// randomExtended returns an extended key of the version given, which
// agrees with the steps of its origin two times in three when it has
// one, steps not nil.
func randomExtended(r *rand.Rand, version uint32, steps []uint32) string {
	raw := binary.BigEndian.AppendUint32(nil, version)
	depth, child := byte(r.IntN(8)), r.Uint32()
	if steps != nil && r.IntN(3) > 0 {
		depth, child = byte(len(steps)), 0
		if len(steps) > 0 {
			child = steps[len(steps)-1]
		}
	}
	raw = append(raw, depth)
	raw = binary.BigEndian.AppendUint32(raw, r.Uint32())
	raw = binary.BigEndian.AppendUint32(raw, child)
	for range 32 {
		raw = append(raw, byte(r.Uint32()))
	}
	first := byte(2 + r.IntN(2))
	if version == versions[2] || version == versions[3] {
		first = 0
	}
	raw = append(raw, first)
	for range 32 {
		raw = append(raw, byte(r.Uint32()))
	}
	return encodeExtended(raw)
}
