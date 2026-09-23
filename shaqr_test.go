// SPDX-License-Identifier: CC0-1.0

package shaqr

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// count returns the bytes 0, 1, .. n-1.
func count(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mustSplit splits payload with sp, or ends the test with the error.
func mustSplit(t testing.TB, sp *Splitter, payload []byte, typ byte, k, n int) [][]byte {
	t.Helper()
	shares, err := sp.Split(payload, typ, k, n)
	if err != nil {
		t.Fatal(err)
	}
	return shares
}

// checked appends a check to body.
func checked(body []byte) []byte {
	return append(bytes.Clone(body), check(body)...)
}

// reseal recomputes the check of a share, as a forger would.
func reseal(sh []byte) []byte {
	return checked(sh[:len(sh)-checkLen])
}

// forge flips a bit at offset i of a share and recomputes its check.
func forge(sh []byte, i int) []byte {
	c := bytes.Clone(sh)
	c[i] ^= 1
	return reseal(c)
}

// subsets calls f with every k-subset of shares.
func subsets(shares [][]byte, k int, f func([][]byte)) {
	idx := make([]int, k)
	for i := range idx {
		idx[i] = i
	}
	for {
		sub := make([][]byte, k)
		for i, j := range idx {
			sub[i] = shares[j]
		}
		f(sub)
		if !next(idx, len(shares)) {
			return
		}
	}
}

// The worked example of SPEC.md, value by value.
func TestWorkedExample(t *testing.T) {
	payload := []byte("JBSWY3DPEHPK3PXP")
	r := count(32)
	sealed := seal(TypeText, payload, sealedLen(len(payload), 2, 0))
	seed := mac([]byte("shaQR v1 seed"), []byte{32}, r, []byte{2}, sealed)
	take := stream(seed, 2*keyLen)
	c := crypt(take[:keyLen], sealed)
	for _, v := range []struct{ name, got, want string }{
		{"sealed", hex.EncodeToString(sealed), "554a425357593344504548504b3350585080"},
		{"seed", hex.EncodeToString(seed), "7868e5a0777f4832079e8a933e2dd37d833f954d1e2bf0f2a5c8a618bc752f64"},
		{"S", hex.EncodeToString(take[:keyLen]), "3c4a0309269d72e99a9696f9fd3f92fc69059757c347521c43cde1fb753eedd9"},
		{"R_1", hex.EncodeToString(take[keyLen:]), "b6cca4e219281751c973c2513fa4895327fff202d2d1eb6ee64efd806ff1771e"},
		{"C", hex.EncodeToString(c), "54b0b64bba71bfc06b92b4baf857b4cdc01f"},
		{"id", hex.EncodeToString(setID(2, take, c)), "b96219ec42ff7a50495969396067235c"},
	} {
		if v.got != v.want {
			t.Errorf("%s = %s, want %s", v.name, v.got, v.want)
		}
	}

	shares, err := (&Splitter{Rand: bytes.NewReader(r)}).Split(payload, TypeText, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantHex := []string{
		"010201b96219ec42ff7a50495969396067235cb6cca4e219281751c973c2513fa4895327fff202d2d1eb6ee64efd806ff1771e54b0b64bba71bfc06b9c6cfef4",
		"010202b96219ec42ff7a50495969396067235c335d56c458ecb8823c473eb26212a4b9f5ea5dfde1703bf812d0d90d41bbc24c92b4baf857b4cdc01f5f709904",
		"010203b96219ec42ff7a50495969396067235cb9dbf12f6759dd3a6fa26a1aa089bf16bb1038a8f0e6828ab753c5765b74588bd041be600cf7e3c033077eaf9c",
	}
	wantText := []string{
		"SHAQR:AEBADOLCDHWEF732KBEVS2JZMBTSGXFWZSSOEGJIC5I4S46CKE72JCKTE777EAWS2HVW5ZSO7WAG74LXDZKLBNSLXJY37QDLTRWP55A",
		"SHAQR:AEBAFOLCDHWEF732KBEVS2JZMBTSGXBTLVLMIWHMXCBDYRZ6WJRBFJFZ6XVF37PBOA57QEWQ3EGUDO6CJSJLJOXYK62M3QA7L5YJSBA",
		"SHAQR:AEBAHOLCDHWEF732KBEVS2JZMBTSGXFZ3PYS6Z2Z3U5G7ITKDKQITPYWXMIDRKHQ42BIVN2TYV3FW5CYRPIEDPTABT36HQBTA57K7HA",
	}
	for i, sh := range shares {
		if got := hex.EncodeToString(sh); got != wantHex[i] {
			t.Errorf("share %d = %s, want %s", i+1, got, wantHex[i])
		}
		if got := Encode(sh); got != wantText[i] {
			t.Errorf("text %d = %s, want %s", i+1, got, wantText[i])
		}
	}
	if h, err := ParseHeader(shares[0]); err != nil || h.Tag() != "#B962" {
		t.Errorf("tag = %s, %v, want #B962", h.Tag(), err)
	}
}

// RFC 8439, appendix A.1, test vector 1: the keystream for a zero key and
// nonce at block counter 0.
func TestStream(t *testing.T) {
	want := "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
		"da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
	if got := hex.EncodeToString(stream(make([]byte, 32), 64)); got != want {
		t.Errorf("stream = %s\nwant %s", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct{ k, n, size int }{
		{2, 3, 0}, {2, 3, 1}, {2, 3, 20}, {3, 5, 450}, {5, 9, 33}, {2, 2, 7}, {7, 7, 100}, {4, 10, 3}, {2, 255, 5},
	}
	for _, tc := range tests {
		for _, derived := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-of-%d/%d/derived=%v", tc.k, tc.n, tc.size, derived), func(t *testing.T) {
				payload := random(tc.size)
				shares, err := (&Splitter{Derived: derived}).Split(payload, TypeBytes, tc.k, tc.n)
				if err != nil {
					t.Fatal(err)
				}
				want := minShare - 1 + (tc.size+2+tc.k-1)/tc.k
				for _, sh := range shares {
					if len(sh) != want {
						t.Fatalf("share of %d bytes, want %d", len(sh), want)
					}
				}
				if tc.n > 20 {
					shares = shares[len(shares)-tc.k-1:]
				}
				subsets(shares, tc.k, func(sub [][]byte) {
					typ, got, err := Combine(sub)
					if err != nil || typ != TypeBytes || !bytes.Equal(got, payload) {
						t.Fatalf("Combine = %c, %x, %v", typ, got, err)
					}
				})
				subsets(shares, tc.k-1, func(sub [][]byte) {
					if _, _, err := Combine(sub); !errors.Is(err, ErrTooFew) {
						t.Fatalf("Combine of %d shares: %v, want ErrTooFew", len(sub), err)
					}
				})
			})
		}
	}
}

func TestBadArguments(t *testing.T) {
	for _, tc := range []struct{ k, n int }{{1, 3}, {0, 3}, {4, 3}, {2, 256}, {-1, 2}} {
		if _, err := Split(nil, TypeBytes, tc.k, tc.n); err == nil {
			t.Errorf("Split %d of %d: no error", tc.k, tc.n)
		}
	}
	if _, err := (&Splitter{Derived: true, MinLen: 32}).Split([]byte("pw"), TypeText, 2, 3); err == nil {
		t.Error("derived set with MinLen: no error")
	}
	if _, err := (&Splitter{Rand: bytes.NewReader(make([]byte, 31))}).Split(nil, TypeBytes, 2, 3); err == nil {
		t.Error("31 bytes of randomness: no error")
	}
	if _, err := (&Splitter{MinLen: 1<<38 + 1}).Split(nil, TypeBytes, 2, 3); err == nil {
		t.Error("sealed payload longer than one stream: no error")
	}
	if _, err := (&Splitter{MinLen: 1 << 38}).Split(nil, TypeBytes, 3, 3); err == nil {
		t.Error("MinLen of one stream rounded up past it: no error")
	}
	for _, minLen := range []int{-1, math.MinInt, math.MaxInt} {
		for _, derived := range []bool{false, true} {
			if _, err := (&Splitter{Derived: derived, MinLen: minLen}).Split([]byte("pw"), TypeText, 2, 3); err == nil {
				t.Errorf("MinLen %d, derived %v: no error", minLen, derived)
			}
		}
	}
}

// Step 6 of splitting catches a share that a fault made wrong, although
// it carries a valid check and the right id.
func TestVerify(t *testing.T) {
	payload := []byte("step six")
	const k, n = 3, 5
	take := random(keyLen * k)
	c := crypt(take[:keyLen], seal(TypeText, payload, sealedLen(len(payload), k, 0)))
	good := build(k, n, take, c)
	if err := verify(good, TypeText, payload, k); err != nil {
		t.Fatalf("clean set: %v", err)
	}
	for i := range n {
		for _, off := range []int{hdrLen + 5, hdrLen + keyLen + 1} {
			bad := slices.Clone(good)
			bad[i] = forge(bad[i], off)
			if err := verify(bad, TypeText, payload, k); err == nil {
				t.Errorf("fault at byte %d of share %d: no error", off, i+1)
			}
		}
	}

	// A fault in C before the id was computed passes the id, and the
	// comparison with the input catches it.
	c[4] ^= 1
	if err := verify(build(k, n, take, c), TypeText, payload, k); err == nil {
		t.Error("fault in C: no error")
	}
	if err := verify(good, TypeBytes, payload, k); err == nil {
		t.Error("wrong type: no error")
	}
	swapped := slices.Clone(good)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if err := verify(swapped, TypeText, payload, k); err == nil {
		t.Error("shares out of order: no error")
	}
}

func TestDamage(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("secret"), TypeText, 2, 3)

	flipped := bytes.Clone(shares[0])
	flipped[25] ^= 1
	if _, _, err := Combine([][]byte{flipped, shares[1]}); !errors.Is(err, ErrCheck) {
		t.Errorf("flipped bit: %v, want ErrCheck", err)
	}

	forged := forge(shares[0], 25)
	if _, _, err := Combine([][]byte{forged, shares[1]}); !errors.Is(err, ErrID) {
		t.Errorf("forged check: %v, want ErrID", err)
	}

	// With a spare share the forgery is outvoted and named.
	all := [][]byte{forged, shares[1], shares[2]}
	if _, got, err := Combine(all); err != nil || string(got) != "secret" {
		t.Errorf("Combine with spare = %q, %v", got, err)
	}
	if bad, err := Audit(all); err != nil || !reflect.DeepEqual(bad, []int{1}) {
		t.Errorf("Audit = %v, %v, want [1]", bad, err)
	}
	if bad, err := Audit(shares); err != nil || bad != nil {
		t.Errorf("Audit of a clean set = %v, %v", bad, err)
	}
}

// frame forges the key parts of the shares at positions a and b so that
// the key polynomial through the shares at sub keeps its value at 0. S
// stays and the R_i move, which an id over S alone would let through.
func frame(shares [][]byte, sub []int, a, b int) [][]byte {
	xs := make([]byte, len(sub))
	for i, j := range sub {
		xs[i] = shares[j][2]
	}
	w := weights(xs, 0)
	wa, wb := w[slices.Index(sub, a)], w[slices.Index(sub, b)]
	fa, fb := bytes.Clone(shares[a]), bytes.Clone(shares[b])
	for j := range keyLen {
		d := byte(j) | 0x80
		fa[hdrLen+j] ^= d
		fb[hdrLen+j] ^= mul(mul(wa, d), inv(wb))
	}
	out := slices.Clone(shares)
	out[a], out[b] = reseal(fa), reseal(fb)
	return out
}

func TestTwoForgerFrame(t *testing.T) {
	tests := []struct {
		k, n int
		sub  []int
		a, b int
	}{
		{2, 4, []int{2, 3}, 2, 3},
		{2, 4, []int{0, 1}, 0, 1},
		{3, 5, []int{2, 3, 4}, 3, 4},
		{3, 5, []int{0, 1, 2}, 0, 1},
		{5, 8, []int{1, 3, 5, 6, 7}, 5, 7},
	}
	payload := []byte("the payload of the frame test")
	for _, tc := range tests {
		shares, err := Split(payload, TypeText, tc.k, tc.n)
		if err != nil {
			t.Fatal(err)
		}
		forged := frame(shares, tc.sub, tc.a, tc.b)
		var honest, held [][]byte
		for _, i := range tc.sub {
			honest = append(honest, shares[i])
			held = append(held, forged[i])
		}
		if !bytes.Equal(keyAt0(held), keyAt0(honest)) {
			t.Fatalf("%d-of-%d: the frame moved S", tc.k, tc.n)
		}

		if _, _, err := Combine(held); !errors.Is(err, ErrID) {
			t.Errorf("%d-of-%d, forgers %d and %d: Combine of k shares: %v, want ErrID", tc.k, tc.n, tc.a+1, tc.b+1, err)
		}
		if _, got, err := Combine(forged); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("%d-of-%d: Combine with spares = %q, %v", tc.k, tc.n, got, err)
		}
		if bad, err := Audit(forged); err != nil || !reflect.DeepEqual(bad, []int{tc.a + 1, tc.b + 1}) {
			t.Errorf("%d-of-%d: Audit = %v, %v, want [%d %d]", tc.k, tc.n, bad, err, tc.a+1, tc.b+1)
		}
	}
}

// keyAt0 returns S as the key parts of the given shares give it.
func keyAt0(shares [][]byte) []byte {
	var xs []byte
	var ys [][]byte
	for _, sh := range shares {
		xs = append(xs, sh[2])
		ys = append(ys, sh[hdrLen:hdrLen+keyLen])
	}
	return interp(nil, xs, ys, 0)
}

func TestSets(t *testing.T) {
	a := mustSplit(t, new(Splitter), []byte("same"), TypeText, 2, 3)
	b := mustSplit(t, new(Splitter), []byte("same"), TypeText, 2, 3)
	if _, _, err := Combine([][]byte{a[0], b[1]}); !errors.Is(err, ErrSet) {
		t.Errorf("two sets: %v, want ErrSet", err)
	}
	if _, _, err := Combine(a[:1]); !errors.Is(err, ErrTooFew) {
		t.Errorf("one share: %v, want ErrTooFew", err)
	}
	if _, _, err := Combine([][]byte{a[0], a[0]}); !errors.Is(err, ErrTooFew) {
		t.Errorf("same share twice: %v, want ErrTooFew", err)
	}
	if _, p, err := Combine([][]byte{a[0], a[0], a[2]}); err != nil || string(p) != "same" {
		t.Errorf("a copy beside a full set: %q, %v", p, err)
	}
	if _, _, err := Combine(nil); !errors.Is(err, ErrTooFew) {
		t.Errorf("no shares: %v, want ErrTooFew", err)
	}

	// Step 1 comes before step 2: a damaged share is reported as damaged
	// even after shares of two sets.
	damaged := bytes.Clone(a[1])
	damaged[30] ^= 1
	for _, in := range [][][]byte{{a[0], b[1], damaged}, {a[0], damaged, b[1]}} {
		if _, _, err := Combine(in); !errors.Is(err, ErrCheck) {
			t.Errorf("Combine: %v, want ErrCheck", err)
		}
		if _, err := Audit(in); !errors.Is(err, ErrCheck) {
			t.Errorf("Audit: %v, want ErrCheck", err)
		}
		if _, err := ShareAt(in, 2); !errors.Is(err, ErrCheck) {
			t.Errorf("ShareAt: %v, want ErrCheck", err)
		}
	}
}

func TestTooFewError(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("too few"), TypeText, 3, 5)
	other := forge(shares[3], 40)
	_, _, err := Combine([][]byte{shares[3], shares[0], shares[0], other})
	var tooFew *TooFewError
	if !errors.As(err, &tooFew) || !errors.Is(err, ErrTooFew) {
		t.Fatalf("Combine: %v, want a TooFewError", err)
	}
	if tooFew.K != 3 || !reflect.DeepEqual(tooFew.Held, []int{1}) || !reflect.DeepEqual(tooFew.Disputed, []int{4}) {
		t.Errorf("TooFewError = %+v", tooFew)
	}
	if want := "shaqr: not enough shares: 1 of 3, not counting 1 disputed x"; err.Error() != want {
		t.Errorf("message %q, want %q", err, want)
	}
}

func TestDisputed(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("disputed"), TypeText, 2, 4)
	other := forge(shares[1], 40)

	if _, p, err := Combine([][]byte{shares[0], shares[1], other, shares[2]}); err != nil || string(p) != "disputed" {
		t.Errorf("Combine = %q, %v", p, err)
	}
	if _, _, err := Combine([][]byte{shares[0], shares[1], other}); !errors.Is(err, ErrTooFew) {
		t.Errorf("one other x left: %v, want ErrTooFew", err)
	}
	// The true share at x = 2 is among them, but Combine does not try
	// the disputed shares in turn.
	if _, _, err := Combine([][]byte{other, shares[1], shares[3]}); !errors.Is(err, ErrTooFew) {
		t.Errorf("disputed x with one other x: %v, want ErrTooFew", err)
	}
	if bad, err := Audit([][]byte{shares[1], other, shares[2], shares[3]}); err != nil || !reflect.DeepEqual(bad, []int{2}) {
		t.Errorf("Audit = %v, %v, want [2]", bad, err)
	}
}

func TestDerived(t *testing.T) {
	sp := Splitter{Derived: true}
	payload := []byte("high entropy payload")
	a := mustSplit(t, &sp, payload, TypeText, 2, 3)
	b := mustSplit(t, &sp, payload, TypeText, 2, 5)
	if !reflect.DeepEqual(a, b[:3]) {
		t.Error("a derived set at larger n does not extend the smaller one")
	}
	c := mustSplit(t, new(Splitter), payload, TypeText, 2, 3)
	if reflect.DeepEqual(a, c) {
		t.Error("session set equals derived set")
	}
	d := mustSplit(t, &sp, payload, TypeText, 3, 3)
	ha, _ := ParseHeader(a[0])
	hd, _ := ParseHeader(d[0])
	if ha.ID == hd.ID {
		t.Error("derived sets at another k share an id")
	}
}

func TestShareAt(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("replace a plate"), TypeText, 3, 5)
	held := [][]byte{shares[0], shares[2], shares[4]}
	got, err := ShareAt(held, 2)
	if err != nil || !bytes.Equal(got, shares[1]) {
		t.Fatalf("ShareAt 2 = %x, %v", got, err)
	}
	ninth, err := ShareAt(held, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, p, err := Combine([][]byte{ninth, shares[1], shares[3]}); err != nil || string(p) != "replace a plate" {
		t.Errorf("Combine with new share = %q, %v", p, err)
	}
	for _, x := range []int{0, 256} {
		if _, err := ShareAt(held, x); err == nil {
			t.Errorf("ShareAt %d: no error", x)
		}
	}
}

func TestMinLen(t *testing.T) {
	sp := Splitter{MinLen: 32}
	a := mustSplit(t, &sp, []byte("pw"), TypeText, 2, 3)
	b := mustSplit(t, &sp, []byte("a much longer password!"), TypeText, 2, 3)
	if len(a[0]) != len(b[0]) || len(a[0]) != minShare-1+16 {
		t.Errorf("share lengths %d and %d", len(a[0]), len(b[0]))
	}
	if _, p, err := Combine(a[1:]); err != nil || string(p) != "pw" {
		t.Errorf("Combine = %q, %v", p, err)
	}
	// L stays a multiple of k: 32 becomes 33 at k = 3.
	c := mustSplit(t, &sp, []byte("pw"), TypeText, 3, 3)
	if len(c[0]) != minShare-1+11 {
		t.Errorf("3-of-3 share of %d bytes", len(c[0]))
	}
}

func TestUnseal(t *testing.T) {
	for _, tc := range []struct {
		sealed string
		ok     bool
	}{
		{"55616280", true}, {"4280", true}, {"5580000000", true}, {"558080", true},
		{"556162", false}, {"0000", false}, {"8000", false}, {"", false},
	} {
		_, _, err := unseal(unhex(t, tc.sealed))
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, ErrPadding) {
			t.Errorf("unseal %s: %v", tc.sealed, err)
		}
	}
}

func TestHeader(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("x"), TypeBytes, 3, 4)
	h, err := ParseHeader(shares[3])
	if err != nil || h.K != 3 || h.X != 4 || !bytes.Equal(h.ID[:], shares[0][3:hdrLen]) {
		t.Errorf("ParseHeader = %+v, %v", h, err)
	}
	if want := fmt.Sprintf("#%X", h.ID[:2]); h.Tag() != want {
		t.Errorf("Tag = %s, want %s", h.Tag(), want)
	}

	set := func(i int, b byte) []byte {
		c := bytes.Clone(shares[0])
		c[i] = b
		return reseal(c)
	}
	for _, tc := range []struct {
		name  string
		share []byte
		want  error
	}{
		{"no bytes", nil, ErrCheck},
		{"three bytes", []byte{1, 2, 3}, ErrCheck},
		{"check alone", check(nil), ErrShare},
		{"flipped bit", func() []byte { c := bytes.Clone(shares[0]); c[40] ^= 1; return c }(), ErrCheck},
		{"version 2", set(0, 2), ErrVersion},
		{"version 0", set(0, 0), ErrVersion},
		{"k = 1", set(1, 1), ErrShare},
		{"x = 0", set(2, 0), ErrShare},
		{"55 bytes", checked(shares[0][:hdrLen+keyLen]), ErrShare},
		{"short and of another version", checked([]byte{7, 2, 1}), ErrVersion},
	} {
		if _, err := ParseHeader(tc.share); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestGroup(t *testing.T) {
	a := mustSplit(t, new(Splitter), []byte("set a"), TypeText, 2, 3)
	b := mustSplit(t, new(Splitter), []byte("set b"), TypeText, 2, 3)
	damaged := bytes.Clone(b[2])
	damaged[30] ^= 1
	other := forge(a[1], 40)

	in := [][]byte{a[0], b[1], damaged, a[2], []byte("junk"), a[1], other}
	sets, rejected := Group(in)
	if len(sets) != 2 || len(sets[0]) != 4 || len(sets[1]) != 1 {
		t.Fatalf("Group = %d sets", len(sets))
	}
	var got []string
	for _, r := range rejected {
		got = append(got, fmt.Sprintf("%d %s", r.Index, reason(r.Err)))
	}
	want := []string{"2 check", "4 check", "5 disputed", "6 disputed"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rejected = %v, want %v", got, want)
	}
	if _, p, err := Combine(sets[0]); err != nil || string(p) != "set a" {
		t.Errorf("Combine = %q, %v", p, err)
	}
	if _, _, err := Combine(sets[1]); !errors.Is(err, ErrTooFew) {
		t.Errorf("stray share alone: %v, want ErrTooFew", err)
	}

	// Derived sets of one payload and one k are the same set.
	sp := Splitter{Derived: true}
	c := mustSplit(t, &sp, []byte("same payload"), TypeText, 2, 3)
	d := mustSplit(t, &sp, []byte("same payload"), TypeText, 2, 3)
	e := mustSplit(t, &sp, []byte("same payload"), TypeText, 3, 3)
	if sets, _ := Group([][]byte{c[0], d[1], e[2]}); len(sets) != 2 || len(sets[0]) != 2 {
		t.Errorf("derived sets grouped into %d", len(sets))
	}
}

func TestDecode(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("typed by hand"), TypeText, 2, 2)
	a, b := Encode(shares[0]), Encode(shares[1])
	text := "#1\n  " + strings.ToLower(a[:30]) + "\n\t" + a[30:] + " #1\n\nSHAQR:AAA\n" + b + "\r\n"
	got, rejected := Decode(text)
	if len(got) != 2 || !bytes.Equal(got[0], shares[0]) || !bytes.Equal(got[1], shares[1]) {
		t.Errorf("Decode = %x", got)
	}
	if len(rejected) != 1 || !errors.Is(rejected[0], ErrText) || !strings.Contains(rejected[0].Error(), "the share on line 5: 3 characters, a length") {
		t.Errorf("rejected = %v", rejected)
	}
	if _, rejected := Decode(a[:49] + "1" + a[49:]); len(rejected) != 1 || !strings.Contains(rejected[0].Error(), `43 characters up to '1' on line 1`) {
		t.Errorf("share cut by a 1: %v", rejected)
	}
	if got, rejected := Decode("no shares here"); got != nil || rejected != nil {
		t.Errorf("Decode of plain text = %x, %v", got, rejected)
	}

	// White space outside ASCII is deleted inside a share, and characters
	// outside ASCII before a share do not move its line.
	text = "Ünïcödé\u3000lines\n" + a[:20] + "\u00a0\n\u3000" + a[20:40] + "\u2028" + a[40:] + "\u205f\n" +
		"\u00a0\u00a0" + b[:31] + "\u200b" + b[31:] + "\n"
	got, rejected = Decode(text)
	if len(got) != 1 || !bytes.Equal(got[0], shares[0]) {
		t.Errorf("Decode with Unicode white space = %x", got)
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0].Error(), "the share on line 4: 25 characters up to '\\u200b' on line 4") {
		t.Errorf("rejected = %v", rejected)
	}
}

func TestScan(t *testing.T) {
	shares := mustSplit(t, new(Splitter), []byte("typed by hand"), TypeText, 2, 2)
	a, b := Encode(shares[0]), Encode(shares[1])
	text := "# plate 1, café\n" + strings.ToLower(a[:40]) + "\n" + a[40:62] + "8" + a[62:] + "\n" +
		"# plate 2\n" + b[:30] + "\n\u3000" + b[30:] + "\n" +
		"SHAQR:AAA\n"
	found := Scan(text)
	want := []struct {
		line, end int
		stop      rune
		ok        bool
	}{
		{2, 3, '8', true},
		{5, 7, 0, true},
		{7, 8, 0, false},
	}
	if len(found) != len(want) {
		t.Fatalf("Scan found %d shares, want %d", len(found), len(want))
	}
	for i, w := range want {
		f := found[i]
		if f.Line != w.line || f.EndLine != w.end || f.Stop != w.stop || (f.Err == nil) != w.ok {
			t.Errorf("share %d: line %d to %d, stop %q, %v; want line %d to %d, stop %q", i+1, f.Line, f.EndLine, f.Stop, f.Err, w.line, w.end, w.stop)
		}
	}
	if !errors.Is(found[2].Err, ErrText) || found[2].Share != nil {
		t.Errorf("share 3: %x, %v", found[2].Share, found[2].Err)
	}
	if found[0].Share == nil || found[0].Err != nil {
		t.Errorf("share 1 cut by an 8 does not decode: %v", found[0].Err)
	}
	if !bytes.Equal(found[1].Share, shares[1]) {
		t.Errorf("share 2 = %x", found[1].Share)
	}
}

// A lower case letter or any character outside this set would push a QR
// encoder out of alphanumeric mode.
func TestQRAlphanumeric(t *testing.T) {
	const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	shares := mustSplit(t, new(Splitter), random(200), TypeBytes, 2, 3)
	for _, sh := range shares {
		s := Encode(sh)
		if i := strings.IndexFunc(s, func(r rune) bool { return !strings.ContainsRune(alnum, r) }); i >= 0 {
			t.Fatalf("%q in %s", s[i], s)
		}
	}
}

// The Sizes table of SPEC.md.
func TestSizes(t *testing.T) {
	for _, tc := range []struct{ payload, k, n, share, text int }{
		{20, 2, 3, 66, 112},
		{32, 2, 3, 72, 122},
		{32, 3, 5, 67, 114},
		{457, 2, 3, 285, 462},
		{743, 3, 5, 304, 493},
		{2889, 10, 20, 345, 558},
	} {
		shares, err := Split(random(tc.payload), TypeDescriptor, tc.k, tc.n)
		if err != nil {
			t.Fatal(err)
		}
		if len(shares[0]) != tc.share || len(Encode(shares[0])) != tc.text {
			t.Errorf("%d bytes %d-of-%d: share %d bytes, text %d, want %d and %d",
				tc.payload, tc.k, tc.n, len(shares[0]), len(Encode(shares[0])), tc.share, tc.text)
		}
	}
}

// The search for k shares that pass the id stops at maxWork, however
// large k and the shares are, and still finds a run that avoids one
// forged share when the run comes early.
func TestSearchBound(t *testing.T) {
	const k, n = 254, 255
	shares := mustSplit(t, &Splitter{Derived: true}, bytes.Repeat([]byte("bound"), 60*k), TypeBytes, k, n)
	wrong := make([][]byte, n)
	for i, sh := range shares {
		wrong[i] = forge(sh, 3) // every share claims the same other id
	}
	_, _, err := Combine(wrong)
	if !errors.Is(err, ErrID) || !strings.Contains(err.Error(), "the search stopped after") {
		t.Errorf("Combine with no k shares that fit: %v, want ErrID that says the search stopped", err)
	}
	held := slices.Clone(shares)
	held[0] = forge(held[0], hdrLen+keyLen+7)
	if _, _, err := Combine(held); err != nil {
		t.Errorf("Combine with share 1 forged: %v", err)
	}
}

// One forged share among many must not block a large quorum, wherever
// its index falls. Lexicographic search alone would need tens of
// thousands of tries here.
func TestLargeQuorumWithForgery(t *testing.T) {
	payload := random(2880)
	shares := mustSplit(t, new(Splitter), payload, TypeBytes, 10, 20)
	for _, pos := range []int{0, 4, 9, 19} {
		held := slices.Clone(shares)
		held[pos] = forge(held[pos], hdrLen+keyLen+7)

		_, got, err := Combine(held)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("forged share %d: Combine: %v", pos+1, err)
		}
		if bad, _ := Audit(held); !reflect.DeepEqual(bad, []int{pos + 1}) {
			t.Errorf("forged share %d: Audit = %v", pos+1, bad)
		}
	}
}
