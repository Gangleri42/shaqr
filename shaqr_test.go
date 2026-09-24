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
		{"id", hex.EncodeToString(setID(formatSealed, 2, take, c)), "b96219ec42ff7a50495969396067235c"},
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

// kinds are the three kinds of set, by name.
var kinds = map[string]Splitter{
	"session": {},
	"derived": {Derived: true},
	"open":    {Open: true},
}

func TestRoundTrip(t *testing.T) {
	tests := []struct{ k, n, size int }{
		{2, 3, 0}, {2, 3, 1}, {2, 3, 20}, {3, 5, 450}, {5, 9, 33}, {2, 2, 7}, {7, 7, 100}, {4, 10, 3}, {2, 255, 5},
		{6, 8, 61}, {8, 11, 0}, {9, 9, 17}, {10, 13, 300}, {10, 255, 1000},
	}
	for _, tc := range tests {
		for name, sp := range kinds {
			t.Run(fmt.Sprintf("%d-of-%d/%d/%s", tc.k, tc.n, tc.size, name), func(t *testing.T) {
				payload := random(tc.size)
				shares, err := sp.Split(payload, TypeBytes, tc.k, tc.n)
				if err != nil {
					t.Fatal(err)
				}
				want := minShare(formatSealed) - 1 + (tc.size+2+tc.k-1)/tc.k
				if sp.Open {
					want -= keyLen
				}
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
	for _, sp := range []Splitter{{Derived: true, MinLen: 32}, {Open: true, MinLen: 32}, {Open: true, Derived: true}} {
		if _, err := sp.Split([]byte("pw"), TypeText, 2, 3); err == nil {
			t.Errorf("%+v: no error", sp)
		}
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
		for name, sp := range kinds {
			sp.MinLen = minLen
			if _, err := sp.Split([]byte("pw"), TypeText, 2, 3); err == nil {
				t.Errorf("MinLen %d, %s set: no error", minLen, name)
			}
		}
	}
}

// failing is a source of randomness that fails.
type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

// Derived and open sets read nothing from Rand.
func TestRandUnread(t *testing.T) {
	for _, sp := range []Splitter{{Derived: true, Rand: failing{}}, {Open: true, Rand: failing{}}} {
		mustSplit(t, &sp, []byte("no r"), TypeText, 2, 3)
	}
	if _, err := (&Splitter{Rand: failing{}}).Split([]byte("r"), TypeText, 2, 3); err == nil {
		t.Error("session set with failing Rand: no error")
	}
}

// Step 6 of splitting catches a share that a fault made wrong, although
// it carries a valid check and the right id, in a sealed set and in an
// open one, whose take is empty.
func TestVerify(t *testing.T) {
	payload := []byte("step six")
	const k, n = 3, 5
	sealed := seal(TypeText, payload, sealedLen(len(payload), k, 0))
	sealedTake := random(keyLen * k)
	for _, tc := range []struct {
		name     string
		take, c  []byte
		faultsAt []int
	}{
		{"sealed", sealedTake, crypt(sealedTake[:keyLen], sealed), []int{hdrLen + 5, hdrLen + keyLen + 1}},
		{"open", nil, bytes.Clone(sealed), []int{hdrLen, hdrLen + 2}},
	} {
		good := build(k, n, tc.take, tc.c)
		if err := verify(good, TypeText, payload, k); err != nil {
			t.Fatalf("clean %s set: %v", tc.name, err)
		}
		for i := range n {
			for _, off := range tc.faultsAt {
				bad := slices.Clone(good)
				bad[i] = forge(bad[i], off)
				if err := verify(bad, TypeText, payload, k); err == nil {
					t.Errorf("%s set, fault at byte %d of share %d: no error", tc.name, off, i+1)
				}
			}
		}

		// A fault in C before the id was computed passes the id, and the
		// comparison with the input catches it.
		tc.c[4] ^= 1
		if err := verify(build(k, n, tc.take, tc.c), TypeText, payload, k); err == nil {
			t.Errorf("%s set, fault in C: no error", tc.name)
		}
		if err := verify(good, TypeBytes, payload, k); err == nil {
			t.Errorf("%s set, wrong type: no error", tc.name)
		}
		swapped := slices.Clone(good)
		swapped[0], swapped[1] = swapped[1], swapped[0]
		if err := verify(swapped, TypeText, payload, k); err == nil {
			t.Errorf("%s set, shares out of order: no error", tc.name)
		}
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

// An open set is a function of the content type, the payload and k, and
// its first k shares hold the slices of sealed in the clear.
func TestOpen(t *testing.T) {
	sp := Splitter{Open: true}
	payload := []byte("must survive lost plates and need not stay private")
	a := mustSplit(t, &sp, payload, TypeText, 3, 5)
	if b := mustSplit(t, &sp, payload, TypeText, 3, 5); !reflect.DeepEqual(a, b) {
		t.Error("two open sets of one payload differ")
	}
	if b := mustSplit(t, &sp, payload, TypeText, 3, 7); !reflect.DeepEqual(a, b[:5]) {
		t.Error("an open set at larger n does not extend the smaller one")
	}
	h, _ := ParseHeader(a[0])
	for _, tc := range []struct {
		name  string
		share []byte
	}{
		{"another k", mustSplit(t, &sp, payload, TypeText, 2, 5)[0]},
		{"another type", mustSplit(t, &sp, payload, TypeBytes, 3, 5)[0]},
		{"a derived set", mustSplit(t, &Splitter{Derived: true}, payload, TypeText, 3, 5)[0]},
	} {
		if other, _ := ParseHeader(tc.share); other.ID == h.ID {
			t.Errorf("%s has the id of the open set", tc.name)
		}
	}

	sealed := seal(TypeText, payload, sealedLen(len(payload), 3, 0))
	b := len(sealed) / 3
	for i, sh := range a[:3] {
		if !bytes.Equal(sh[hdrLen:len(sh)-checkLen], sealed[b*i:b*(i+1)]) {
			t.Errorf("share %d does not hold slice %d of sealed", i+1, i+1)
		}
	}
}

// Open and sealed shares never form one set: the format is part of the
// group and of the id.
func TestOpenApart(t *testing.T) {
	relabel := func(sh []byte, format byte) []byte {
		c := bytes.Clone(sh)
		c[0] = format
		return reseal(c)
	}
	payload := []byte("one payload in two formats")
	sealed := mustSplit(t, &Splitter{Derived: true}, payload, TypeText, 2, 3)
	open := mustSplit(t, &Splitter{Open: true}, payload, TypeText, 2, 3)
	sets, rejected := Group([][]byte{sealed[0], open[1], sealed[2], open[0]})
	if len(sets) != 2 || len(sets[0]) != 2 || len(sets[1]) != 2 || rejected != nil {
		t.Errorf("Group = %d sets, %v", len(sets), rejected)
	}
	if _, _, err := Combine([][]byte{sealed[0], open[1]}); !errors.Is(err, ErrSet) {
		t.Errorf("a sealed and an open share: %v, want ErrSet", err)
	}

	// A sealed share relabelled open, with a check that matches, lands in
	// a set of its own, and k of them fail the id.
	flipped := [][]byte{relabel(sealed[0], formatOpen), relabel(sealed[1], formatOpen), relabel(sealed[2], formatOpen)}
	if sets, _ := Group([][]byte{flipped[0], sealed[1], sealed[2]}); len(sets) != 2 || len(sets[0]) != 1 {
		t.Errorf("a relabelled share grouped into %d sets", len(sets))
	}
	if _, p, err := Combine([][]byte{sealed[1], sealed[2]}); err != nil || !bytes.Equal(p, payload) {
		t.Errorf("Combine of the sealed shares = %q, %v", p, err)
	}
	if _, _, err := Combine(flipped); !errors.Is(err, ErrID) {
		t.Errorf("sealed shares relabelled open: %v, want ErrID", err)
	}

	// An open share relabelled sealed is too short to be sealed, or fails
	// the id.
	if _, err := ParseHeader(relabel(open[0], formatSealed)); !errors.Is(err, ErrShare) {
		t.Errorf("a short open share relabelled sealed: %v, want ErrShare", err)
	}
	long := mustSplit(t, &Splitter{Open: true}, random(100), TypeBytes, 2, 2)
	if _, _, err := Combine([][]byte{relabel(long[0], formatSealed), relabel(long[1], formatSealed)}); !errors.Is(err, ErrID) {
		t.Errorf("open shares relabelled sealed: %v, want ErrID", err)
	}
}

// A forged share in an open set is outvoted by spares and named, as in a
// sealed one.
func TestOpenDamage(t *testing.T) {
	payload := random(90)
	shares := mustSplit(t, &Splitter{Open: true}, payload, TypeBytes, 3, 5)
	for i := range shares {
		held := slices.Clone(shares)
		held[i] = forge(held[i], hdrLen+2)
		if _, got, err := Combine(held); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("share %d forged: Combine = %x, %v", i+1, got, err)
		}
		if bad, err := Audit(held); err != nil || !reflect.DeepEqual(bad, []int{i + 1}) {
			t.Errorf("share %d forged: Audit = %v, %v", i+1, bad, err)
		}
		k := [][]byte{held[i], held[(i+1)%5], held[(i+2)%5]}
		if _, _, err := Combine(k); !errors.Is(err, ErrID) {
			t.Errorf("share %d forged, no spare: %v, want ErrID", i+1, err)
		}
	}
}

func TestShareAt(t *testing.T) {
	for name, sp := range kinds {
		shares := mustSplit(t, &sp, []byte("replace a plate"), TypeText, 3, 5)
		held := [][]byte{shares[0], shares[2], shares[4]}
		got, err := ShareAt(held, 2)
		if err != nil || !bytes.Equal(got, shares[1]) {
			t.Fatalf("%s set: ShareAt 2 = %x, %v", name, got, err)
		}
		ninth, err := ShareAt(held, 9)
		if err != nil {
			t.Fatal(err)
		}
		if _, p, err := Combine([][]byte{ninth, shares[1], shares[3]}); err != nil || string(p) != "replace a plate" {
			t.Errorf("%s set: Combine with new share = %q, %v", name, p, err)
		}
		for _, x := range []int{0, 256} {
			if _, err := ShareAt(held, x); err == nil {
				t.Errorf("%s set: ShareAt %d: no error", name, x)
			}
		}
	}
}

func TestMinLen(t *testing.T) {
	sp := Splitter{MinLen: 32}
	a := mustSplit(t, &sp, []byte("pw"), TypeText, 2, 3)
	b := mustSplit(t, &sp, []byte("a much longer password!"), TypeText, 2, 3)
	if len(a[0]) != len(b[0]) || len(a[0]) != minShare(formatSealed)-1+16 {
		t.Errorf("share lengths %d and %d", len(a[0]), len(b[0]))
	}
	if _, p, err := Combine(a[1:]); err != nil || string(p) != "pw" {
		t.Errorf("Combine = %q, %v", p, err)
	}
	// L stays a multiple of k: 32 becomes 33 at k = 3.
	c := mustSplit(t, &sp, []byte("pw"), TypeText, 3, 3)
	if len(c[0]) != minShare(formatSealed)-1+11 {
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
	if err != nil || h.Open || h.K != 3 || h.X != 4 || !bytes.Equal(h.ID[:], shares[0][3:hdrLen]) {
		t.Errorf("ParseHeader = %+v, %v", h, err)
	}
	open := mustSplit(t, &Splitter{Open: true}, []byte("x"), TypeBytes, 3, 4)
	if h, err := ParseHeader(open[1]); err != nil || !h.Open || h.K != 3 || h.X != 2 {
		t.Errorf("ParseHeader of an open share = %+v, %v", h, err)
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
		{"format 3", set(0, 3), ErrVersion},
		{"format 0", set(0, 0), ErrVersion},
		{"k = 1", set(1, 1), ErrShare},
		{"x = 0", set(2, 0), ErrShare},
		{"sealed, 55 bytes", checked(shares[0][:hdrLen+keyLen]), ErrShare},
		{"open, 23 bytes", checked(open[0][:hdrLen]), ErrShare},
		{"open, 23 bytes, k = 1", checked(append([]byte{formatOpen, 1}, open[0][2:hdrLen]...)), ErrShare},
		{"a sealed share of 24 bytes", checked(append([]byte{formatSealed}, open[0][1:hdrLen+1]...)), ErrShare},
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

	// Derived sets of one payload and one k are the same set, and so are
	// open sets.
	for _, sp := range []Splitter{{Derived: true}, {Open: true}} {
		c := mustSplit(t, &sp, []byte("same payload"), TypeText, 2, 3)
		d := mustSplit(t, &sp, []byte("same payload"), TypeText, 2, 3)
		e := mustSplit(t, &sp, []byte("same payload"), TypeText, 3, 3)
		if sets, _ := Group([][]byte{c[0], d[1], e[2]}); len(sets) != 2 || len(sets[0]) != 2 {
			t.Errorf("%+v: sets grouped into %d", sp, len(sets))
		}
	}

	// An open share below 24 bytes is dropped, and the others go on.
	open := mustSplit(t, &Splitter{Open: true}, []byte("open"), TypeText, 2, 3)
	sets, rejected = Group([][]byte{open[0], checked(open[1][:hdrLen]), open[2]})
	if len(sets) != 1 || len(rejected) != 1 || rejected[0].Index != 1 || !errors.Is(rejected[0].Err, ErrShare) {
		t.Errorf("Group = %d sets, %v", len(sets), rejected)
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

// The Sizes table of SPEC.md: share bytes and text characters of a
// sealed and of an open set.
func TestSizes(t *testing.T) {
	for _, tc := range []struct{ payload, k, n, share, text, openShare, openText int }{
		{20, 2, 3, 66, 112, 34, 61},
		{32, 2, 3, 72, 122, 40, 70},
		{32, 3, 5, 67, 114, 35, 62},
		{457, 2, 3, 285, 462, 253, 411},
		{743, 3, 5, 304, 493, 272, 442},
		{2889, 10, 20, 345, 558, 313, 507},
	} {
		payload := random(tc.payload)
		sealed := mustSplit(t, new(Splitter), payload, TypeDescriptor, tc.k, tc.n)
		open := mustSplit(t, &Splitter{Open: true}, payload, TypeDescriptor, tc.k, tc.n)
		for _, got := range []struct {
			name        string
			share       []byte
			bytes, text int
		}{
			{"sealed", sealed[0], tc.share, tc.text},
			{"open", open[0], tc.openShare, tc.openText},
		} {
			if len(got.share) != got.bytes || len(Encode(got.share)) != got.text {
				t.Errorf("%d bytes %d-of-%d, %s: share %d bytes, text %d, want %d and %d",
					tc.payload, tc.k, tc.n, got.name, len(got.share), len(Encode(got.share)), got.bytes, got.text)
			}
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
	for _, sp := range []Splitter{{}, {Open: true}} {
		shares := mustSplit(t, &sp, payload, TypeBytes, 10, 20)
		for _, pos := range []int{0, 4, 9, 19} {
			held := slices.Clone(shares)
			held[pos] = forge(held[pos], hdrLen+keyLen+7)

			_, got, err := Combine(held)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("%+v, forged share %d: Combine: %v", sp, pos+1, err)
			}
			if bad, _ := Audit(held); !reflect.DeepEqual(bad, []int{pos + 1}) {
				t.Errorf("%+v, forged share %d: Audit = %v", sp, pos+1, bad)
			}
		}
	}
}

// TestNoDefaultRand stands in for a bare-metal build, where defaultRand is
// nil: a session set then needs Splitter.Rand, while derived and open sets
// never read it.
func TestNoDefaultRand(t *testing.T) {
	saved := defaultRand
	defaultRand = nil
	defer func() { defaultRand = saved }()
	if _, err := Split([]byte("secret"), TypeText, 2, 3); err == nil {
		t.Fatal("a session set with no random source split")
	}
	for _, s := range []Splitter{{Derived: true}, {Open: true}} {
		if _, err := s.Split([]byte("secret"), TypeText, 2, 3); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
	}
}
