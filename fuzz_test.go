// SPDX-License-Identifier: CC0-1.0

package shaqr

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func FuzzSplitCombine(f *testing.F) {
	f.Add([]byte("JBSWY3DPEHPK3PXP"), byte(2), byte(3), false, false, 0)
	f.Add([]byte{}, byte(2), byte(2), true, false, 0)
	f.Add([]byte("pw"), byte(3), byte(5), false, false, 40)
	f.Add([]byte{}, byte(2), byte(3), false, true, 0)
	f.Add([]byte("an open note"), byte(4), byte(9), false, true, 0)
	f.Fuzz(func(t *testing.T, payload []byte, k, n byte, derived, open bool, minLen int) {
		sp := Splitter{Derived: derived, MinLen: minLen & 1023}
		if open {
			sp = Splitter{Open: true}
		}
		shares, err := sp.Split(payload, TypeBytes, int(k), int(n))
		if err != nil {
			return
		}
		if sp.Derived || sp.Open {
			again, err := sp.Split(payload, TypeBytes, int(k), int(n))
			if err != nil || !slices.EqualFunc(again, shares, bytes.Equal) {
				t.Fatalf("a second split of the same input differs: %v", err)
			}
		}
		// The first k shares, typed back in lower case with labels.
		var text strings.Builder
		for _, sh := range shares[:k] {
			text.WriteString("#label\n" + strings.ToLower(Encode(sh)) + "\n")
		}
		raws, rejected := Decode(text.String())
		if rejected != nil {
			t.Fatal(rejected)
		}
		_, got, err := Combine(raws)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("Combine = %x, %v, want %x", got, err, payload)
		}
	})
}

func FuzzDecode(f *testing.F) {
	shares := mustSplit(f, &Splitter{Derived: true}, []byte("seed corpus"), TypeText, 2, 3)
	open := mustSplit(f, &Splitter{Open: true}, []byte("seed corpus"), TypeText, 2, 3)
	f.Add(Encode(shares[0]) + "\n" + Encode(shares[1]))
	f.Add(Encode(open[2]) + "\n" + Encode(shares[1]) + "\n" + Encode(open[0]))
	f.Add("#1\n" + strings.ToLower(Encode(shares[2])) + " #1\n" + Encode(shares[0])[:40] + "\n\t" + Encode(shares[0])[40:])
	f.Add("SHAQR:")
	f.Add("shaqr:A shaqr:AAA=SHAQR:AA1B")
	f.Fuzz(func(t *testing.T, text string) {
		raws, _ := Decode(text)
		for _, raw := range raws {
			back, rejected := Decode(Encode(raw))
			if rejected != nil || len(back) != 1 || !bytes.Equal(back[0], raw) {
				t.Fatalf("share %x does not survive its text form: %x, %v", raw, back, rejected)
			}
		}
		sets, _ := Group(raws)
		for _, set := range sets {
			Combine(set)
			Audit(set)
			ShareAt(set, 7)
		}
		Combine(raws)
	})
}

func FuzzCombine(f *testing.F) {
	shares := mustSplit(f, &Splitter{Derived: true}, []byte("seed corpus"), TypeText, 2, 3)
	open := mustSplit(f, &Splitter{Open: true}, []byte("seed corpus"), TypeText, 2, 3)
	f.Add(shares[0], shares[1], shares[2])
	f.Add(shares[0], forge(shares[1], 30), shares[2])
	f.Add(open[0], open[1], open[2])
	f.Add(open[0], forge(open[1], hdrLen+1), open[2])
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		// Recompute the checks so that the fuzzer gets past them.
		var raws [][]byte
		for _, sh := range [][]byte{a, b, c} {
			if len(sh) > checkLen {
				raws = append(raws, reseal(sh))
			}
		}
		sets, _ := Group(raws)
		for _, set := range sets {
			Audit(set)
			ShareAt(set, 9)
		}
		// Once the id passes, and Combine fails at most on the padding,
		// Audit names exactly the x values at which a held share differs
		// from the share that ShareAt makes there.
		if _, _, err := Combine(raws); err != nil && !errors.Is(err, ErrPadding) {
			return
		}
		bad, err := Audit(raws)
		if err != nil {
			t.Fatalf("the id passes, Audit: %v", err)
		}
		off := make(map[int]bool)
		for _, sh := range raws {
			x := int(sh[2])
			want, err := ShareAt(raws, x)
			if err != nil {
				t.Fatalf("the id passes, ShareAt %d: %v", x, err)
			}
			if !bytes.Equal(sh, want) {
				off[x] = true
			}
		}
		var offXs []int
		for x := range off {
			offXs = append(offXs, x)
		}
		slices.Sort(offXs)
		if !slices.Equal(bad, offXs) {
			t.Fatalf("Audit = %v, the shares off the set are at %v", bad, offXs)
		}
	})
}
