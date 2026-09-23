// SPDX-License-Identifier: CC0-1.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Gangleri42/shaqr"
	"github.com/Gangleri42/shaqr/descriptor"
)

// export is the descriptor of testdata/vectors.json as an exporter might
// write it: another key order, ' for hardened steps, an upper-case
// fingerprint, three spellings of the children and no checksum.
const export = "wsh(sortedmulti(2," +
	"[b8688df1/48'/0'/0'/2']xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/0/*," +
	"[28645006/48h/0h/0h/2h]xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6," +
	"[73C5DA0A/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*))"

// vector returns the descriptor set of testdata/vectors.json in the
// format given, "sealed" or "open": the canonical descriptor that its
// packed payload holds, the tag of the set and the text of its shares 1
// to 3.
func vector(t *testing.T, format string) (desc, tag string, plates []string) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Valid []struct {
			Type    string   `json:"type"`
			Format  string   `json:"format"`
			Payload string   `json:"payload_hex"`
			Tag     string   `json:"tag"`
			Shares  []string `json:"shares"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Valid {
		if c.Type == "D" && c.Format == format {
			payload, err := hex.DecodeString(c.Payload)
			if err != nil {
				t.Fatal(err)
			}
			desc, err := descriptor.Unpack(payload)
			if err != nil {
				t.Fatal(err)
			}
			return desc, c.Tag, c.Shares
		}
	}
	t.Fatalf("no %s descriptor set in the vectors", format)
	return "", "", nil
}

// descbackup runs a command line on input and returns what it prints and
// what it reports.
func descbackup(input string, args ...string) (out, reports string, err error) {
	var stdout, stderr strings.Builder
	err = run(args, strings.NewReader(input), &stdout, log.New(&stderr, "", 0))
	return stdout.String(), stderr.String(), err
}

// reseal replaces the check of a share given as text, so that a forged
// share passes step 1 of recovering.
func reseal(t *testing.T, text string, flip int) string {
	t.Helper()
	raws, _ := shaqr.Decode(text)
	sh := raws[0]
	sh[flip] ^= 1
	n := len(sh) - 4
	sum := sha256.Sum256(append([]byte("shaQR v1 check"), sh[:n]...))
	copy(sh[n:], sum[:4])
	return shaqr.Encode(sh)
}

// wrap breaks every share in text into lines of 20 characters and
// leaves the labels whole, as a plate engraved in text alone holds them.
func wrap(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		for len(line) > 20 && !strings.HasPrefix(line, "#") {
			b.WriteString(line[:20] + "\n")
			line = line[20:]
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

const (
	key  = "[d34db33f/48h/0h/0h/2h]xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
	bare = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
)

// Split cuts the sets of testdata/vectors.json from the export, sealed
// by default and open with -open, with share sizes as DESCRIPTOR.md
// Sizes gives them, and recover prints the canonical descriptor from any
// two of their plates.
func TestSplitRecover(t *testing.T) {
	for _, c := range []struct {
		format string
		flags  []string
		size   int
	}{
		{"sealed", nil, 182},
		{"open", []string{"-open"}, 150},
	} {
		desc, tag, plates := vector(t, c.format)
		out, reports, err := descbackup("", append(append([]string{"split"}, c.flags...), export)...)
		if err != nil {
			t.Fatalf("split %q: %v", c.flags, err)
		}
		set := fmt.Sprintf("set %s (2-of-3, %s)", tag, c.format)
		want := fmt.Sprintf("# %s, %d bytes per share\n", set, c.size) +
			"# share 1 of " + set + ", key [28645006]\n" + plates[0] + "\n" +
			"# share 2 of " + set + ", key [73c5da0a]\n" + plates[1] + "\n" +
			"# share 3 of " + set + ", key [b8688df1]\n" + plates[2] + "\n"
		if out != want {
			t.Errorf("split %q printed\n%s\nwant\n%s", c.flags, out, want)
		}
		// The export has no checksum, so split asks the user to compare.
		if !strings.HasPrefix(reports, "warning: the descriptor has no checksum") || !strings.HasSuffix(reports, "\n"+desc+"\n") {
			t.Errorf("split %q reports %q", c.flags, reports)
		}
		again, reports, _ := descbackup("", append(append([]string{"split"}, c.flags...), "-k", "2", "-n", "3", desc)...)
		if again != out || reports != "" {
			t.Errorf("split %q of the canonical form with -k and -n printed\n%s\nand reported %q", c.flags, again, reports)
		}

		for _, input := range []string{
			out,
			plates[0] + "\n" + plates[1],
			plates[2] + "\n" + plates[0],
			plates[1] + " " + plates[2] + " " + plates[1],
		} {
			got, reports, err := descbackup(input, "recover")
			if err != nil || reports != "" || got != desc+"\n" {
				t.Errorf("recover of the %s set = %q, %q, %v", c.format, got, reports, err)
			}
		}
	}
}

// Split -open refuses a descriptor that holds a private key, since every
// plate of an open set shows part of it. A sealed set takes it.
func TestSplitOpenPrivate(t *testing.T) {
	const (
		xprv = "[aabbccdd/84h/0h/0h]xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
		wif  = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
		// The same key, compressed.
		wifC = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
	)
	for _, args := range [][]string{
		{"wsh(sortedmulti(2," + xprv + "/<0;1>/*," + bare + "))"},
		{"-k", "2", "-n", "2", "tr(" + bare + ",multi_a(2," + wif + "," + bare + "/7/*))"},
		{"-k", "2", "-n", "2", "tr(" + bare + ",pk(musig(" + wifC + "," + bare + ")))"},
	} {
		if _, _, err := descbackup("", append([]string{"split"}, args...)...); err != nil {
			t.Errorf("split %.60q: %v", args, err)
		}
		_, _, err := descbackup("", append([]string{"split", "-open"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "holds a private key") {
			t.Errorf("split -open %.60q: %v", args, err)
		}
	}
}

// Split reads the descriptor from standard input when no argument, or
// "-", gives it, and explains itself with -h.
func TestSplitInput(t *testing.T) {
	_, _, plates := vector(t, "sealed")
	want, _, _ := descbackup("", "split", export)
	for _, args := range [][]string{{"split"}, {"split", "-"}, {"split", "-k", "2", "-n", "3", "-"}} {
		out, _, err := descbackup(" "+export+"\n", args...)
		if err != nil || out != want {
			t.Errorf("%q with the descriptor on standard input: %v\n%s", args, err, out)
		}
	}
	if !strings.Contains(want, plates[0]) {
		t.Errorf("split printed\n%s", want)
	}
	for _, args := range [][]string{{"split", "-h"}, {"-h"}, {"help"}} {
		out, _, err := descbackup("", args...)
		if err != nil || !strings.Contains(out, "-k K   the number of plates needed to recover") {
			t.Errorf("%q: %v\n%s", args, err, out)
		}
	}
	if _, _, err := descbackup("", "split", export, "-k", "2", "-n", "3"); !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "flags before it") {
		t.Errorf("flags after the descriptor: %v", err)
	}
	if _, _, err := descbackup(" \n", "split"); !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "no descriptor given") {
		t.Errorf("nothing on standard input: %v", err)
	}
}

func TestSplitThreshold(t *testing.T) {
	var keys256 []string
	for i := range 256 {
		keys256 = append(keys256, fmt.Sprintf("02ab%062x", i+1))
	}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"-k", "3", export}, "the descriptor is 2-of-3"},
		{[]string{"-n", "4", export}, "the descriptor is 2-of-3"},
		{[]string{"wpkh(" + key + ")"}, "give -k"},
		{[]string{"-k", "2", "wpkh(" + key + ")"}, "give -k"},
		{[]string{"-k", "3", "-n", "2", "wpkh(" + key + ")"}, "k must be from 1 to n"},
		{[]string{"wsh(sortedmulti(2," + key + "," + bare + "))#aaaaaaaa"}, "checksum"},
		{[]string{"-k", "2", "-n", "256", "wpkh(" + key + ")"}, "-n 256: a set has at most 255 shares"},
		{[]string{"wsh(multi(2," + strings.Join(keys256, ",") + "))"}, "256 keys: a set has at most 255 shares"},
	} {
		if _, _, err := descbackup("", append([]string{"split"}, c.args...)...); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("split %.80q: %v, want %q", c.args, err, c.err)
		}
	}

	// A 1-of-n descriptor makes no set: every plate carries it.
	out, _, err := descbackup("", "split", "wsh(sortedmulti(1,"+key+","+bare+"))")
	if err != nil || !strings.HasPrefix(out, "# 1-of-2: no set; every plate carries this descriptor as it is\nwsh(sortedmulti(1,") {
		t.Errorf("split of a 1-of-2 = %v\n%s", err, out)
	}

	// A descriptor that does not say which key goes with which share
	// takes k and n from the flags and labels no keys.
	out, _, err = descbackup("", "split", "-k", "2", "-n", "3", "tr("+key+",sortedmulti_a(2,"+bare+","+bare[:len(bare)-1]+"6))")
	if err != nil || !strings.Contains(out, " (2-of-3, sealed)\nSHAQR:") || strings.Contains(out, "key") {
		t.Errorf("split of a tr() = %v\n%s", err, out)
	}

	// A key without an origin is named by its last 8 characters, without
	// the children that the canonical form gives it.
	out, _, err = descbackup("", "split", "wsh(multi(2,"+key+","+bare+"))")
	if err != nil || !strings.Contains(out, " (2-of-2, sealed), key [d34db33f]\n") || !strings.Contains(out, " (2-of-2, sealed), key ...Uv6fcLW5\n") {
		t.Errorf("split with a bare key = %v\n%s", err, out)
	}
}

// Split refuses a key whose origin or path no wallet would take, and
// names it.
func TestSplitKeys(t *testing.T) {
	for _, c := range []struct {
		desc, err string
	}{
		{"wsh(sortedmulti(2,[d34db33f/48H/0H/0H/2H]" + bare + "/<0;1>/*," + bare + "/0/*))", `key [d34db33f/48H/0H/0H/2H]xpub6D4BDPcP2GT577Vvch3R8...: "48H" is not a step`},
		{"wsh(sortedmulti(2,[zz/48q]foo,bar,baz))", `key [zz/48q]foo: the origin fingerprint "zz" is not 8 hex digits`},
		{"wsh(sortedmulti(2,[d34db33f/48q]foo,bar,baz))", `key [d34db33f/48q]foo: "48q" is not a step`},
		{"wsh(sortedmulti(2," + key + "/0/x," + bare + "))", `"x" is not a step`},
		{"wsh(sortedmulti(2," + key + "/<0;1>," + bare + "//0))", `"" is not a step`},
		{"wsh(sortedmulti(2,foo[d34db33f]bar," + bare + "))", "a key origin is in [ ] at the start of the key"},
	} {
		if _, _, err := descbackup("", "split", c.desc); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("split %q: %v, want %q", c.desc, err, c.err)
		}
	}
	for _, args := range [][]string{
		{"wsh(sortedmulti(2," + key + "/<0;1>/*," + bare + "/<0h;1h>/*h))"},
		{"-k", "2", "-n", "2", "tr(" + bare + ",multi_a(2,[d34db33f]" + bare + "/7/*," + bare + "))"},
	} {
		if _, _, err := descbackup("", append([]string{"split"}, args...)...); err != nil {
			t.Errorf("split %q: %v", args, err)
		}
	}
}

// A holder's box can hold plates of another wallet and plates that are
// damaged. Each is reported by the line it starts on, and none stops the
// recovery.
func TestRecoverDamaged(t *testing.T) {
	desc, tag, plates := vector(t, "sealed")
	foreign, err := shaqr.Split([]byte("another wallet"), shaqr.TypeText, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := shaqr.ParseHeader(foreign[1])
	typo := []byte(plates[1])
	typo[100] = map[bool]byte{true: 'B', false: 'A'}[typo[100] == 'A']

	input := "# a plate of another wallet\n" + shaqr.Encode(foreign[1]) + "\n" +
		"# cut short by a 1\n" + plates[1][:49] + "1" + plates[1][49:] + "\n" +
		"# a typing error\n" + string(typo) + "\n" +
		"# two good plates\n" + plates[0] + "\n" + plates[2] + "\n"
	out, reports, err := descbackup(input, "recover")
	if err != nil || out != desc+"\n" {
		t.Errorf("recover = %q, %v", out, err)
	}
	want := "malformed text: the share on line 4: 43 characters up to '1' on line 4, a length that base32 does not produce\n" +
		"share 2 of set " + tag + " (unverified), on line 6: share check failed\n" +
		"set " + h.Tag() + ": 1 of 2 shares: have share 2; add another plate of this set\n"
	if reports != want {
		t.Errorf("reports\n%s\nwant\n%s", reports, want)
	}
}

// A stray character inside a share cuts it short. Whether what is left
// decodes or not, the report names the character and its line, and the
// rest of the share is reported as base32 outside every share.
func TestRecoverCutShort(t *testing.T) {
	_, tag, plates := vector(t, "sealed")
	for _, c := range []struct {
		at   int // base32 characters before the stray 8
		want string
	}{
		{56, "share 2 of set " + tag + " (unverified), on line 2: share check failed; it ends at '8' on line 5, which is not a base32 character\n"},
		{57, "malformed text: the share on line 2: 57 characters up to '8' on line 5, a length that base32 does not produce\n"},
	} {
		cut := 6 + c.at
		input := "# plate 2\n" + wrap(plates[1][:cut]+"8"+plates[1][cut:]) + "# plate 1\n" + plates[0] + "\n"
		_, reports, err := descbackup(input, "recover")
		if err == nil || !strings.HasPrefix(reports, c.want) || !strings.Contains(reports, "\nlines 6 to ") ||
			!strings.Contains(reports, " hold base32 outside every share: a share without its SHAQR: prefix, or the rest of one cut short\n") {
			t.Errorf("an 8 after %d characters: %v\n%s", c.at, err, reports)
		}
	}
}

// Input without a share says so, and a plate typed without its prefix
// is pointed out.
func TestRecoverNoShares(t *testing.T) {
	desc, _, plates := vector(t, "sealed")
	for _, c := range []struct {
		input, reports string
	}{
		{"", ""},
		// Words of a note are base32 letters, and too short to look like a share.
		{"Backup of the family wallet kept in the safe\n", ""},
		{"\n  " + desc + "\n", "the input is a descriptor with its checksum, not shares: a 1-of-n backup carries the descriptor itself\n"},
		{"# plate 1\nshaqr " + plates[0][6:] + "\n", "line 2 holds base32 outside every share: a share without its SHAQR: prefix, or the rest of one cut short\n"},
	} {
		_, reports, err := descbackup(c.input, "recover")
		if err == nil || err.Error() != "no shares found in the input" || reports != c.reports {
			t.Errorf("recover of %.40q = %q, %v", c.input, reports, err)
		}
	}
	_, reports, _ := descbackup(plates[0]+"\n# plate 2\n"+wrap(strings.ToLower(plates[1][6:])), "recover")
	if !strings.HasPrefix(reports, "lines 3 to 16 hold base32 outside every share") {
		t.Errorf("a plate without its prefix after another plate: %q", reports)
	}
}

// A share that passes its check and is off the set is named by its line.
// Where two texts claim one x, the id decides between them.
func TestRecoverWrongShares(t *testing.T) {
	desc, tag, plates := vector(t, "sealed")
	forged := reseal(t, plates[2], 60)
	out, reports, err := descbackup(plates[0]+"\n"+plates[1]+"\n"+forged, "recover")
	if err != nil || out != desc+"\n" || reports != "set "+tag+": share 3, on line 3, is wrong and should be replaced\n" {
		t.Errorf("recover with a forged share 3 = %q, %q, %v", out, reports, err)
	}

	forged = reseal(t, plates[1], 60)
	disputed := "set " + tag + ": different texts given for share 2, on lines 1 and 2\n" +
		"set " + tag + ": of the 2 texts given for share 2, the one on line 1 is right and the one on line 2 is wrong\n"
	for _, input := range []string{
		plates[1] + "\n" + forged + "\n" + plates[0] + "\n" + plates[2],
		// Too few other x values: each text is tried, and the id decides.
		plates[1] + "\n" + forged + "\n" + plates[0],
	} {
		out, reports, err = descbackup(input, "recover")
		if err != nil || out != desc+"\n" || reports != disputed {
			t.Errorf("recover with x = 2 disputed = %q, %q, %v", out, reports, err)
		}
	}

	// Both texts of share 2 are wrong.
	other := reseal(t, plates[1], 61)
	_, reports, err = descbackup(forged+"\n"+other+"\n"+plates[0], "recover")
	want := "set " + tag + ": 1 of 2 shares, not counting share 2, whose texts differ and give no set that passes its id: " +
		"have share 1; add another plate of this set\n"
	if err == nil || !strings.HasSuffix(reports, want) {
		t.Errorf("recover with two wrong texts for x = 2 = %q, %v", reports, err)
	}

	// Exactly k shares, one forged: the id fails, and a spare would tell.
	_, reports, err = descbackup(plates[0]+"\n"+forged, "recover")
	want = "set " + tag + ": these shares do not fit together; one of them reads correctly and is still wrong. " +
		"Add another plate of this set to find which\n"
	if err == nil || err.Error() != "1 of 1 sets with enough shares failed" || reports != want {
		t.Errorf("recover of k shares, one forged = %q, %v", reports, err)
	}
}

// A set short of k says which shares it has, and which were given twice.
func TestRecoverShort(t *testing.T) {
	_, tag, plates := vector(t, "sealed")
	_, reports, err := descbackup(plates[0]+"\n"+plates[0], "recover")
	want := "set " + tag + ": 1 of 2 shares: have share 1 (given twice, on lines 1 and 2); add another plate of this set\n"
	if err == nil || reports != want {
		t.Errorf("recover of one plate twice = %q, %v", reports, err)
	}

	shares, err := (&shaqr.Splitter{Derived: true}).Split([]byte(export), shaqr.TypeDescriptor, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := shaqr.ParseHeader(shares[0])
	input := shaqr.Encode(shares[0]) + "\n" + shaqr.Encode(shares[3]) + "\n" + shaqr.Encode(shares[3])
	_, reports, _ = descbackup(input, "recover")
	want = "set " + h.Tag() + ": 2 of 3 shares: have shares 1 and 4 (share 4 given twice, on lines 2 and 3); add another plate of this set\n"
	if reports != want {
		t.Errorf("recover of 2 of 3 = %q", reports)
	}
}

// A set that recovers and does not hold a packed descriptor is reported,
// and the other sets are recovered all the same.
func TestRecoverNotADescriptor(t *testing.T) {
	desc, _, plates := vector(t, "sealed")
	packed, err := descriptor.Pack(desc)
	if err != nil {
		t.Fatal(err)
	}
	notPacked := "the payload unpacks to a descriptor that packs to other bytes, so it is not the packed form DESCRIPTOR.md gives"
	good := plates[0] + "\n" + plates[1] + "\n"
	for _, c := range []struct {
		typ     byte
		payload []byte
		err     string
	}{
		{shaqr.TypeText, packed, "it holds a text note (type U), not a descriptor"},
		{shaqr.TypeBytes, packed, "it holds bytes (type B), not a descriptor"},
		{'Z', packed, "it holds content of type 0x5A, not a descriptor"},
		// The text, as Draft 3 held it, fails the repack check.
		{shaqr.TypeDescriptor, []byte(desc), notPacked},
		{shaqr.TypeDescriptor, []byte(desc[:len(desc)-9]), notPacked},
		// An origin token with nothing after its marker.
		{shaqr.TypeDescriptor, append(bytes.Clone(packed), 0x91), "the payload is not a packed descriptor"},
		// Nothing of the payload goes into the report.
		{shaqr.TypeDescriptor, []byte("pässword-hunter2"), "the payload is not a packed descriptor"},
	} {
		shares, err := shaqr.Split(c.payload, c.typ, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := shaqr.ParseHeader(shares[0])
		input := good + shaqr.Encode(shares[0]) + "\n" + shaqr.Encode(shares[1])
		out, reports, err := descbackup(input, "recover")
		if err == nil || out != desc+"\n" || reports != "set "+h.Tag()+": "+c.err+"\n" {
			t.Errorf("%s: recover = %q, %q, %v", c.err, out, reports, err)
		}
	}
}

// Several sets: recover says which output line is which set, and
// replace names them.
func TestSeveralSets(t *testing.T) {
	desc, tag, plates := vector(t, "sealed")
	other, _, err := descbackup("", "split", "wsh(multi(2,"+key+","+bare+"))")
	if err != nil {
		t.Fatal(err)
	}
	raws, _ := shaqr.Decode(other)
	h, _ := shaqr.ParseHeader(raws[0])
	input := plates[0] + "\n" + plates[1] + "\n" + other
	out, reports, err := descbackup(input, "recover")
	want := "line 1 of the output: set " + tag + " (2-of-3, sealed)\nline 2 of the output: set " + h.Tag() + " (2-of-2, sealed)\n"
	if err != nil || !strings.HasPrefix(out, desc+"\nwsh(multi(2,") || reports != want {
		t.Errorf("recover of two sets = %q, %q, %v", out, reports, err)
	}
	_, _, err = descbackup(input, "replace", "2")
	if want := "2 sets have enough shares: " + tag + " (2-of-3, sealed) and " + h.Tag() + " (2-of-2, sealed); give one set at a time"; err == nil || err.Error() != want {
		t.Errorf("replace with two sets: %v", err)
	}

	// The sealed and the open set of one wallet stay apart, and each
	// gives the descriptor.
	_, openTag, open := vector(t, "open")
	out, reports, err = descbackup(plates[0]+"\n"+open[1]+"\n"+plates[1]+"\n"+open[0], "recover")
	want = "line 1 of the output: set " + tag + " (2-of-3, sealed)\nline 2 of the output: set " + openTag + " (2-of-3, open)\n"
	if err != nil || out != desc+"\n"+desc+"\n" || reports != want {
		t.Errorf("recover of the sealed and the open set = %q, %q, %v", out, reports, err)
	}
}

func TestReplace(t *testing.T) {
	for _, format := range []string{"sealed", "open"} {
		_, tag, plates := vector(t, format)
		out, reports, err := descbackup(plates[2]+"\n"+plates[0], "replace", "2")
		want := "# share 2 of set " + tag + " (2-of-3, " + format + "), key [73c5da0a]\n" + plates[1] + "\n"
		if err != nil || reports != "" || out != want {
			t.Errorf("replace 2 of the %s set = %q, %q, %v", format, out, reports, err)
		}
	}

	// A fourth share goes on no key's plate.
	_, tag, plates := vector(t, "sealed")
	out, reports, err := descbackup(plates[0]+"\n"+plates[1], "replace", "4")
	if err != nil || !strings.HasPrefix(out, "# share 4 of set "+tag+" (2-of-3, sealed)\nSHAQR:") ||
		reports != "share 4 goes on no key's plate: the descriptor has 3 keys, so it is an extra plate of set "+tag+"\n" {
		t.Errorf("replace 4 = %q, %q, %v", out, reports, err)
	}
	raws, _ := shaqr.Decode(out)
	all, _ := shaqr.Decode(strings.Join(plates, "\n"))
	if _, _, err := shaqr.Combine([][]byte{raws[0], all[2]}); err != nil {
		t.Errorf("share 4 with share 3: %v", err)
	}

	for _, c := range []struct {
		input, err string
	}{
		{plates[0], "no set has enough shares"},
		{"", "no shares found in the input"},
	} {
		if _, _, err := descbackup(c.input, "replace", "2"); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("replace: %v, want %q", err, c.err)
		}
	}

	// X is checked before anything is read.
	for _, x := range []string{"0", "256", "-1", "two"} {
		err := run([]string{"replace", x}, unread{t}, io.Discard, log.New(io.Discard, "", 0))
		if !errors.Is(err, errUsage) || !strings.HasPrefix(err.Error(), "X must be a number from 1 to 255\n") {
			t.Errorf("replace %s: %v", x, err)
		}
	}
}

// unread is standard input that must not be read.
type unread struct{ t *testing.T }

func (u unread) Read([]byte) (int, error) {
	u.t.Error("standard input read")
	return 0, io.EOF
}

// Plates engraved in text alone: every share wrapped at 20 characters
// with its label above it, read back in any case.
func TestTextOnly(t *testing.T) {
	desc, _, _ := vector(t, "sealed")
	out, _, err := descbackup("", "split", export)
	if err != nil {
		t.Fatal(err)
	}
	text := wrap(out)
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "#") && len(line) > 20 {
			t.Fatalf("share not wrapped: %q", line)
		}
	}
	two, three := strings.Index(text, "# share 2"), strings.Index(text, "# share 3")
	for _, input := range []string{
		text,
		strings.ToLower(text),
		strings.ToLower(text[:two] + text[three:]),
		text[two:],
	} {
		got, reports, err := descbackup(input, "recover")
		if err != nil || reports != "" || got != desc+"\n" {
			t.Errorf("recover from\n%s\n= %q, %q, %v", input, got, reports, err)
		}
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"splice"},
		{"split"},
		{"split", "-x", export},
		{"split", export, export},
		{"recover", "now"},
		{"replace"},
		{"replace", "two"},
		{"replace", "0"},
		{"replace", "2", "3"},
	} {
		if _, _, err := descbackup("", args...); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v, want the usage", args, err)
		}
	}
}

// Every line split prints that is not a share is a label: it starts with
// "#" and is part of no share, in either case.
func TestLabels(t *testing.T) {
	for _, format := range []string{"sealed", "open"} {
		_, _, plates := vector(t, format)
		out, _, err := descbackup("", "split", "-open="+fmt.Sprint(format == "open"), export)
		if err != nil {
			t.Fatal(err)
		}
		var labels []string
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if !strings.HasPrefix(line, "SHAQR:") {
				labels = append(labels, line)
			}
		}
		for _, line := range labels {
			if !strings.HasPrefix(line, "#") {
				t.Errorf("label %q does not start with #", line)
			}
		}
		if raws, rejected := shaqr.Decode(strings.Join(labels, "\n")); raws != nil || rejected != nil {
			t.Errorf("labels alone decode to %x, %v", raws, rejected)
		}
		want, _ := shaqr.Decode(strings.Join(plates, "\n"))
		if raws, rejected := shaqr.Decode(strings.ToLower(out)); rejected != nil || !reflect.DeepEqual(raws, want) {
			t.Errorf("split output of the %s set in lower case decodes to %x, %v", format, raws, rejected)
		}
	}
}
