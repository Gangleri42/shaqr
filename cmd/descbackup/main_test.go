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
	// Another xpub, that of the wallet's key [b8688df1].
	other = "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX"
	// bare with its last character changed, so that its check fails.
	badBare = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW6"
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
			"# share 1 of " + set + "\n" + plates[0] + "\n" +
			"# share 2 of " + set + "\n" + plates[1] + "\n" +
			"# share 3 of " + set + "\n" + plates[2] + "\n"
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
		// The same xprv with the SLIP-132 version of a zprv, which is no
		// xprv or tprv and holds the same private key.
		zprv = "[aabbccdd/48h/0h/0h/2h]zprvAWgYBBk7JR8GjzqSzmunMCS7dAbwpYTCs1YUMDXqduMA5JFHZ3iX5s2UkAR6vBdcCYYa1S5o1fVLrKsrnpCQ4WpUd6aVUWP1bS2Yy5DoaKv"
		// The zprv with one character changed, so that its check fails.
		badZprv = "[aabbccdd/48h/0h/0h/2h]zprvAWgYBBk7JR8GjzqSzmunMCS7dAbwpYTCs1YUMDXqduMA5JFHZ3iX5s2UmAR6vBdcCYYa1S5o1fVLrKsrnpCQ4WpUd6aVUWP1bS2Yy5DoaKv"
	)
	for _, args := range [][]string{
		{"wsh(sortedmulti(2," + xprv + "/<0;1>/*," + bare + "))"},
		{"-k", "2", "-n", "2", "tr(" + bare + ",multi_a(2," + wif + "," + bare + "/7/*))"},
		{"-k", "2", "-n", "2", "tr(" + bare + ",pk(musig(" + wifC + "," + bare + ")))"},
		{"wsh(sortedmulti(2," + zprv + "/<0;1>/*," + bare + "))"},
		{"wsh(sortedmulti(2," + badZprv + "/<0;1>/*," + bare + "))"},
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
		if err != nil || !strings.Contains(out, "-k K   the number of plates needed to recover") ||
			!strings.Contains(out, "-k and -n default to the wallet's quorum") {
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
		{[]string{"-k", "4", export}, "4-of-3: k must be from 1 to n; the wallet is 2-of-3, and -k and -n change either"},
		{[]string{"-n", "1", export}, "2-of-1: k must be from 1 to n; the wallet is 2-of-3"},
		{[]string{"-k", "-1", export}, "-1-of-3: k must be from 1 to n"},
		{[]string{"-n", "256", export}, "-n 256: a set has at most 255 shares"},
		{[]string{"wpkh(" + key + ")"}, "give -k"},
		{[]string{"-k", "2", "wpkh(" + key + ")"}, "give -k"},
		{[]string{"-k", "3", "-n", "2", "wpkh(" + key + ")"}, "k must be from 1 to n"},
		{[]string{"wsh(sortedmulti(2," + key + "," + bare + "))#aaaaaaaa"}, "checksum"},
		{[]string{"-k", "2", "-n", "256", "wpkh(" + key + ")"}, "-n 256: a set has at most 255 shares"},
		{[]string{"wsh(multi(2," + strings.Join(keys256, ",") + "))"}, "256 keys: a set has at most 255 shares; give -n"},
	} {
		if _, _, err := descbackup("", append([]string{"split"}, c.args...)...); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("split %.80q: %v, want %q", c.args, err, c.err)
		}
	}

	// A 1-of-n descriptor makes no set by default: every plate carries
	// it. So does a k of 1 given with -k. A k of 2 makes a set of it.
	oneOfTwo := "wsh(sortedmulti(1," + key + "," + bare + "))"
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "# 1-of-2: no set; every plate carries this descriptor as it is\nwsh(sortedmulti(1,"},
		{[]string{"-n", "300"}, "# 1-of-300: no set; every plate carries this descriptor as it is\nwsh(sortedmulti(1,"},
		{[]string{"-k", "1", "-n", "3"}, "# 1-of-3: no set; every plate carries this descriptor as it is\nwsh(sortedmulti(1,"},
		{[]string{"-k", "1"}, "# 1-of-2: no set"},
		{[]string{"-k", "2", "-n", "3"}, "# set #"},
	} {
		out, _, err := descbackup("", append(append([]string{"split"}, c.args...), oneOfTwo)...)
		if err != nil || !strings.HasPrefix(out, c.want) {
			t.Errorf("split %q of a 1-of-2 = %v\n%s", c.args, err, out)
		}
	}
	oneOfThree, _, _ := descbackup("", "split", "-k", "1", "-n", "3", export)
	if !strings.HasPrefix(oneOfThree, "# 1-of-3: no set;") {
		t.Errorf("split -k 1 of a 2-of-3 printed\n%s", oneOfThree)
	}

	// -n brings a wallet of more than 255 keys into a set.
	out, _, err := descbackup("", "split", "-n", "3", "wsh(multi(2,"+strings.Join(keys256, ",")+"))")
	if err != nil || !strings.Contains(out, " (2-of-3, sealed), ") || strings.Count(out, "SHAQR:") != 3 {
		t.Errorf("split -n 3 of 256 keys = %v\n%s", err, out)
	}

	// A descriptor that does not say which key goes with which share
	// takes k and n from the flags and labels no keys.
	out, _, err = descbackup("", "split", "-k", "2", "-n", "3", "tr("+key+",sortedmulti_a(2,"+bare+","+other+"))")
	if err != nil || !strings.Contains(out, " (2-of-3, sealed)\nSHAQR:") || strings.Contains(out, "key") {
		t.Errorf("split of a tr() = %v\n%s", err, out)
	}

	// A label names no key, whether it has an origin or not.
	out, _, err = descbackup("", "split", "wsh(multi(2,"+key+","+bare+"))")
	if err != nil || !strings.Contains(out, "# share 1 of set #") || !strings.Contains(out, " (2-of-2, sealed)\nSHAQR:") ||
		strings.Contains(out, "key") || strings.Contains(out, "d34db33f") || strings.Contains(out, "Uv6fcLW5") {
		t.Errorf("split with a bare key = %v\n%s", err, out)
	}
}

// wallet35 is the 3-of-5 wallet of DESCRIPTOR.md Sizes, in canonical
// form.
const wallet35 = "wsh(sortedmulti(3," +
	"[759b1073/48h/0h/0h/2h]xpub6ECC8DopPsi43ovwsteKfSUPbUZEZuknv2AwP54DqmFzUxUjNMyvkCzbSxN6XnFo9DEkWdqpSy87oF6nH6tiWcLmq1B7cMiUuUeQB5w7Tmi/<0;1>/*," +
	"[a9394e65/48h/0h/0h/2h]xpub6EwPeoVByhLBu5Zd45gkzU9HmNyrC3EYkxsS1xoBDd115MWfJ7EfDS7EwjSVF2iZ7ZSJemRrToAipmp9XbW8d42bSET8Pq9V8Hh37FVC9AZ/<0;1>/*," +
	"[ae088dba/48h/0h/0h/2h]xpub6FH2AWEZgkQL8uN1UFkcimcGqFsrivLjt2ouwak9P1aBBpRwZqoqifN9YvChBEQCkKsiuqD252yQs2Y3Y4PtfjgeK5E2cBRyy8Jy9uEcfnp/<0;1>/*," +
	"[dfd3ff9b/48h/0h/0h/2h]xpub6F8wrnn9eAgauZEG7bZoQips14Jrk6wcHGrcWsK5Lo2vaPdiryZrKH7pzkajZwb3gXuvztqNBRwwcDUR4WiLjMaabJWwMM7mAFMnSbyn9ps/<0;1>/*," +
	"[ec68d459/48h/0h/0h/2h]xpub6E8ep22nvtyeoRSNRyB8D6iL2Hic86F5BA1FLwiiHXRxubT9C6qSPUD5k659ASXpAMcaiBBgZziNPCFmBaofqGsvWhyy3szgLLAZW94UdVm/<0;1>/*))#wlklsul6"

// cut splits wallet35 with args and returns the set's tag and its plates.
// It checks the labels, which name the set, its quorum and its format
// and no key.
func cut(t *testing.T, k, n int, args ...string) (tag string, plates []string) {
	t.Helper()
	out, reports, err := descbackup("", append(append([]string{"split"}, args...), wallet35)...)
	if err != nil || reports != "" {
		t.Fatalf("split %q = %v, %q", args, err, reports)
	}
	raws, rejected := shaqr.Decode(out)
	if len(raws) != n || rejected != nil {
		t.Fatalf("split %q gave %d shares, %v", args, len(raws), rejected)
	}
	h, _ := shaqr.ParseHeader(raws[0])
	set := fmt.Sprintf("set %s (%d-of-%d, sealed)", h.Tag(), k, n)
	want := fmt.Sprintf("# %s, %d bytes per share\n", set, len(raws[0]))
	for i, raw := range raws {
		plates = append(plates, shaqr.Encode(raw))
		want += fmt.Sprintf("# share %d of %s\n%s\n", i+1, set, plates[i])
	}
	if h.K != k || out != want {
		t.Errorf("split %q printed\n%s\nwant\n%s", args, out, want)
	}
	return h.Tag(), plates
}

// -k and -n override the wallet's quorum, which they default to: a set is
// not tied to the keys. A 3-of-5 wallet goes on 2-of-3 plates or on
// 4-of-6, and any k of them give it back.
func TestSplitOverride(t *testing.T) {
	_, plates35 := cut(t, 3, 5)
	if _, again := cut(t, 3, 5, "-k", "3", "-n", "5"); !reflect.DeepEqual(again, plates35) {
		t.Errorf("-k 3 -n 5 cut other plates than the default")
	}
	// A derived set is a function of the wallet and k: another n cuts
	// more or fewer of the same plates.
	if _, four := cut(t, 3, 4, "-n", "4"); !reflect.DeepEqual(four, plates35[:4]) {
		t.Errorf("-n 4 cut other plates than the first 4 of the default")
	}
	cut(t, 2, 5, "-k", "2")

	tag23, plates23 := cut(t, 2, 3, "-k", "2", "-n", "3")
	tag46, plates46 := cut(t, 4, 6, "-k", "4", "-n", "6")
	if tag23 == tag46 {
		t.Fatalf("the 2-of-3 and the 4-of-6 set share the tag %s", tag23)
	}
	for _, input := range []string{
		plates23[0] + "\n" + plates23[2],
		plates23[2] + "\n" + plates23[1],
		plates46[5] + "\n" + plates46[0] + "\n" + plates46[3] + "\n" + plates46[2],
		strings.Join(plates46[1:5], "\n"),
	} {
		got, reports, err := descbackup(input, "recover")
		if err != nil || reports != "" || got != wallet35+"\n" {
			t.Errorf("recover = %q, %q, %v", got, reports, err)
		}
	}
	// Three plates of the 4-of-6 are too few, though three seeds sign.
	_, reports, err := descbackup(strings.Join(plates46[:3], "\n"), "recover")
	if err == nil || reports != "set "+tag46+": 3 of 4 shares: have shares 1, 2 and 3; add another plate of this set\n" {
		t.Errorf("recover of 3 plates of the 4-of-6 = %q, %v", reports, err)
	}

	// No share tells n, and a set whose k is not the wallet's threshold
	// was not cut at the wallet's quorum, so its name gives k alone.
	input := plates23[0] + "\n" + plates23[1] + "\n" + strings.Join(plates46[:4], "\n")
	out, reports, err := descbackup(input, "recover")
	want := "line 1 of the output: set " + tag23 + " (2 needed, sealed)\nline 2 of the output: set " + tag46 + " (4 needed, sealed)\n"
	if err != nil || out != wallet35+"\n"+wallet35+"\n" || reports != want {
		t.Errorf("recover of the 2-of-3 and the 4-of-6 = %q, %q, %v", out, reports, err)
	}
}

// Replace labels a share with the n of -n, or by default the wallet's
// number of keys when the set's k is the wallet's threshold.
func TestReplaceOverride(t *testing.T) {
	tag23, plates23 := cut(t, 2, 3, "-k", "2", "-n", "3")
	tag35, plates35 := cut(t, 3, 5)
	two := plates23[0] + "\n" + plates23[2]
	three := plates35[4] + "\n" + plates35[0] + "\n" + plates35[2]
	for _, c := range []struct {
		input   string
		args    []string
		out     string
		reports string
	}{
		{two, []string{"2"}, "# share 2 of set " + tag23 + " (2 needed, sealed)\n" + plates23[1] + "\n", ""},
		{two, []string{"-n", "3", "2"}, "# share 2 of set " + tag23 + " (2-of-3, sealed)\n" + plates23[1] + "\n", ""},
		{two, []string{"-n", "5", "2"}, "# share 2 of set " + tag23 + " (2-of-5, sealed)\n" + plates23[1] + "\n", ""},
		{three, []string{"4"}, "# share 4 of set " + tag35 + " (3-of-5, sealed)\n" + plates35[3] + "\n", ""},
		{three, []string{"-n", "7", "4"}, "# share 4 of set " + tag35 + " (3-of-7, sealed)\n" + plates35[3] + "\n", ""},
		{three, []string{"6"}, "# share 6 of set " + tag35 + " (3 needed, sealed)\n",
			"share 6 is past plate 5 of set " + tag35 + ", the wallet's number of keys; if the set was cut with more plates, give -n with that number to label it\n"},
	} {
		out, reports, err := descbackup(c.input, append([]string{"replace"}, c.args...)...)
		if err != nil || !strings.HasPrefix(out, c.out) || reports != c.reports {
			t.Errorf("replace %q = %q, %q, %v", c.args, out, reports, err)
		}
	}
	if _, _, err := descbackup(three, "replace", "-n", "2", "1"); err == nil || err.Error() != "-n 2: set "+tag35+" needs 3 plates, so it has at least 3" {
		t.Errorf("replace -n 2 of a 3-of-5 set: %v", err)
	}
	if _, _, err := descbackup(two, "replace", "-n", "3", "4"); err == nil || err.Error() != "-n 3: share 4 is past the last plate of set "+tag23 {
		t.Errorf("replace -n 3 4: %v", err)
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
		// An extended key that fails its check: no wallet loads it, and a
		// mistyped xprv would pass for public.
		{"wsh(sortedmulti(2," + key + "," + badBare + "))", "key " + badBare[:48] + "...: the extended key fails its base58check"},
		{"wsh(sortedmulti(2,[aabbccdd/84h/0h/0h]xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMaHi," + bare + "))",
			"the extended key fails its base58check"},
		// Inside a musig() a key keeps no children, and is checked all the same.
		{"tr(" + bare + ",pk(musig(" + bare + "," + badBare + ")))", "the extended key fails its base58check"},
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

// A set whose text is not a descriptor in canonical form was not cut by a
// tool that follows DESCRIPTOR.md. Recover says so and prints the text
// all the same, since only wallet software can judge it.
func TestRecoverNotCanonical(t *testing.T) {
	desc, _, _ := vector(t, "sealed")
	// The wallet with the children /0/*, which the canonical form writes
	// as /<0;1>/*.
	body := strings.ReplaceAll(desc[:len(desc)-9], "/<0;1>/*", "/0/*")
	sum, _ := descriptor.Checksum(body)
	note, _ := descriptor.Checksum("hello, this is not a descriptor")
	for _, text := range []string{body + "#" + sum, "hello, this is not a descriptor#" + note} {
		payload, err := descriptor.Pack(text)
		if err != nil {
			t.Fatal(err)
		}
		shares, err := (&shaqr.Splitter{Open: true}).Split(payload, shaqr.TypeDescriptor, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := shaqr.ParseHeader(shares[0])
		out, reports, err := descbackup(shaqr.Encode(shares[0])+"\n"+shaqr.Encode(shares[2]), "recover")
		want := "set " + h.Tag() + ": the text is not a descriptor in canonical form, so no tool that follows DESCRIPTOR.md " +
			"cut these plates from a wallet; check it against the wallet before you use it\n"
		if err != nil || out != text+"\n" || reports != want {
			t.Errorf("recover of %.30q = %q, %q, %v", text, out, reports, err)
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
		want := "# share 2 of set " + tag + " (2-of-3, " + format + ")\n" + plates[1] + "\n"
		if err != nil || reports != "" || out != want {
			t.Errorf("replace 2 of the %s set = %q, %q, %v", format, out, reports, err)
		}
	}

	// A fourth share is an extra plate of a set cut at the wallet's
	// quorum.
	_, tag, plates := vector(t, "sealed")
	out, reports, err := descbackup(plates[0]+"\n"+plates[1], "replace", "4")
	if err != nil || !strings.HasPrefix(out, "# share 4 of set "+tag+" (2 needed, sealed)\nSHAQR:") ||
		reports != "share 4 is past plate 3 of set "+tag+", the wallet's number of keys; if the set was cut with more plates, give -n with that number to label it\n" {
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

	// X and -n are checked before anything is read.
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"0"}, "X must be a number from 1 to 255\n"},
		{[]string{"256"}, "X must be a number from 1 to 255\n"},
		{[]string{"two"}, "X must be a number from 1 to 255\n"},
		{[]string{"-n", "3", "0"}, "X must be a number from 1 to 255\n"},
		// A negative number reads as a flag.
		{[]string{"-1"}, "flag provided but not defined: -1\n"},
		{[]string{"-n", "1", "2"}, "-n must be a number from 2 to 255\n"},
		{[]string{"-n", "256", "2"}, "-n must be a number from 2 to 255\n"},
		{[]string{"-n", "-3", "2"}, "-n must be a number from 2 to 255\n"},
	} {
		err := run(append([]string{"replace"}, c.args...), unread{t}, io.Discard, log.New(io.Discard, "", 0))
		if !errors.Is(err, errUsage) || !strings.HasPrefix(err.Error(), c.err) {
			t.Errorf("replace %q: %v", c.args, err)
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
		{"replace", "2", "-n", "3"},
		{"replace", "-n"},
		{"replace", "-k", "2", "2"},
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
