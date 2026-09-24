// SPDX-License-Identifier: CC0-1.0

// Descbackup splits a multisig wallet descriptor into a set of plates,
// by default one for each signer's seed, and recovers it from any k of
// them, as DESCRIPTOR.md describes.
//
//	descbackup split [-open] [-k K] [-n N] [DESCRIPTOR]
//	descbackup recover < plates.txt
//	descbackup replace [-n N] X < plates.txt
//
// Split puts the descriptor in canonical form, packs it and cuts a
// derived set of it, so that every run cuts the same plates from the
// same wallet and k. With -open it cuts an open set instead, whose
// plates are 32 bytes shorter and each show part of the descriptor. It
// refuses to cut an open set of a descriptor that holds a private key,
// or a key that looks like one. It takes the descriptor from its
// argument, or from standard input when there is none or it is "-",
// which keeps the keys out of the shell's history. By default k and n
// are the wallet's quorum, which it reads from a descriptor whose keys
// all sit in one multi, sortedmulti, multi_a or sortedmulti_a. -k and -n
// override either, since a set is not tied to the keys: a 3-of-5 wallet
// can go on 2-of-3 plates. For any other descriptor give -k, the size of
// the smallest group of keys that can spend, and -n. It labels share x
// with its set, the quorum of the set and its format, sealed or open,
// and names no key: the owner decides who keeps which plate. It checks
// the origin and the path of every key and the base58check of every
// extended key, and warns when the descriptor has no checksum, since
// then nothing shows that it is the wallet's. A k of 1, the default of a
// 1-of-n descriptor, makes no set: split prints the canonical
// descriptor, which goes on every plate as it is. Every other line it
// prints that is not a share starts with "#".
//
// Recover and replace read standard input as one text, as it was scanned
// or typed from the plates: in any case, wrapped over lines, with labels
// between the shares. They report every share they leave out and why, by
// the line it starts on, and every set they hold too few shares of, and
// carry on without them. Recover unpacks the descriptor of every set it
// holds k shares of and prints it with its checksum, byte for byte, with
// a warning when it is not a descriptor in canonical form. Replace
// prints share X of the one set it holds k shares of, to cut a lost
// plate again or add one. A share does not tell n, so replace labels it
// with the wallet's number of keys when the set's k is the wallet's
// threshold, as split does by default, and with the n of -n when it is
// given.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Gangleri42/shaqr"
	"github.com/Gangleri42/shaqr/descriptor"
)

// errUsage reports a command line that names no command or gives one the
// wrong arguments.
var errUsage = errors.New(`usage: descbackup split [-open] [-k K] [-n N] [DESCRIPTOR]
       descbackup recover < plates.txt
       descbackup replace [-n N] X < plates.txt
       descbackup -h`)

// help explains the commands and flags, for -h.
const help = `Descbackup splits a multisig wallet descriptor into a set of plates, by
default one for each signer's seed, and recovers it from any k of them
(DESCRIPTOR.md).

descbackup split [-open] [-k K] [-n N] [DESCRIPTOR]
    Print the plates: a label and a share for each of the n plates. A
    label names the set, its quorum and its format, and no key. The shares
    form a sealed set: below k plates, they show nothing of the descriptor
    to anyone who lacks one of its keys. The descriptor comes from the
    argument, or from standard input when there is none or it is "-".
    Flags go before it.

    -open  cut an open set: every plate is 32 bytes shorter and shows
           part of the descriptor; the first k plates hold slices of it,
           whole public keys among them. Not for a descriptor that holds
           a private key.
    -k K   the number of plates needed to recover, from 2 to N. A k of 1
           makes no set and prints the descriptor for every plate.
    -n N   the number of plates to make, at most 255.

    -k and -n default to the wallet's quorum, its threshold and its number
    of keys, when the keys are all in one multi, sortedmulti, multi_a or
    sortedmulti_a. Either can differ from it: a 3-of-5 wallet can go on
    2-of-3 plates. Any group that has to recover the wallet needs k of
    them. For any other descriptor give both, with -k the size of the
    smallest group of keys that can spend.

descbackup recover < plates.txt
    Print the descriptor of every set the text holds enough shares of,
    and report every share it leaves out.

descbackup replace [-n N] X < plates.txt
    Print share X, a number from 1 to 255, of the one set the text holds
    enough shares of, to cut a lost plate again or to add one. A share
    does not tell n: the label gives the wallet's number of keys when the
    set's k is the wallet's threshold, and -n N when it is given.
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("descbackup: ")
	err := run(os.Args[1:], os.Stdin, os.Stdout, log.Default())
	switch {
	case errors.Is(err, errUsage):
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	case err != nil:
		log.Fatal(err)
	}
}

// run carries out the command in args. Shares and descriptors go to out,
// and reports on what the command leaves out go to logger.
func run(args []string, in io.Reader, out io.Writer, logger *log.Logger) error {
	if len(args) == 0 {
		return errUsage
	}
	switch cmd, args := args[0], args[1:]; cmd {
	case "split":
		return splitCmd(args, in, out, logger)
	case "recover":
		if len(args) != 0 {
			return errUsage
		}
		return recoverCmd(in, out, logger)
	case "replace":
		return replaceCmd(args, in, out, logger)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(out, help)
		return nil
	}
	return errUsage
}

// splitCmd prints the plates of a descriptor backup: a derived set of the
// packed canonical descriptor, or an open set of it with -open, each
// share under a label.
func splitCmd(args []string, in io.Reader, out io.Writer, logger *log.Logger) error {
	fs := flag.NewFlagSet("split", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	openSet := fs.Bool("open", false, "cut an open set")
	k := fs.Int("k", 0, "shares needed to recover")
	n := fs.Int("n", 0, "shares to make")
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(out, help)
		return nil
	case err != nil:
		return fmt.Errorf("%v\n%w", err, errUsage)
	}
	var given string
	switch {
	case fs.NArg() > 1:
		return fmt.Errorf("give one descriptor, with the flags before it\n%w", errUsage)
	case fs.NArg() == 1 && fs.Arg(0) != "-":
		given = fs.Arg(0)
	default:
		text, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		given = string(text)
	}
	if strings.TrimFunc(given, unicode.IsSpace) == "" {
		return fmt.Errorf("no descriptor given\n%w", errUsage)
	}

	desc, err := descriptor.Canonical(given)
	if err != nil {
		return err
	}
	if err := checkKeys(desc); err != nil {
		return err
	}
	if *openSet && private(desc) {
		return errors.New("the descriptor holds a private key, and the plates of an open set would show it: leave out -open")
	}
	qk, qn, err := threshold(desc, *k, *n)
	if err != nil {
		return err
	}
	if !strings.Contains(given, "#") {
		logger.Printf("warning: the descriptor has no checksum, so nothing shows that it is the wallet's; "+
			"compare its keys with the wallet before you cut the plates. In canonical form it is\n%s", desc)
	}
	if qk == 1 {
		fmt.Fprintf(out, "# 1-of-%d: no set; every plate carries this descriptor as it is\n%s\n", qn, desc)
		return nil
	}

	payload, err := descriptor.Pack(desc)
	if err != nil {
		return err
	}
	sp := shaqr.Splitter{Derived: !*openSet, Open: *openSet}
	shares, err := sp.Split(payload, shaqr.TypeDescriptor, qk, qn)
	if err != nil {
		return err
	}
	h, _ := shaqr.ParseHeader(shares[0])
	fmt.Fprintf(out, "# set %s (%s), %d bytes per share\n", h.Tag(), summary(h, qn), len(shares[0]))
	for i, sh := range shares {
		fmt.Fprintf(out, "%s\n%s\n", label(h, i+1, qn), shaqr.Encode(sh))
	}
	return nil
}

// threshold returns k and n. By default they are the wallet's quorum,
// the threshold and the number of keys of a descriptor whose keys all
// sit in one multi (DESCRIPTOR.md Threshold), and the flags, 0 when not
// given, override either, since a set is not tied to the keys. For any
// other descriptor the flags give both. A k of 1 means no set: the
// descriptor goes on every plate as it is.
func threshold(desc string, k, n int) (int, int, error) {
	qk, keys, ok := descriptor.Quorum(desc)
	fromKeys := ok && n == 0
	switch {
	case ok:
		if k == 0 {
			k = qk
		}
		if n == 0 {
			n = len(keys)
		}
	case k == 0 || n == 0:
		return 0, 0, errors.New("the keys are not all in one multi: give -k, the smallest group of keys that can spend, and -n")
	}
	switch {
	case (k < 1 || k > n) && ok:
		return 0, 0, fmt.Errorf("%d-of-%d: k must be from 1 to n; the wallet is %d-of-%d, and -k and -n change either", k, n, qk, len(keys))
	case k < 1 || k > n:
		return 0, 0, fmt.Errorf("-k %d -n %d: k must be from 1 to n", k, n)
	case k == 1:
	case n > 255 && fromKeys:
		return 0, 0, fmt.Errorf("%d keys: a set has at most 255 shares; give -n", n)
	case n > 255:
		return 0, 0, fmt.Errorf("-n %d: a set has at most 255 shares", n)
	}
	return k, n, nil
}

var (
	// originStep is a step of the path in a key origin, once canonical
	// form has written every hardened step with h.
	originStep = regexp.MustCompile(`^[0-9]+h?$`)
	// childStep is a step of the children of a key: a number, *, or a
	// BIP 389 <a;b;...> of numbers, each hardened or not.
	childStep = regexp.MustCompile(`^([0-9]+h?|\*h?|<[0-9]+h?(;[0-9]+h?)+>)$`)
)

// leaves returns the names, numbers, hashes and key expressions of a
// canonical descriptor: its text without the checksum, cut at every
// parenthesis, brace and comma.
func leaves(desc string) []string {
	body := desc[:strings.LastIndexByte(desc, '#')]
	return strings.FieldsFunc(body, func(r rune) bool { return strings.ContainsRune("(){},", r) })
}

// checkKeys makes a light check of every key expression in a canonical
// descriptor, since package descriptor checks none: an origin
// fingerprint is 8 hex digits, every step of a path is a number with at
// most one h after it, or in the children also * or a <a;b>, and an
// extended key passes its base58check. It refuses H, which BIP 380 does
// not take as a hardened marker, so that a wallet that wallet software
// would refuse does not go onto the plates. An xprv mistyped in one
// character would otherwise pass for public. It does not check that a
// key is a point on the curve.
func checkKeys(desc string) error {
	for _, leaf := range leaves(desc) {
		// A name, a number, a hash or a key with neither origin nor
		// children has no [ and no /, and needs a check only when it is
		// an extended key.
		if !strings.ContainsAny(leaf, "[/") && !extended(leaf) {
			continue
		}
		if err := checkKey(leaf); err != nil {
			if len(leaf) > 48 {
				leaf = leaf[:48] + "..."
			}
			return fmt.Errorf("key %s: %v", leaf, err)
		}
	}
	return nil
}

// checkKey checks the origin and the children of one key expression.
func checkKey(key string) error {
	if k, _, _ := strings.Cut(keyOf(key), "/"); extended(k) && len(base58Check(k)) != 78 {
		return errors.New("the extended key fails its base58check: a typing error, or not a key")
	}
	if origin, rest, ok := strings.Cut(key, "]"); ok && strings.HasPrefix(origin, "[") {
		steps := strings.Split(origin[1:], "/")
		if fp := steps[0]; len(fp) != 8 || strings.Trim(fp, "0123456789abcdef") != "" {
			return fmt.Errorf("the origin fingerprint %q is not 8 hex digits", fp)
		}
		for _, st := range steps[1:] {
			if !originStep.MatchString(st) {
				return badStep(st)
			}
		}
		key = rest
	}
	if strings.ContainsAny(key, "[]") {
		return errors.New("a key origin is in [ ] at the start of the key")
	}
	for _, st := range strings.Split(key, "/")[1:] {
		if !childStep.MatchString(st) {
			return badStep(st)
		}
	}
	return nil
}

func badStep(st string) error {
	return fmt.Errorf("%q is not a step of a path: write a number, with h or ' after it for a hardened step", st)
}

// private reports whether a canonical descriptor holds a private key,
// which DESCRIPTOR.md never lets into an open set: an extended key whose
// key starts with a 00 byte, as that of an xprv, a tprv or a SLIP-132
// zprv does, whatever its version; a WIF key, a base58check string of
// 0x80 or 0xEF and 32 bytes, and 01 after them when the key is
// compressed; or a key whose text starts with a letter and "prv", as
// those of xprv, tprv and zprv do, whether its check passes or not.
func private(desc string) bool {
	for _, leaf := range leaves(desc) {
		key, _, _ := strings.Cut(keyOf(leaf), "/")
		raw := base58Check(key)
		wif := len(raw) == 33 || len(raw) == 34 && raw[33] == 0x01
		switch {
		case len(raw) == 78 && raw[45] == 0x00:
			return true
		case wif && (raw[0] == 0x80 || raw[0] == 0xEF):
			return true
		case len(key) >= 4 && ('a' <= key[0] && key[0] <= 'z' || 'A' <= key[0] && key[0] <= 'Z') && key[1:4] == "prv":
			return true
		}
	}
	return false
}

// keyOf returns a key expression without its origin.
func keyOf(key string) string {
	if strings.HasPrefix(key, "[") {
		if i := strings.IndexByte(key, ']'); i >= 0 {
			return key[i+1:]
		}
	}
	return key
}

// extended reports whether a key starts as the BIP 32 extended keys of
// BIP 380 do: xpub, xprv, tpub or tprv.
func extended(key string) bool {
	return len(key) >= 4 && (key[0] == 'x' || key[0] == 't') && (key[1:4] == "pub" || key[1:4] == "prv")
}

// base58Alphabet is the alphabet of Bitcoin addresses.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Check decodes s as base58check, whose last four bytes are the
// first four of a double SHA-256 of the others, and returns the others.
// It returns nil when s is not base58 or the check does not match.
func base58Check(s string) []byte {
	n := new(big.Int)
	for i := range len(s) {
		d := strings.IndexByte(base58Alphabet, s[i])
		if d < 0 {
			return nil
		}
		n.Mul(n, big.NewInt(58)).Add(n, big.NewInt(int64(d)))
	}
	// Every leading 1 stands for a zero byte.
	raw := append(make([]byte, len(s)-len(strings.TrimLeft(s, "1"))), n.Bytes()...)
	if len(raw) < 4 {
		return nil
	}
	body := raw[:len(raw)-4]
	sum := sha256.Sum256(body)
	sum = sha256.Sum256(sum[:])
	if !bytes.Equal(sum[:4], raw[len(body):]) {
		return nil
	}
	return body
}

// label is the line above share x of the set whose header is h: its set,
// its quorum and its format, as in "# share 1 of set #E096 (2-of-3,
// sealed)". It names no key, since a share belongs to the set and not to
// a cosigner (DESCRIPTOR.md Plates). n is 0 when nothing tells it.
func label(h shaqr.Header, x, n int) string {
	return fmt.Sprintf("# share %d of set %s (%s)", x, h.Tag(), summary(h, n))
}

// summary gives the quorum and the format of the set whose header is h,
// as in "2-of-3, sealed", or "2 needed, open" when n is 0 because
// nothing tells it.
func summary(h shaqr.Header, n int) string {
	format := "sealed"
	if h.Open {
		format = "open"
	}
	if n == 0 {
		return fmt.Sprintf("%d needed, %s", h.K, format)
	}
	return fmt.Sprintf("%d-of-%d, %s", h.K, n, format)
}

// defaultN returns the number of plates of a set whose header is h and
// whose descriptor is desc, which no share tells: the wallet's number of
// keys when the set's k is the wallet's threshold, as split cuts a set
// by default. It returns 0, which labels write as "k needed", when the
// descriptor gives no quorum, when the set has another k, and when the
// wallet has more keys than a set has shares.
func defaultN(h shaqr.Header, desc string) int {
	if k, keys, ok := descriptor.Quorum(desc); ok && k == h.K && len(keys) <= 255 {
		return len(keys)
	}
	return 0
}

// recoverCmd prints the descriptor of every set the input holds k shares
// of, one to a line. It fails if a set with k shares fails, after it has
// printed the others.
func recoverCmd(in io.Reader, out io.Writer, logger *log.Logger) error {
	sets, err := recoverSets(in, logger)
	if err != nil {
		return err
	}
	var failed int
	var names []string
	for _, r := range sets {
		if r.err != nil {
			failed++
			continue
		}
		fmt.Fprintln(out, r.desc)
		names = append(names, r.name())
	}
	if len(names) > 1 {
		for i, name := range names {
			logger.Printf("line %d of the output: set %s", i+1, name)
		}
	}
	switch {
	case failed > 0:
		return fmt.Errorf("%d of %d sets with enough shares failed", failed, len(sets))
	case len(sets) == 0:
		return errors.New("no set has enough shares")
	}
	return nil
}

// replaceCmd prints share x of the one set the input holds k shares of
// (SPEC.md Replacing a lost share). It recovers and checks the
// descriptor first, as recoverCmd does, and labels the share with its
// set, the quorum and the format: n from -n, or else defaultN, and k
// alone when x is past that n.
func replaceCmd(args []string, in io.Reader, out io.Writer, logger *log.Logger) error {
	fs := flag.NewFlagSet("replace", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nFlag := fs.Int("n", 0, "plates in the set")
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(out, help)
		return nil
	case err != nil:
		return fmt.Errorf("%v\n%w", err, errUsage)
	case fs.NArg() != 1:
		return errUsage
	}
	x, err := strconv.Atoi(fs.Arg(0))
	if err != nil || x < 1 || x > 255 {
		return fmt.Errorf("X must be a number from 1 to 255\n%w", errUsage)
	}
	if *nFlag != 0 && (*nFlag < 2 || *nFlag > 255) {
		return fmt.Errorf("-n must be a number from 2 to 255\n%w", errUsage)
	}
	sets, err := recoverSets(in, logger)
	if err != nil {
		return err
	}
	switch {
	case len(sets) == 0:
		return errors.New("no set has enough shares")
	case len(sets) > 1:
		names := make([]string, len(sets))
		for i, r := range sets {
			names[i] = r.name()
		}
		return fmt.Errorf("%d sets have enough shares: %s; give one set at a time", len(sets), and(names))
	case sets[0].err != nil:
		return errors.New("no share made: the set failed")
	}

	r := sets[0]
	sh, err := shaqr.ShareAt(r.solving, x)
	if err != nil {
		return err
	}
	n := *nFlag
	switch {
	case n == 0:
		n = defaultN(r.hdr, r.desc)
		if n != 0 && x > n {
			logger.Printf("share %d is past plate %d of set %s, the wallet's number of keys; if the set was cut with more plates, give -n with that number to label it",
				x, n, r.hdr.Tag())
			n = 0
		}
	case n < r.hdr.K:
		return fmt.Errorf("-n %d: set %s needs %d plates, so it has at least %d", n, r.hdr.Tag(), r.hdr.K, r.hdr.K)
	case x > n:
		return fmt.Errorf("-n %d: share %d is past the last plate of set %s", n, x, r.hdr.Tag())
	}
	fmt.Fprintf(out, "%s\n%s\n", label(r.hdr, x, n), shaqr.Encode(sh))
	return nil
}

// A result is a set the input held k shares of, and what it gave: the
// descriptor and the shares that gave it, or the reason it failed. hdr
// is the header of its shares.
type result struct {
	hdr     shaqr.Header
	desc    string
	solving [][]byte
	err     error
}

// name names the set in a message: its tag, its quorum, with the n of
// defaultN, and its format, as in "#E096 (2-of-3, sealed)".
func (r result) name() string {
	n := 0
	if r.err == nil {
		n = defaultN(r.hdr, r.desc)
	}
	return fmt.Sprintf("%s (%s)", r.hdr.Tag(), summary(r.hdr, n))
}

// recoverSets reads the whole input as one text and recovers every set
// it holds k shares of (SPEC.md Recovering). It reports every share it
// leaves out, every set short of k and every set that fails, and goes on
// with the others: a share from another wallet's plate must not get in
// the way of a recovery. It returns the sets that held k shares, in
// order of their first share.
func recoverSets(in io.Reader, logger *log.Logger) ([]result, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	text := string(data)
	found := shaqr.Scan(text)
	if len(found) == 0 {
		unprefixed(text, found, logger)
		if strings.Contains(text, "#") {
			if _, err := descriptor.Canonical(text); err == nil {
				logger.Print("the input is a descriptor with its checksum, not shares: a 1-of-n backup carries the descriptor itself")
			}
		}
		return nil, errors.New("no shares found in the input")
	}

	var p plates
	for _, f := range found {
		if f.Err != nil {
			logger.Print(plain(f.Err))
			continue
		}
		p.add(f)
	}
	sets, rejected := shaqr.Group(p.shares)
	p.report(rejected, logger)
	unprefixed(text, found, logger)

	var results []result
	for _, set := range sets {
		h, _ := shaqr.ParseHeader(set[0])
		r := result{hdr: h}
		r.desc, r.solving, r.err = open(set)
		var tooFew *shaqr.TooFewError
		switch {
		case errors.As(r.err, &tooFew):
			logger.Printf("set %s: %s", h.Tag(), p.held(set, tooFew))
			continue
		case r.err != nil:
			logger.Printf("set %s: %s", h.Tag(), failure(set, h.K, r.err))
		default:
			p.audit(h.Tag(), set, r.solving, logger)
			if c, err := descriptor.Canonical(r.desc); err != nil || c != r.desc {
				logger.Printf("set %s: the text is not a descriptor in canonical form, so no tool that follows DESCRIPTOR.md "+
					"cut these plates from a wallet; check it against the wallet before you use it", h.Tag())
			}
		}
		results = append(results, r)
	}
	return results, nil
}

// maxChoices bounds the choices of one text for each disputed x that
// open tries.
const maxChoices = 64

// open recovers the descriptor that a set holds and unpacks it as
// DESCRIPTOR.md Recovery requires. Where two or more texts claim one x
// and too few other x values remain, it tries each choice of one text
// for each such x in turn, up to maxChoices of them, and the id decides
// (SPEC.md Recovering, step 3). It returns the descriptor and the
// shares that gave it.
func open(set [][]byte) (desc string, solving [][]byte, err error) {
	desc, err = descriptorOf(shaqr.Combine(set))
	var tooFew *shaqr.TooFewError
	if !errors.As(err, &tooFew) || len(tooFew.Disputed) == 0 || len(tooFew.Held)+len(tooFew.Disputed) < tooFew.K {
		return desc, set, err
	}
	for _, choice := range choices(set, tooFew.Disputed) {
		d, cerr := descriptorOf(shaqr.Combine(choice))
		if !errors.Is(cerr, shaqr.ErrID) {
			return d, choice, cerr
		}
	}
	return "", set, err
}

// choices returns every set made of the shares of set at undisputed x
// and one text for each disputed x, or nil when there are more than
// maxChoices of them.
func choices(set [][]byte, disputed []int) [][][]byte {
	var base [][]byte
	texts := make(map[int][][]byte)
	for _, sh := range set {
		h, _ := shaqr.ParseHeader(sh)
		switch {
		case !slices.Contains(disputed, h.X):
			base = append(base, sh)
		case !slices.ContainsFunc(texts[h.X], func(t []byte) bool { return same(t, sh) }):
			texts[h.X] = append(texts[h.X], sh)
		}
	}
	all := [][][]byte{base}
	for _, x := range disputed {
		var next [][][]byte
		for _, c := range all {
			for _, t := range texts[x] {
				next = append(next, append(slices.Clone(c), t))
			}
		}
		if len(next) > maxChoices {
			return nil
		}
		all = next
	}
	return all
}

// descriptorOf checks what Combine recovered as DESCRIPTOR.md Recovery
// requires: content type D, and a payload that unpacks. It returns the
// descriptor with the checksum that unpacking computes.
func descriptorOf(typ byte, payload []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	switch typ {
	case shaqr.TypeDescriptor:
	case shaqr.TypeText:
		return "", errors.New("it holds a text note (type U), not a descriptor")
	case shaqr.TypeBytes:
		return "", errors.New("it holds bytes (type B), not a descriptor")
	default:
		return "", fmt.Errorf("it holds content of type 0x%02X, not a descriptor", typ)
	}
	desc, err := descriptor.Unpack(payload)
	switch {
	case errors.Is(err, descriptor.ErrNotPacked):
		return "", errors.New("the payload unpacks to a descriptor that packs to other bytes, so it is not the packed form DESCRIPTOR.md gives")
	case err != nil:
		// Unpack's other errors can quote a byte of the payload, which
		// has no place in a report.
		return "", errors.New("the payload is not a packed descriptor")
	}
	return desc, nil
}

// failure explains why a set that held k shares gave no descriptor.
func failure(set [][]byte, k int, err error) string {
	if !errors.Is(err, shaqr.ErrID) {
		return plain(err)
	}
	if m := len(xs(set)); m > k {
		msg := fmt.Sprintf("no %d of these %d shares fit together; some of them read correctly and are still wrong. "+
			"Add more plates of this set to find which", k, m)
		if err != shaqr.ErrID {
			msg += " (" + strings.TrimPrefix(err.Error(), shaqr.ErrID.Error()+": ") + ")"
		}
		return msg
	}
	return "these shares do not fit together; one of them reads correctly and is still wrong. " +
		"Add another plate of this set to find which"
}

// plates holds the shares read from the input and where they were found.
type plates struct {
	shares [][]byte
	found  []shaqr.Found    // found[i] is where shares[i] was found
	lines  map[string][]int // the lines of every share, by its bytes
}

func (p *plates) add(f shaqr.Found) {
	if p.lines == nil {
		p.lines = make(map[string][]int)
	}
	p.shares = append(p.shares, f.Share)
	p.found = append(p.found, f)
	p.lines[string(f.Share)] = append(p.lines[string(f.Share)], f.Line)
}

// where says where the text of a share stands in the input, "line 3", or
// "lines 3 and 7" when it was given more than once.
func (p *plates) where(raw []byte) string {
	return linesOf(p.lines[string(raw)])
}

// report names every share that Group left out, with the reason. A
// share that failed step 1 is named by the line it starts on and, when
// its check failed, by the x and tag that its first bytes claim. A
// disputed x is reported once, with the lines of all its texts.
func (p *plates) report(rejected []shaqr.Rejected, logger *log.Logger) {
	disputes := make(map[string][]int)
	for _, r := range rejected {
		if errors.Is(r.Err, shaqr.ErrDisputed) {
			at := disputeKey(p.shares[r.Index])
			disputes[at] = append(disputes[at], p.found[r.Index].Line)
		}
	}
	said := make(map[string]bool)
	for _, r := range rejected {
		raw, f := p.shares[r.Index], p.found[r.Index]
		var msg string
		if errors.Is(r.Err, shaqr.ErrDisputed) {
			h, _ := shaqr.ParseHeader(raw)
			msg = fmt.Sprintf("set %s: different texts given for share %d, on %s", h.Tag(), h.X, linesOf(disputes[disputeKey(raw)]))
		} else {
			msg = name(raw, f, r.Err) + ": " + plain(r.Err) + stopNote(f)
		}
		if !said[msg] {
			said[msg] = true
			logger.Print(msg)
		}
	}
}

// disputeKey identifies an x of a set: format, k, x, id and length.
func disputeKey(raw []byte) string {
	return fmt.Sprint(raw[:19], len(raw))
}

// name names a share that failed step 1 by the line it starts on, and,
// when its check failed, by the x and tag its first bytes claim, which
// nothing has verified.
func name(raw []byte, f shaqr.Found, err error) string {
	if errors.Is(err, shaqr.ErrCheck) && len(raw) >= 5 {
		return fmt.Sprintf("share %d of set #%02X%02X (unverified), on line %d", raw[2], raw[3], raw[4], f.Line)
	}
	return fmt.Sprintf("the share on line %d", f.Line)
}

// stopNote points at the character that ended a share, since whatever
// followed it lies outside the share: any character but the "#" that
// starts a label.
func stopNote(f shaqr.Found) string {
	if f.Stop == 0 || f.Stop == '#' {
		return ""
	}
	return fmt.Sprintf("; it ends at %q on line %d, which is not a base32 character", f.Stop, f.EndLine)
}

// held says how many of the k shares it needs a set holds, which x
// values, and which were given more than once, as in "1 of 2 shares:
// have share 1 (given twice, on lines 1 and 2); add another plate of
// this set". Copies of a share count once, and an x with two or more
// different texts does not count unless a choice among them fits.
func (p *plates) held(set [][]byte, e *shaqr.TooFewError) string {
	msg := fmt.Sprintf("%d of %d shares", len(e.Held), e.K)
	if len(e.Disputed) > 0 {
		msg += fmt.Sprintf(", not counting %s, whose texts differ", sharesOf(e.Disputed))
		if len(e.Held)+len(e.Disputed) >= e.K {
			msg += " and give no set that passes its id"
		}
	}
	if len(e.Held) > 0 {
		var copies []string
		for _, x := range e.Held {
			for _, sh := range set {
				h, _ := shaqr.ParseHeader(sh)
				if n := len(p.lines[string(sh)]); h.X == x && n > 1 {
					note := fmt.Sprintf("given %s, on %s", times(n), p.where(sh))
					if len(e.Held) > 1 {
						note = fmt.Sprintf("share %d %s", x, note)
					}
					copies = append(copies, note)
					break
				}
			}
		}
		msg += ": have " + sharesOf(e.Held)
		if len(copies) > 0 {
			msg += " (" + strings.Join(copies, "; ") + ")"
		}
	}
	return msg + "; add another plate of this set"
}

// audit names the shares of a recovered set that are off its
// polynomials, by the lines they stand on, and where two or more texts
// claim one x, it says which of them is right. solving holds the shares
// Combine passed on: the set, or the set with one text chosen for each
// disputed x.
func (p *plates) audit(tag string, set, solving [][]byte, logger *log.Logger) {
	// Combine has just passed on solving, so Audit and ShareAt find the
	// same k shares and cannot fail.
	bad, _ := shaqr.Audit(solving)
	for _, x := range xs(set) {
		var texts [][]byte
		for _, sh := range set {
			if h, _ := shaqr.ParseHeader(sh); h.X == x && !slices.ContainsFunc(texts, func(t []byte) bool { return same(t, sh) }) {
				texts = append(texts, sh)
			}
		}
		if len(texts) == 1 {
			if slices.Contains(bad, x) {
				logger.Printf("set %s: share %d, on %s, is wrong and should be replaced", tag, x, p.where(texts[0]))
			}
			continue
		}
		right, _ := shaqr.ShareAt(solving, x)
		var good, wrong []int
		for _, t := range texts {
			if same(t, right) {
				good = append(good, p.lines[string(t)]...)
			} else {
				wrong = append(wrong, p.lines[string(t)]...)
			}
		}
		switch {
		case len(good) == 0:
			logger.Printf("set %s: every text given for share %d, on %s, is wrong and should be replaced", tag, x, linesOf(wrong))
		case len(texts) == 2:
			logger.Printf("set %s: of the 2 texts given for share %d, the one on %s is right and the one on %s is wrong",
				tag, x, linesOf(good), linesOf(wrong))
		default:
			logger.Printf("set %s: of the %d texts given for share %d, the one on %s is right and the others, on %s, are wrong",
				tag, len(texts), x, linesOf(good), linesOf(wrong))
		}
	}
}

// xs returns the x values of the shares of a set, in ascending order.
func xs(set [][]byte) []int {
	var all []int
	for _, sh := range set {
		h, _ := shaqr.ParseHeader(sh)
		if !slices.Contains(all, h.X) {
			all = append(all, h.X)
		}
	}
	slices.Sort(all)
	return all
}

// same compares two shares without stopping at the first difference.
func same(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// unprefixed warns about lines outside every share that hold nothing but
// base32 characters and white space, with 16 or more of those characters
// in a row: a share typed without its SHAQR: prefix, or the rest of one
// that a stray character cut short. Words of a note are shorter.
func unprefixed(text string, found []shaqr.Found, logger *log.Logger) {
	lines := strings.Split(text, "\n")
	inside := make([]bool, len(lines)+1)
	for _, f := range found {
		for l := f.Line; l <= f.EndLine && l <= len(lines); l++ {
			inside[l] = true
		}
	}
	var runs [][2]int
	for i, line := range lines {
		n := i + 1
		switch {
		case inside[n] || !base32Line(line):
		case len(runs) > 0 && runs[len(runs)-1][1] == n-1:
			runs[len(runs)-1][1] = n
		default:
			runs = append(runs, [2]int{n, n})
		}
	}
	for _, r := range runs {
		where := fmt.Sprintf("line %d holds", r[0])
		if r[0] != r[1] {
			where = fmt.Sprintf("lines %d to %d hold", r[0], r[1])
		}
		logger.Printf("%s base32 outside every share: a share without its SHAQR: prefix, or the rest of one cut short", where)
	}
}

// base32Line reports whether a line holds nothing but base32 characters,
// in either case, and white space, with 16 or more of the characters in
// a row.
func base32Line(line string) bool {
	run, longest := 0, 0
	for _, r := range line {
		switch {
		case 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z', '2' <= r && r <= '7':
			run++
			longest = max(longest, run)
		case unicode.IsSpace(r):
			run = 0
		default:
			return false
		}
	}
	return longest >= 16
}

// plain returns the text of an error without the "shaqr: " of package
// shaqr, which reads as if it named the SHAQR: of a share.
func plain(err error) string {
	return strings.ReplaceAll(err.Error(), "shaqr: ", "")
}

// linesOf writes line numbers as "line 3" or "lines 3 and 7".
func linesOf(lines []int) string {
	lines = slices.Compact(slices.Sorted(slices.Values(lines)))
	if len(lines) == 1 {
		return fmt.Sprintf("line %d", lines[0])
	}
	return "lines " + and(numbers(lines))
}

// sharesOf writes x values as "share 2" or "shares 1 and 2".
func sharesOf(xs []int) string {
	if len(xs) == 1 {
		return fmt.Sprintf("share %d", xs[0])
	}
	return "shares " + and(numbers(xs))
}

func numbers(ns []int) []string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return s
}

// and joins words as "a", "a and b" or "a, b and c".
func and(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// times writes a count of copies: "twice", "3 times".
func times(n int) string {
	if n == 2 {
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}
