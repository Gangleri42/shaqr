// SPDX-License-Identifier: CC0-1.0

// Package shaqr implements the shaQR draft: k-of-n secret sharing in which
// a share is about 1/k the size of the secret. The construction is
// Krawczyk's "Secret Sharing Made Short". SPEC.md is the specification,
// and the functions here name the steps of it that they carry out.
//
// Shares are byte slices. Encode and Decode convert them to and from the
// text form that goes into QR codes.
package shaqr

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"slices"
	"strings"

	"golang.org/x/crypto/chacha20"
)

// Content types. Other values are reserved.
const (
	TypeBytes      byte = 'B'
	TypeText       byte = 'U' // UTF-8, not normalized
	TypeDescriptor byte = 'D' // packed descriptor, DESCRIPTOR.md
)

// Formats, the first byte of every share.
const (
	formatSealed = 0x01
	formatOpen   = 0x02
)

const (
	keyLen   = 32
	idLen    = 16
	checkLen = 4
	hdrLen   = 3 + idLen

	// maxSealed is the length of one ChaCha20 stream, which bounds the
	// sealed payload.
	maxSealed = 1 << 38

	// maxSubsets bounds the lexicographic part of the search Combine
	// makes when it holds spare shares and the first k do not verify.
	maxSubsets = 1024

	// maxWork bounds the whole of that search, runs included, in field
	// multiplications (see fits), whatever k and the length of the shares
	// are: about a second of work.
	maxWork = 1 << 27
)

// Errors returned by Combine, ShareAt, Audit, ParseHeader and Group,
// possibly wrapped. Test for them with errors.Is.
var (
	ErrShare    = errors.New("shaqr: malformed share")
	ErrCheck    = errors.New("shaqr: share check failed")
	ErrVersion  = errors.New("shaqr: share made by another version")
	ErrDisputed = errors.New("shaqr: different shares with the same x")
	ErrSet      = errors.New("shaqr: shares are not one set")
	ErrTooFew   = errors.New("shaqr: not enough shares")
	ErrID       = errors.New("shaqr: set id does not match")
	ErrPadding  = errors.New("shaqr: bad padding")
)

// A Splitter makes share sets. The zero value makes sealed session sets
// with r from crypto/rand and no padding.
type Splitter struct {
	// Rand supplies the 32 bytes of r. Nil means crypto/rand.Reader on a
	// host; a bare-metal build has no default and needs one set here.
	// Derived and open sets read nothing from it.
	Rand io.Reader

	// Derived makes a derived set: r is empty, and the set is a function
	// of the content type, the payload and k, so that it can be made
	// again later. Anyone with one share can then test guesses at the
	// payload. Use it only for payloads with at least 128 bits an
	// attacker cannot know.
	Derived bool

	// MinLen pads the sealed payload to at least this many bytes, to
	// hide the length of short secrets. A derived or open set gets no
	// padding beyond what sealing needs, so Derived or Open with MinLen
	// above 0 is an error, and so is a MinLen below 0 or above 2^38, the
	// length of one ChaCha20 stream.
	MinLen int

	// Open makes an open set: no key and no encryption, so that every
	// share is 32 bytes shorter and shows part of the payload. Use it
	// only for data that must survive lost shares and need not stay
	// private. An open set is a function of the content type, the
	// payload and k. It has no r, so Open with Derived is an error.
	Open bool
}

// Split calls Split on a zero Splitter.
func Split(payload []byte, typ byte, k, n int) ([][]byte, error) {
	return new(Splitter).Split(payload, typ, k, n)
}

// Split returns n shares of payload, any k of which recover it. Share
// i of the result has index x = i+1. Before it returns, Split reads
// every share back from its text and recovers the payload from the k
// shares with the highest x (SPEC.md, Splitting, step 6), so a fault in
// the computation gives an error and no shares.
func (s *Splitter) Split(payload []byte, typ byte, k, n int) ([][]byte, error) {
	if k < 2 || k > n || n > 255 {
		return nil, fmt.Errorf("shaqr: invalid threshold %d of %d", k, n)
	}
	if err := s.options(); err != nil {
		return nil, err
	}
	size := sealedLen(len(payload), k, s.MinLen)
	if size > maxSealed {
		return nil, fmt.Errorf("shaqr: %d sealed bytes exceed one ChaCha20 stream", size)
	}
	if size > math.MaxInt {
		return nil, fmt.Errorf("shaqr: %d sealed bytes are too many for this platform", size)
	}
	r, err := s.random()
	if err != nil {
		return nil, err
	}

	sealed := seal(typ, payload, size)
	var shares [][]byte
	if s.Open {
		shares = build(k, n, nil, sealed)
	} else {
		seed, take := drawTake(r, k, sealed)
		// take holds S and the R_i. The keystream under S turns into C
		// in place (see crypt). What Go cannot erase is listed at erase.
		defer erase(r, seed, take, sealed)
		shares = build(k, n, take, crypt(take[:keyLen], sealed))
	}
	if err := verify(shares, typ, payload, k); err != nil {
		return nil, fmt.Errorf("shaqr: the new set fails its own check: %w", err)
	}
	return shares, nil
}

// options reports fields of s that contradict each other or SPEC.md.
func (s *Splitter) options() error {
	switch {
	case s.Open && s.Derived:
		return errors.New("shaqr: an open set has no r and is not derived")
	case s.Open && s.MinLen > 0:
		return errors.New("shaqr: an open set takes no padding")
	case s.Derived && s.MinLen > 0:
		return errors.New("shaqr: a derived set takes no padding")
	case s.MinLen < 0 || int64(s.MinLen) > maxSealed:
		return fmt.Errorf("shaqr: invalid MinLen %d", s.MinLen)
	}
	return nil
}

// random returns r: nothing for a derived or open set, else 32 bytes from
// s.Rand.
// defaultRand is the source of r when Splitter.Rand is nil. rand_default.go
// sets it on hosts; it stays nil on bare metal.
var defaultRand io.Reader

func (s *Splitter) random() ([]byte, error) {
	if s.Derived || s.Open {
		return nil, nil
	}
	src := s.Rand
	if src == nil {
		src = defaultRand
	}
	if src == nil {
		return nil, errors.New("shaqr: no random source for a session set: set Splitter.Rand")
	}
	r := make([]byte, 32)
	if _, err := io.ReadFull(src, r); err != nil {
		return nil, fmt.Errorf("shaqr: reading randomness: %w", err)
	}
	return r, nil
}

// drawTake is step 2 of splitting: it returns the seed and take, the key
// polynomial at 0 .. k-1, for r, k and the sealed payload.
func drawTake(r []byte, k int, sealed []byte) (seed, take []byte) {
	seed = mac([]byte("shaQR v1 seed"), []byte{byte(len(r))}, r, []byte{byte(k)}, sealed)
	return seed, stream(seed, keyLen*k)
}

// build computes the set id and shares 1 to n from take, the key
// polynomial at 0 .. k-1, and C (SPEC.md, Splitting, steps 4 and 5).
// take is empty only in an open set, whose C is sealed itself and whose
// shares have no key part.
func build(k, n int, take, c []byte) [][]byte {
	format := byte(formatSealed)
	if len(take) == 0 {
		format = formatOpen
	}
	id := setID(format, k, take, c)
	kp, b := keyPart(format), len(c)/k
	keyXs, keyYs := make([]byte, k), make([][]byte, k)
	dataXs, dataYs := make([]byte, k), make([][]byte, k)
	for i := range k {
		keyXs[i], keyYs[i] = byte(i), take[kp*i:kp*(i+1)]
		dataXs[i], dataYs[i] = byte(i+1), c[b*i:b*(i+1)]
	}
	shares := make([][]byte, n)
	for i := range shares {
		x := byte(i + 1)
		sh := header(format, byte(k), x, id, kp+b)
		if kp > 0 {
			sh = interp(sh, keyXs, keyYs, x)
		}
		sh = interp(sh, dataXs, dataYs, x)
		shares[i] = append(sh, check(sh)...)
	}
	return shares
}

// header starts a share with format, k, x and id, and leaves room for a
// body of bodyLen bytes and the check.
func header(format, k, x byte, id []byte, bodyLen int) []byte {
	sh := make([]byte, 0, hdrLen+bodyLen+checkLen)
	sh = append(sh, format, k, x)
	return append(sh, id...)
}

// keyPart returns the length of the key part of a share of the given
// format: keyLen in a sealed set, nothing in an open one.
func keyPart(format byte) int {
	if format == formatOpen {
		return 0
	}
	return keyLen
}

// minShare returns the length of the shortest share of the given format:
// header, key part, one byte of data and check.
func minShare(format byte) int {
	return hdrLen + keyPart(format) + 1 + checkLen
}

// verify is step 6 of splitting. A fault in the code that made the
// shares also made their check and id, so only a recovery exposes it:
// verify reads every share back from its text, recovers the payload
// from the k shares with the highest x, and compares every share byte
// for byte with what the recovered polynomials give at its x.
func verify(shares [][]byte, typ byte, payload []byte, k int) error {
	var text strings.Builder
	for _, sh := range shares {
		text.WriteString(Encode(sh) + "\n")
	}
	read, rejected := Decode(text.String())
	if len(rejected) > 0 || len(read) != len(shares) {
		return errors.New("the shares do not survive their text form")
	}
	for i := range read {
		if subtle.ConstantTimeCompare(read[i], shares[i]) != 1 {
			return fmt.Errorf("share %d does not survive its text form", i+1)
		}
	}

	s, err := newSet(read[len(read)-k:])
	if err != nil {
		return err
	}
	sol, err := s.solve()
	if err != nil {
		return err
	}
	sealed := s.decrypt(sol)
	defer erase(sol.take, sealed)
	gotTyp, got, err := unseal(sealed)
	if err != nil {
		return err
	}
	if gotTyp != typ || subtle.ConstantTimeCompare(got, payload) != 1 {
		return errors.New("the recovered payload differs from the input")
	}
	for i, sh := range shares {
		if subtle.ConstantTimeCompare(s.at(sol.idx, byte(i+1)), sh) != 1 {
			return fmt.Errorf("share %d is off the recovered polynomials", i+1)
		}
	}
	return nil
}

// Combine recovers the content type and payload from k or more shares
// of one set. Every share must pass step 1 of recovering, and the result
// must match the set id, or Combine returns an error and no data. Shares
// of more than one set are an error too. Group sorts them out beforehand.
//
// Exact copies of a share count once. Where two or more different shares
// have the same x, Combine leaves that x out and goes on if k other x
// values remain. When fewer remain, SPEC.md allows a receiver to try the
// disputed shares in turn; Combine does not, and reports a TooFewError,
// which says which x values it holds and which are disputed.
//
// Given spare shares, Combine survives shares that pass their check and
// are wrong all the same: it tries runs of k consecutive shares, then
// k-subsets in lexicographic order, runs included, up to 1024 of them,
// until one matches the id. The whole search stops at a bound on its
// work of about a second, so with a large k and long shares it tries
// fewer, down to the first run alone, and reports ErrID, wrapped to say
// that it stopped. Audit names the wrong shares.
func Combine(shares [][]byte) (typ byte, payload []byte, err error) {
	s, err := newSet(shares)
	if err != nil {
		return 0, nil, err
	}
	sol, err := s.solve()
	if err != nil {
		return 0, nil, err
	}
	defer erase(sol.take)
	return unseal(s.decrypt(sol))
}

// ShareAt returns the share with index x of the set the given shares
// belong to. It needs k shares that pass the id, and it does not decrypt:
// a set whose payload fails unsealing still gives shares, which recover to
// the same error. The caller holds a quorum and should treat the occasion
// like a recovery. ShareAt replaces a lost share or adds one.
func ShareAt(shares [][]byte, x int) ([]byte, error) {
	if x < 1 || x > 255 {
		return nil, fmt.Errorf("shaqr: invalid share index %d", x)
	}
	s, err := newSet(shares)
	if err != nil {
		return nil, err
	}
	sol, err := s.solve()
	if err != nil {
		return nil, err
	}
	defer erase(sol.take)
	return s.at(sol.idx, byte(x)), nil
}

// Audit returns, in ascending order, the x of every given share that is
// off the set's polynomials, a disputed x included when a share held at
// it is off. It needs k shares that pass the id, as Combine does, and
// finds nothing to compare unless it has more. The id commits to take
// and C, which fix the key polynomial and the data polynomial, so the
// blame is right whenever the id passes.
func Audit(shares [][]byte) ([]int, error) {
	s, err := newSet(shares)
	if err != nil {
		return nil, err
	}
	sol, err := s.solve()
	if err != nil {
		return nil, err
	}
	defer erase(sol.take)
	var bad []int
	for _, sh := range slices.Concat(s.shares, s.disputed) {
		if subtle.ConstantTimeCompare(s.at(sol.idx, sh.x), sh.raw) != 1 && !slices.Contains(bad, int(sh.x)) {
			bad = append(bad, int(sh.x))
		}
	}
	slices.Sort(bad)
	return bad, nil
}

// Rejected reports a share that Group found fault with: its position in
// the input and the reason, which wraps ErrCheck, ErrVersion, ErrShare
// or ErrDisputed.
type Rejected struct {
	Index int
	Err   error
}

// Group sorts shares into sets by format, k, id and length, in order of
// first appearance (SPEC.md, Recovering, steps 1 to 3). Shares of
// different sets are never combined, so a share scanned from the wrong
// plate lands in a set of its own and spoils nothing.
//
// A share that fails step 1 is rejected and joins no set. Where a set
// holds two or more different shares with the same x, each of them is
// rejected with ErrDisputed and stays in its set all the same: Combine
// leaves that x out, and can then say how many other x values remain.
// rejected is in input order. A set may hold fewer than k shares, which
// Combine reports.
func Group(shares [][]byte) (sets [][][]byte, rejected []Rejected) {
	type key struct {
		format, k byte
		id        [idLen]byte
		len       int
	}
	index := make(map[key]int)
	var groups [][]share
	var where [][]int // input positions of the shares in groups
	for i, raw := range shares {
		sh, err := parse(raw)
		if err != nil {
			rejected = append(rejected, Rejected{i, err})
			continue
		}
		g := key{sh.format, sh.k, [idLen]byte(sh.id), len(raw)}
		j, ok := index[g]
		if !ok {
			j = len(groups)
			index[g] = j
			groups = append(groups, nil)
			where = append(where, nil)
		}
		groups[j] = append(groups[j], sh)
		where[j] = append(where[j], i)
	}

	for j, g := range groups {
		bad := disputed(g)
		set := make([][]byte, len(g))
		for i, sh := range g {
			set[i] = sh.raw
			if bad[sh.x] {
				err := fmt.Errorf("%w: x = %d of set %s", ErrDisputed, sh.x, tag(sh.id))
				rejected = append(rejected, Rejected{where[j][i], err})
			}
		}
		sets = append(sets, set)
	}
	slices.SortFunc(rejected, func(a, b Rejected) int { return cmp.Compare(a.Index, b.Index) })
	return sets, rejected
}

// A Header is the public part of a share. Open reports a share of an
// open set, whose format byte is 0x02.
type Header struct {
	Open bool
	K, X int
	ID   [idLen]byte
}

// Tag returns the tag of the share's set, "#" and the first two bytes of
// the id in upper-case hex, as in #B962. Tools use it to label shares
// and to name sets.
func (h Header) Tag() string {
	return tag(h.ID[:])
}

// ParseHeader verifies a share as step 1 of recovering does and returns
// its header.
func ParseHeader(raw []byte) (Header, error) {
	sh, err := parse(raw)
	if err != nil {
		return Header{}, err
	}
	return Header{Open: sh.format == formatOpen, K: int(sh.k), X: int(sh.x), ID: [idLen]byte(sh.id)}, nil
}

// A share is a share that passed step 1 of recovering.
type share struct {
	format, k, x byte
	id           []byte
	body         []byte // key part, if any, then data part
	raw          []byte
}

// parse is step 1 of recovering for one decoded share: check first, then
// the format, then the fields that no share of its format can have.
func parse(raw []byte) (share, error) {
	n := len(raw) - checkLen
	if n < 0 {
		return share{}, fmt.Errorf("%w: %d bytes cannot hold one", ErrCheck, len(raw))
	}
	if subtle.ConstantTimeCompare(check(raw[:n]), raw[n:]) != 1 {
		return share{}, ErrCheck
	}
	if n > 0 && raw[0] != formatSealed && raw[0] != formatOpen {
		return share{}, fmt.Errorf("%w: format %d", ErrVersion, raw[0])
	}
	// A check alone is shorter than a share of either format.
	if len(raw) < minShare(raw[0]) {
		return share{}, fmt.Errorf("%w: %d bytes", ErrShare, len(raw))
	}
	sh := share{format: raw[0], k: raw[1], x: raw[2], id: raw[3:hdrLen], body: raw[hdrLen:n], raw: raw}
	if sh.k < 2 {
		return share{}, fmt.Errorf("%w: k = %d", ErrShare, sh.k)
	}
	if sh.x == 0 {
		return share{}, fmt.Errorf("%w: x = 0", ErrShare)
	}
	return sh, nil
}

// disputed returns the x values at which shares holds two or more
// different shares.
func disputed(shares []share) map[byte]bool {
	first := make(map[byte][]byte)
	bad := make(map[byte]bool)
	for _, sh := range shares {
		prev, ok := first[sh.x]
		switch {
		case !ok:
			first[sh.x] = sh.raw
		case subtle.ConstantTimeCompare(prev, sh.raw) != 1:
			bad[sh.x] = true
		}
	}
	return bad
}

// A set holds the shares of one set that recovery may use, one for each
// undisputed x and in order of x, and apart from them every share held
// at a disputed x.
type set struct {
	format, k byte
	id        []byte
	bodyLen   int
	shares    []share
	disputed  []share
}

// A TooFewError reports a set that holds fewer than k undisputed x
// values (SPEC.md, Recovering, steps 2 and 3). It wraps ErrTooFew, and
// its message is the one Combine has always given, as in "shaqr: not
// enough shares: 1 of 2".
type TooFewError struct {
	K        int   // the threshold of the set
	Held     []int // the undisputed x values held, in ascending order
	Disputed []int // the disputed x values, in ascending order
}

func (e *TooFewError) Error() string {
	msg := fmt.Sprintf("%v: %d of %d", ErrTooFew, len(e.Held), e.K)
	if len(e.Disputed) > 0 {
		msg += fmt.Sprintf(", not counting %d disputed x", len(e.Disputed))
	}
	return msg
}

func (e *TooFewError) Unwrap() error { return ErrTooFew }

// newSet parses shares that should all belong to one set and prepares
// them for recovery (SPEC.md, Recovering, steps 1 to 3). It verifies
// every share, step 1, before it compares them, step 2, so a damaged
// share is reported as damaged wherever it stands.
func newSet(raws [][]byte) (*set, error) {
	if len(raws) == 0 {
		return nil, ErrTooFew
	}
	all := make([]share, len(raws))
	for i, raw := range raws {
		sh, err := parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%w (share %d of %d)", err, i+1, len(raws))
		}
		all[i] = sh
	}
	for _, sh := range all[1:] {
		if sh.format != all[0].format || sh.k != all[0].k || !bytes.Equal(sh.id, all[0].id) || len(sh.raw) != len(all[0].raw) {
			return nil, ErrSet
		}
	}

	s := &set{format: all[0].format, k: all[0].k, id: all[0].id, bodyLen: len(all[0].body)}
	bad := disputed(all)
	held := make(map[byte]bool)
	for _, sh := range all {
		switch {
		case bad[sh.x]:
			s.disputed = append(s.disputed, sh)
		case !held[sh.x]:
			held[sh.x] = true
			s.shares = append(s.shares, sh)
		}
	}
	if len(s.shares) < int(s.k) {
		e := &TooFewError{K: int(s.k)}
		for _, sh := range s.shares {
			e.Held = append(e.Held, int(sh.x))
		}
		for x := range bad {
			e.Disputed = append(e.Disputed, int(x))
		}
		slices.Sort(e.Held)
		slices.Sort(e.Disputed)
		return nil, e
	}
	slices.SortFunc(s.shares, func(a, b share) int { return cmp.Compare(a.x, b.x) })
	return s, nil
}

// points returns the interpolation points that the shares picked by idx
// give for bytes lo to hi of the body.
func (s *set) points(idx []int, lo, hi int) (xs []byte, ys [][]byte) {
	for _, i := range idx {
		xs = append(xs, s.shares[i].x)
		ys = append(ys, s.shares[i].body[lo:hi])
	}
	return xs, ys
}

// at returns the share at x of the polynomials through the shares
// picked by idx.
func (s *set) at(idx []int, x byte) []byte {
	xs, ys := s.points(idx, 0, s.bodyLen)
	sh := header(s.format, s.k, x, s.id, s.bodyLen)
	sh = interp(sh, xs, ys, x)
	return append(sh, check(sh)...)
}

// A solution is what k shares of a set give: take, the key polynomial
// at 0 .. k-1, which is empty in an open set, C, and the positions in
// set.shares of the shares that gave them.
type solution struct {
	take, c []byte
	idx     []int
}

// solve finds k shares whose key polynomial and C match the set id
// (SPEC.md, Recovering, steps 4 and 5). It tries the k-subsets that
// candidates yields, in order, until their work reaches maxWork; it
// always tries the first. When the bound stops it early, the ErrID it
// returns says so.
func (s *set) solve() (*solution, error) {
	k, kp := int(s.k), keyPart(s.format)
	sol := &solution{
		take: make([]byte, 0, kp*k),
		c:    make([]byte, 0, (s.bodyLen-kp)*k),
		idx:  make([]int, k),
	}
	tried, work := 0, int64(0)
	for idx := range candidates(k, len(s.shares)) {
		if work >= maxWork {
			erase(sol.take)
			return nil, fmt.Errorf("%w: the search stopped after %d subsets, at its bound on work", ErrID, tried)
		}
		tried++
		copy(sol.idx, idx)
		ok, w := s.fits(sol)
		if ok {
			return sol, nil
		}
		work += w
	}
	erase(sol.take)
	return nil, ErrID
}

// candidates yields the k-subsets of the positions 0 .. m-1 that solve
// tries, in order. First comes every run of k consecutive positions,
// wrapping around, starting with the k lowest x. A run that avoids the
// wrong shares exists whenever they sit next to each other and number no
// more than the spares, which covers one wrong share at any k. Then come
// k-subsets in lexicographic order, runs included, up to maxSubsets of
// them. It yields the same slice each time.
func candidates(k, m int) iter.Seq[[]int] {
	return func(yield func([]int) bool) {
		idx := make([]int, k)
		runs := m
		if m == k {
			runs = 1
		}
		for start := range runs {
			for i := range idx {
				idx[i] = (start + i) % m
			}
			if !yield(idx) {
				return
			}
		}
		for i := range idx {
			idx[i] = i
		}
		for tries := 0; tries < maxSubsets && next(idx, m); tries++ {
			if !yield(idx) {
				return
			}
		}
	}
}

// fits interpolates take and c from the shares at sol.idx and reports
// whether they match the set id, and roughly how many field
// multiplications that took: k*k for the denominators of the basis and
// 12 for each of its k inverses, up to 14k for the weights at each
// target, and one per byte for every nonzero weight. A target that is
// one of the held x values has one nonzero weight and any other has k,
// so a subset costs up to about k*k*bodyLen. An open set has no key
// part, and its take stays empty.
func (s *set) fits(sol *solution) (ok bool, work int64) {
	k, kp := int(s.k), keyPart(s.format)
	xs, keys := s.points(sol.idx, 0, kp)
	_, data := s.points(sol.idx, kp, s.bodyLen)
	b := newBasis(xs)
	// work counts in int64, since k*k*bodyLen can pass 2^31.
	work = int64(k * (k + 12))
	sol.take = sol.take[:0]
	sol.c = sol.c[:0]
	if kp > 0 {
		for i := range k {
			w := b.weights(byte(i))
			sol.take = apply(sol.take, w, keys)
			work += int64(14*k + nonzero(w)*kp)
		}
	}
	for i := 1; i <= k; i++ {
		w := b.weights(byte(i))
		sol.c = apply(sol.c, w, data)
		work += int64(14*k) + int64(nonzero(w))*int64(s.bodyLen-kp)
	}
	return subtle.ConstantTimeCompare(setID(s.format, k, sol.take, sol.c), s.id) == 1, work
}

// decrypt returns sealed from what solve found: C decrypted under S in a
// sealed set, and C as it stands in an open one (SPEC.md, Recovering,
// step 6).
func (s *set) decrypt(sol *solution) []byte {
	if s.format == formatOpen {
		return sol.c
	}
	return crypt(sol.take[:keyLen], sol.c)
}

// nonzero counts the nonzero weights in w.
func nonzero(w []byte) int {
	n := 0
	for _, wi := range w {
		if wi != 0 {
			n++
		}
	}
	return n
}

// next advances idx to the following k-subset of 0..n-1 in
// lexicographic order and reports whether there was one.
func next(idx []int, n int) bool {
	k := len(idx)
	for i := k - 1; i >= 0; i-- {
		if idx[i] < n-k+i {
			idx[i]++
			for j := i + 1; j < k; j++ {
				idx[j] = idx[j-1] + 1
			}
			return true
		}
	}
	return false
}

// sealedLen returns L, the length of the sealed payload: the payload and
// two bytes, at least minLen, rounded up to a multiple of k. It counts in
// int64, so that a minLen up to 2^38 cannot overflow it on any platform.
func sealedLen(payload, k, minLen int) int64 {
	n := max(int64(payload)+2, int64(minLen))
	return n + (int64(k)-n%int64(k))%int64(k)
}

// seal returns T ‖ payload ‖ 0x80 followed by zero bytes up to size
// (SPEC.md, Splitting, step 1).
func seal(typ byte, payload []byte, size int64) []byte {
	s := make([]byte, size)
	s[0] = typ
	copy(s[1:], payload)
	s[1+len(payload)] = 0x80
	return s
}

// unseal strips trailing zero bytes and one 0x80 and splits off the
// content type (SPEC.md, Recovering, step 6).
func unseal(s []byte) (typ byte, payload []byte, err error) {
	s = bytes.TrimRight(s, "\x00")
	if len(s) == 0 || s[len(s)-1] != 0x80 {
		return 0, nil, fmt.Errorf("%w: no 0x80 after the payload", ErrPadding)
	}
	if len(s) == 1 {
		return 0, nil, fmt.Errorf("%w: nothing before the 0x80", ErrPadding)
	}
	return s[0], s[1 : len(s)-1], nil
}

// stream returns the first n bytes of the ChaCha20 keystream for a 32
// byte key, a nonce of 12 zero bytes and block counter 0, 1, 2, ...
// (RFC 8439, section 2.4). The nonce can stay fixed because no key
// encrypts more than one message.
func stream(key []byte, n int) []byte {
	c, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
	if err != nil {
		panic(err) // every key here is 32 bytes
	}
	out := make([]byte, n)
	c.XORKeyStream(out, out)
	return out
}

// crypt returns data XOR stream(key, len(data)), which encrypts and
// decrypts alike. The keystream turns into the result in place. The
// x/crypto Cipher, which Go cannot erase, keeps the key and its last
// keystream block.
func crypt(key, data []byte) []byte {
	out := stream(key, len(data))
	subtle.XORBytes(out, out, data)
	return out
}

// setID is step 4 of splitting. take is the key polynomial at 0 .. k-1,
// so the id commits to the whole key polynomial and not only to S. In an
// open set take is empty.
func setID(format byte, k int, take, c []byte) []byte {
	h := sha256.New()
	h.Write([]byte("shaQR v1 id"))
	h.Write([]byte{format, byte(k)})
	h.Write(take)
	h.Write(c)
	return h.Sum(nil)[:idLen]
}

func check(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte("shaQR v1 check"))
	h.Write(b)
	return h.Sum(nil)[:checkLen]
}

func mac(key []byte, msg ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, m := range msg {
		h.Write(m)
	}
	return h.Sum(nil)
}

// tag names the set with the given id: "#" and the first two bytes of
// the id as four upper-case hex digits.
func tag(id []byte) string {
	return fmt.Sprintf("#%02X%02X", id[0], id[1])
}

// erase zeroes secrets once they are no longer needed. Go cannot promise
// more: the garbage collector may have copied them, the ChaCha20 state
// keeps its key and its last keystream block, and the SHA-256 and HMAC
// states keep the last partial block of what they hashed, which in mac
// is the tail of sealed.
func erase(secrets ...[]byte) {
	for _, s := range secrets {
		clear(s)
	}
}
