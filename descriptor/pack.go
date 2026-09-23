// SPDX-License-Identifier: CC0-1.0

package descriptor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ErrNotPacked reports bytes that unpack to a descriptor but are not
// the packed form of it, since Pack gives other bytes for that text.
var ErrNotPacked = errors.New("descriptor: not the packed form of its descriptor")

var (
	errTruncated = errors.New("descriptor: packed token truncated")
	errNumber    = errors.New("descriptor: packed number not below 2^32 in five bytes")
	errNoOrigin  = errors.New("descriptor: packed token needs an origin token before it")
)

// The markers that start the tokens of a packed descriptor. A key
// token has the marker markKey + 4 * kind + 2 * implied + parity.
const (
	markKey      = 0x80
	markGeneric  = 0x90 // any other extended key, all 78 bytes
	markOrigin   = 0x91 // fingerprint, number of steps, steps
	markSamePath = 0x92 // fingerprint, and the steps of the last origin token
	markChildren = 0x93 // the children /<0;1>/*
	markHex32    = 0x94 // a hex key of 32 bytes
	markHex33    = 0x95 // a hex key of 33 bytes
)

// multipath is the text that markChildren stands for.
const multipath = "/<0;1>/*"

// versions are the BIP 32 versions of the four kinds of key token:
// xpub and tpub, whose keys are public, and xprv and tprv.
var versions = [4]uint32{0x0488B21E, 0x043587CF, 0x0488ADE4, 0x04358394}

// The offsets of the fields of the 78 bytes of an extended key: version
// (4), depth (1), parent fingerprint (4), child number (4), chain code
// (32) and key (33).
const (
	offDepth    = 4
	offParent   = 5
	offChild    = 9
	offChain    = 13
	offKey      = 45
	extendedLen = 78
)

// Pack returns the packed payload of a descriptor backup (DESCRIPTOR.md
// Packed payload) from a descriptor with its checksum, as Canonical
// returns it. Key origins, extended keys, hex keys and the children
// /<0;1>/* become binary tokens, and the "#" and checksum are dropped.
// Pack verifies the checksum. It does not check that desc is canonical,
// since a receiver packs what it unpacked to check it, and that need not
// be canonical either.
func Pack(desc string) ([]byte, error) {
	if err := Verify(desc); err != nil {
		return nil, err
	}
	return pack(desc[:len(desc)-9]), nil
}

// pack packs s, a descriptor without its "#" and checksum.
func pack(s string) []byte {
	p := packer{originEnd: -1}
	for i := 0; i < len(s); {
		i = p.next(s, i)
	}
	return p.out
}

// A packer writes the tokens of a text to out. steps are those of the
// last origin token, and originEnd is the offset in the text where that
// token ended, or -1 before the first.
type packer struct {
	out       []byte
	steps     []uint32
	originEnd int
}

// next writes the bytes of the first rule of DESCRIPTOR.md that matches
// s at i and returns the offset after the text it matched.
func (p *packer) next(s string, i int) int {
	if fp, steps, n := matchOrigin(s[i:]); n > 0 {
		p.origin(fp, steps)
		p.originEnd = i + n
		return i + n
	}
	if raw, n := matchExtended(s, i); raw != nil {
		p.key(raw, p.originEnd == i)
		return i + n
	}
	if b := matchHex(s, i); b != nil {
		p.out = append(append(p.out, markHex32+byte(len(b)-32)), b...)
		return i + 2*len(b)
	}
	if strings.HasPrefix(s[i:], multipath) {
		p.out = append(p.out, markChildren)
		return i + len(multipath)
	}
	p.out = append(p.out, s[i])
	return i + 1
}

// origin writes an origin token, with markSamePath when the last origin
// token had the same steps.
func (p *packer) origin(fp []byte, steps []uint32) {
	if p.originEnd >= 0 && slices.Equal(steps, p.steps) {
		p.out = append(append(p.out, markSamePath), fp...)
	} else {
		p.out = append(append(p.out, markOrigin), fp...)
		p.out = binary.AppendUvarint(p.out, uint64(len(steps)))
		for _, v := range steps {
			p.out = binary.AppendUvarint(p.out, uint64(v))
		}
	}
	p.steps = steps
}

// key writes the token of the 78 bytes of an extended key. afterOrigin
// is whether an origin token came right before it.
func (p *packer) key(raw []byte, afterOrigin bool) {
	m, ok := keyMarker(raw)
	switch {
	case !ok:
		p.out = append(append(p.out, markGeneric), raw...)
	case afterOrigin && implied(raw, p.steps):
		p.out = append(append(p.out, m+2), raw[offParent:offChild]...)
		p.out = append(append(p.out, raw[offChain:offKey]...), raw[offKey+1:]...)
	default:
		p.out = append(append(p.out, m), raw[offDepth:offKey]...)
		p.out = append(p.out, raw[offKey+1:]...)
	}
}

// keyMarker returns the marker of a key token for raw with the implied
// bit clear. ok is false for a key of another version, or whose first
// key byte does not fit its kind, which packs as markGeneric.
func keyMarker(raw []byte) (marker byte, ok bool) {
	kind := slices.Index(versions[:], binary.BigEndian.Uint32(raw))
	first := raw[offKey]
	switch {
	case (kind == 0 || kind == 1) && (first == 2 || first == 3):
		return markKey + byte(4*kind) + first - 2, true
	case (kind == 2 || kind == 3) && first == 0:
		return markKey + byte(4*kind), true
	}
	return 0, false
}

// implied reports whether the steps of an origin give the depth and the
// child number of an extended key.
func implied(raw []byte, steps []uint32) bool {
	return int(raw[offDepth]) == len(steps) && binary.BigEndian.Uint32(raw[offChild:]) == childNumber(steps)
}

// childNumber returns the BIP 32 child number of the last of steps, its
// index plus 2^31 when it is hardened, or 0 when there are no steps.
func childNumber(steps []uint32) uint32 {
	if len(steps) == 0 {
		return 0
	}
	v := steps[len(steps)-1]
	return v>>1 | v&1<<31
}

// matchOrigin matches rule 1 at the start of s: "[", eight lower-case
// hex digits, any number of steps and "]", where a step is "/", a
// decimal index below 2^31 with no leading zero, and an optional "h".
// It returns the fingerprint, each step as 2 * index + 1 when it has h
// and 2 * index when it does not, and the length of the match, which is
// 0 when there is none.
func matchOrigin(s string) (fp []byte, steps []uint32, n int) {
	if len(s) < 10 || s[0] != '[' || !isLowerHex(s[1:9]) {
		return nil, nil, 0
	}
	i := 9
	for i < len(s) && s[i] == '/' {
		j := i + 1
		for j < len(s) && '0' <= s[j] && s[j] <= '9' {
			j++
		}
		index, err := strconv.ParseUint(s[i+1:j], 10, 31)
		if err != nil || s[i+1] == '0' && j > i+2 {
			return nil, nil, 0
		}
		v := uint32(index) << 1
		if j < len(s) && s[j] == 'h' {
			v, j = v|1, j+1
		}
		steps, i = append(steps, v), j
	}
	if i == len(s) || s[i] != ']' {
		return nil, nil, 0
	}
	fp, _ = hex.DecodeString(s[1:9])
	return fp, steps, i + 1
}

// matchExtended matches rule 2 at s[i]: the base58 characters from
// there to the first that is not base58, where s[i-1] is not base58
// either, when they are the base58check of 78 bytes. It returns those
// bytes and the number of characters.
func matchExtended(s string, i int) ([]byte, int) {
	if i > 0 && isBase58(s[i-1]) {
		return nil, 0
	}
	j := i
	for j < len(s) && isBase58(s[j]) {
		j++
	}
	return decodeExtended(s[i:j]), j - i
}

// matchHex matches rule 3 at s[i]: the lower-case hex digits from there
// to the first character that is not one, where s[i-1] is not one
// either, when there are 64 or 66 of them. It returns their bytes.
func matchHex(s string, i int) []byte {
	if i > 0 && isHexDigit(s[i-1]) {
		return nil
	}
	j := i
	for j < len(s) && isHexDigit(s[j]) {
		j++
	}
	if j-i != 64 && j-i != 66 {
		return nil
	}
	b, _ := hex.DecodeString(s[i:j])
	return b
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// Unpack returns the descriptor with its checksum that a packed payload
// holds (DESCRIPTOR.md Packed payload). It packs that text again and
// returns ErrNotPacked when the bytes differ from packed, so that every
// descriptor has one packed form. Bytes that do not unpack at all give
// another error.
func Unpack(packed []byte) (string, error) {
	u := unpacker{p: packed}
	for u.i < len(packed) {
		if err := u.next(); err != nil {
			return "", err
		}
	}
	s := u.b.String()
	sum, err := Checksum(s)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(pack(s), packed) {
		return "", ErrNotPacked
	}
	return s + "#" + sum, nil
}

// An unpacker reads the tokens of p from offset i and writes their text
// to b. steps are those of the last origin token, haveOrigin is whether
// there was one, and afterOrigin whether it is the token read last.
type unpacker struct {
	p           []byte
	i           int
	b           strings.Builder
	steps       []uint32
	haveOrigin  bool
	afterOrigin bool
}

// next reads one token.
func (u *unpacker) next() error {
	c := u.p[u.i]
	u.i++
	afterOrigin := u.afterOrigin
	u.afterOrigin = false
	switch {
	case c < markKey:
		u.b.WriteByte(c)
	case c < markGeneric:
		return u.key(c, afterOrigin)
	case c == markGeneric:
		raw, err := u.take(extendedLen)
		if err != nil {
			return err
		}
		u.b.WriteString(encodeExtended(raw))
	case c == markOrigin, c == markSamePath:
		return u.origin(c == markSamePath)
	case c == markChildren:
		u.b.WriteString(multipath)
	case c == markHex32, c == markHex33:
		b, err := u.take(32 + int(c-markHex32))
		if err != nil {
			return err
		}
		u.b.WriteString(hex.EncodeToString(b))
	default:
		return errUnused(c)
	}
	return nil
}

func errUnused(marker byte) error {
	return fmt.Errorf("descriptor: unused marker %#x", marker)
}

// take reads the next n bytes.
func (u *unpacker) take(n int) ([]byte, error) {
	if n > len(u.p)-u.i {
		return nil, errTruncated
	}
	u.i += n
	return u.p[u.i-n : u.i], nil
}

// number reads an unsigned LEB128 number below 2^32, which takes at
// most five bytes.
func (u *unpacker) number() (uint32, error) {
	var v uint64
	for shift := 0; shift < 35; shift += 7 {
		b, err := u.take(1)
		if err != nil {
			return 0, err
		}
		v |= uint64(b[0]&0x7f) << shift
		if b[0] < 0x80 {
			if v >= 1<<32 {
				return 0, errNumber
			}
			return uint32(v), nil
		}
	}
	return 0, errNumber
}

// origin reads an origin token and writes it as "[fingerprint/steps]"
// with h. same marks a markSamePath token, which takes the steps of the
// last origin token.
func (u *unpacker) origin(same bool) error {
	fp, err := u.take(4)
	if err != nil {
		return err
	}
	switch {
	case same && !u.haveOrigin:
		return errNoOrigin
	case !same:
		if u.steps, err = u.readSteps(); err != nil {
			return err
		}
	}
	u.haveOrigin, u.afterOrigin = true, true
	u.b.WriteString("[" + hex.EncodeToString(fp))
	for _, v := range u.steps {
		u.b.WriteString("/" + strconv.FormatUint(uint64(v>>1), 10))
		if v&1 != 0 {
			u.b.WriteByte('h')
		}
	}
	u.b.WriteByte(']')
	return nil
}

// readSteps reads the number of steps and the steps of a markOrigin
// token.
func (u *unpacker) readSteps() ([]uint32, error) {
	count, err := u.number()
	if err != nil {
		return nil, err
	}
	// Every step takes a byte, so a count above the bytes left is
	// refused before it allocates.
	if int64(count) > int64(len(u.p)-u.i) {
		return nil, errTruncated
	}
	steps := make([]uint32, count)
	for i := range steps {
		if steps[i], err = u.number(); err != nil {
			return nil, err
		}
	}
	return steps, nil
}

// key reads the key token with marker c and writes the key as
// base58check. afterOrigin is whether an origin token came right before
// it, which gives the depth and child number when the token implies
// them.
func (u *unpacker) key(c byte, afterOrigin bool) error {
	kind, implies, parity := (c-markKey)>>2, c&2 != 0, c&1
	if kind >= 2 && parity == 1 {
		return errUnused(c)
	}
	raw := binary.BigEndian.AppendUint32(make([]byte, 0, extendedLen), versions[kind])
	if implies {
		// A depth is a byte, so no key implies more steps than 255.
		if !afterOrigin || len(u.steps) > 255 {
			return errNoOrigin
		}
		parent, err := u.take(4)
		if err != nil {
			return err
		}
		raw = append(append(raw, byte(len(u.steps))), parent...)
		raw = binary.BigEndian.AppendUint32(raw, childNumber(u.steps))
	} else {
		head, err := u.take(offChain - offDepth)
		if err != nil {
			return err
		}
		raw = append(raw, head...)
	}
	rest, err := u.take(64)
	if err != nil {
		return err
	}
	first := byte(0)
	if kind < 2 {
		first = 2 + parity
	}
	raw = append(append(append(raw, rest[:32]...), first), rest[32:]...)
	u.b.WriteString(encodeExtended(raw))
	return nil
}
