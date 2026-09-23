// SPDX-License-Identifier: CC0-1.0

package shaqr

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const prefix = "SHAQR:"

// ErrText reports text after SHAQR: that does not decode as a share.
var ErrText = errors.New("shaqr: malformed text")

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Encode returns the text form of a share: the prefix and the share in
// upper-case base32 with no padding and no white space. Every character
// is in the QR alphanumeric set.
func Encode(share []byte) string {
	return prefix + b32.EncodeToString(share)
}

// Decode finds every share in text, which may hold shares of any number
// of sets beside labels and other text, and decodes it (SPEC.md, Text
// form). Case does not matter, in the prefix either; only ASCII letters
// change case. A share starts after SHAQR: and runs to the next SHAQR:,
// to the first character that is neither base32 nor white space, or to
// the end of text. White space inside a share is deleted, and text
// outside shares is ignored. White space is any character with the
// Unicode White_Space property, as unicode.IsSpace has it: the ASCII
// white space, the non-breaking space that pasted text can carry, the
// ideographic space and the others.
//
// A share whose text does not decode goes into rejected, as an error that
// wraps ErrText and gives its line, and the other shares are decoded all
// the same. Decode does not verify checks: Group, Combine and ParseHeader
// do. Scan says where it found each share.
func Decode(text string) (shares [][]byte, rejected []error) {
	for _, f := range Scan(text) {
		if f.Err != nil {
			rejected = append(rejected, f.Err)
			continue
		}
		shares = append(shares, f.Share)
	}
	return shares, rejected
}

// A Found is a share as Scan found it in a text, and where.
type Found struct {
	Share []byte // the share, or nil when its text does not decode
	Err   error  // why its text does not decode, wrapping ErrText
	Line  int    // the line its SHAQR: is on, counting from 1

	// Stop is the character, neither base32 nor white space, that ended
	// the share, or 0 when the next SHAQR: or the end of the text did.
	// EndLine is the line of whichever ended it.
	Stop    rune
	EndLine int
}

// Scan finds the shares in text and decodes them as Decode does, in
// order, and says where it found each, so that a tool can name the line
// of a share that does not decode or fails its check, and the character
// that cut it short. Lines are counted by line feeds.
func Scan(text string) []Found {
	up := upper(text)
	starts := indexAll(up, prefix)
	found := make([]Found, len(starts))
	line, counted := 1, 0
	for n, p := range starts {
		end := len(up)
		if n+1 < len(starts) {
			end = starts[n+1]
		}
		line += strings.Count(up[counted:p], "\n")
		counted = p
		body := p + len(prefix)
		chars, stop := cut(up[body:end])
		f := &found[n]
		f.Line = line
		f.EndLine = line + strings.Count(up[p:body+stop], "\n")
		upTo := ""
		if body+stop < end {
			f.Stop, _ = utf8.DecodeRuneInString(up[body+stop:])
			upTo = fmt.Sprintf(" up to %q on line %d", f.Stop, f.EndLine)
		}
		switch len(chars) % 8 {
		case 1, 3, 6:
			f.Err = fmt.Errorf("%w: the share on line %d: %d characters%s, a length that base32 does not produce", ErrText, line, len(chars), upTo)
			continue
		}
		raw, err := b32.DecodeString(string(chars))
		if err != nil {
			f.Err = fmt.Errorf("%w: the share on line %d: %v", ErrText, line, err)
			continue
		}
		f.Share = raw
	}
	return found
}

// cut returns the base32 characters of the share at the start of s, with
// white space deleted, and the byte offset at which the share ends. s is
// in upper case and holds no other share. A byte that is not UTF-8 ends
// the share, as any other character outside base32 and white space does.
func cut(s string) (chars []byte, end int) {
	for i, r := range s {
		switch {
		case 'A' <= r && r <= 'Z', '2' <= r && r <= '7':
			chars = append(chars, byte(r))
		case !unicode.IsSpace(r):
			return chars, i
		}
	}
	return chars, len(s)
}

// upper returns s with ASCII letters in upper case and every other byte
// as it was, so that byte offsets into s still hold, whatever characters
// outside ASCII s holds.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// indexAll returns the offsets of the non-overlapping instances of sub
// in s.
func indexAll(s, sub string) []int {
	var at []int
	for i := 0; ; i += len(sub) {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return at
		}
		i += j
		at = append(at, i)
	}
}
