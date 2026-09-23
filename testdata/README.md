# Test vectors

The Go tests write both files (README.md in the directory above says how),
and the Go and JavaScript tests read them. Another implementation can run
them the same way. Bytes are in lower-case hex, and every character outside
ASCII in a JSON string is escaped, so that no invisible character hides in
a file.

## vectors.json

One object with the lists `valid`, `invalid` and `text`. A content type is
its one character, as `U`.

`valid` lists sets to rebuild from their inputs, text for text.

```
name          what the case shows
payload_hex   the payload
type          the content type T
format        "sealed" or "open"
k, n          threshold and share count
r_hex         r of a session set, 32 bytes; empty for a derived set and
              for an open set
pad_to        the least L, the length of sealed (SPEC.md Padding), or 0
              for none; only session sets have one
id_hex, tag   the id of the set and its tag
shares        the text of shares 1 to n
```

Any k of the shares recover the payload. The payload of a set of type D is
a descriptor packed as DESCRIPTOR.md describes.

`invalid` lists text for a receiver to recover from: `name`, `text` and
`expect`. `expect.recovered` lists what the sets in the text give, each as
`type` and `payload_hex`, in order of the first share of each set.
`expect.rejected` lists what the receiver reports, one word per report.
The list is sorted and is compared as a multiset: sort your own list
before you compare it.

```
not-decoded    a share whose text does not decode (SPEC.md Text form)
check          a share that fails check, or is too short to hold one
               (Recovering, step 1)
other-version  a share whose check matches and whose format is neither
               0x01 nor 0x02
malformed      a check alone, a sealed share shorter than 56 bytes or an
               open one shorter than 24, or a share with x = 0 or k below 2
disputed       an x at which a set holds two or more different shares,
               reported once for each x
too-few        a set with fewer than k undisputed x values
id             a set in which no k shares match the id
padding        a set that passes the id and fails step 6 of Recovering
bad-share      an x at which a held share of a recovered set is off the
               set's polynomials, a disputed x included (Finding a bad
               share)
```

The cases with spare shares expect a receiver that searches for k shares
that pass the id and then names every held share off the set. No case
depends on trying the shares of a disputed x in turn, which SPEC.md leaves
to the receiver.

`text` lists input for the text form alone: `name`, `input`, and what a
receiver reads from it. `shares_hex` holds the shares that decode, in
order, whether or not their check matches, and `rejected` is the number of
shares whose text does not decode.

## descriptors.json

One object with the lists `canonical`, `quorum`, `pack` and `unpack`.

`canonical` lists a `name` and an `input` for DESCRIPTOR.md Canonical form.
The input gives either `canonical`, its canonical form with the checksum,
and `packed`, the packed payload of that text, or `error`: `checksum` for
a checksum that does not match and `invalid` for any other refusal.

`quorum` lists a `name` and an `input`. `ok` says whether the descriptor has
a single multi, sortedmulti, multi_a or sortedmulti_a that holds every key
(DESCRIPTOR.md Threshold). If it does, `k` is its threshold, `n` its number
of keys, and `fingerprints` the origin fingerprint of each of its keys in
order, in lower case, or "" for a key without one. If not, `k` and `n` are
0 and there are no fingerprints.

`pack` lists a `name` and a `text` in canonical form with its checksum, and
either `packed`, its packed payload, or `error`: `invalid` for a text longer
than eight times its packed bytes plus 64.

`unpack` lists a `name` and bytes, `packed`, that a receiver refuses, and
the `error`: `not-packed` for bytes that unpack to a text that packs to
other bytes, and `invalid` for bytes that do not unpack, or whose text
passes eight times their length plus 64.
