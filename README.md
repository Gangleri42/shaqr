# shaQR

Short secret shares: k-of-n secret sharing where a share is about 1/k the
size of the secret, made to be engraved as QR codes. SPEC.md is the
specification. This is a draft. Nobody has reviewed it. Do not use it with
real secrets.

SPEC.md is at Draft 4, and the code and test vectors here implement it.
Draft 4 adds the open format. Byte 0 of a share names its format: 0x01
for a sealed set, 0x02 for an open one. An open set leaves out the key
and the encryption, so every share is 32 bytes shorter and shows part of
the secret. It suits data that must survive lost plates and need not stay
private. Draft 4 also packs descriptors: content type D holds the
descriptor in the packed form of DESCRIPTOR.md, where key origins,
extended keys, hex keys and the children `/<0;1>/*` are binary tokens.
That makes a descriptor share about a third smaller.

```
SPEC.md                    the specification
DESCRIPTOR.md              profile: multisig descriptor backups on seed plates
DECODING.md                note: Berlekamp-Welch decoding of wrong shares
PIECES.md                  note: one way to carry a share over several codes
*.go                       package shaqr, the core
descriptor/                BIP 380 checksum, canonical form, packing and
                           quorum of a multisig descriptor
cmd/descbackup/            splits a descriptor across seed plates and
                           recovers it
js/                        a second implementation, in JavaScript
testdata/vectors.json      test vectors, valid and invalid
testdata/descriptors.json  canonical and packed forms and quorums of
                           descriptors
testdata/README.md         the fields of both files and the words they use
py/bw_sketch.py            a sketch of the decoder in DECODING.md
site/                      the demo page, https://shaqr.org/
.github/workflows/         the tests, and the Pages deploy of site/
```

Go 1.25, and golang.org/x/crypto for ChaCha20. Nothing else.

```
go test ./...
go test -fuzz FuzzDecode .
cd js && node --test
```

FuzzCombine and FuzzSplitCombine run the same way as FuzzDecode.

Go writes the vectors. `go test -run TestVectors -update` rewrites
testdata/vectors.json from the inputs in vectors_test.go, and
`go test ./descriptor/ -update` rewrites testdata/descriptors.json from
the inputs in descriptor/descriptor_test.go, pack_test.go and
wallets_test.go. testdata/README.md describes both files. Without -update
the Go tests check that both files are exactly what the inputs give,
rebuild every valid set and compare the text of the shares byte for byte.
The JS tests read the same files and check them, so the two
implementations agree. To change the format, change the Go code and its
inputs, rewrite the files and make the JS tests pass again.

Things the Go package does that SPEC.md leaves open: Combine, given more
than k shares, searches for k that pass the id. It tries every run of k
shares next to each other in order of x, wrapping around and starting with
the k lowest x, then k-subsets in lexicographic order, runs included, up to
1024 of them. The whole search stops at about 2^27 multiplications in the
field, a second or so, whatever k and the length of the shares, so with a
large k and long shares it tries fewer subsets, and always the first run.
Combine does not try the shares of a disputed x in turn. Audit names every
held share that is off the polynomials of a set that passed the id.
Multiplication in the field takes the same time for all inputs, and check,
id and shares are compared in constant time. Package descriptor, and
descriptor.js, refuse a descriptor whose parentheses and braces nest more
than 1000 deep.

## Descriptor backups

A descriptor backup packs the canonical descriptor and splits the packed
bytes as type D. In Go:

```go
desc, err := descriptor.Canonical(exported) // verifies a checksum, writes a new one
payload, err := descriptor.Pack(desc)       // 457 bytes of text become 252
sp := shaqr.Splitter{Derived: true}         // or Open: true
shares, err := sp.Split(payload, shaqr.TypeDescriptor, k, n)
```

To recover, check that Combine returns type D and unpack the payload:

```go
typ, payload, err := shaqr.Combine(held)
desc, err := descriptor.Unpack(payload) // the canonical text with its checksum
```

Unpack packs the text it unpacked once more and returns
`descriptor.ErrNotPacked` when the bytes differ, so that one wallet has
one packed form and so one set per format and k. Pack refuses, and Unpack
stops at, a text longer than eight times the packed bytes plus 64
(DESCRIPTOR.md Packed payload). In JavaScript, `pack(desc)` and
`unpack(packed)` in js/descriptor.js do the same, and
`split(payload, TypeDescriptor, k, n, { open: true })` cuts an open set;
js/README.md has an example.

Share bytes, text characters and QR version (alphanumeric, level L) of
the wallets of DESCRIPTOR.md Sizes: `wsh(sortedmulti(..))` of keys derived
from seeds, with key origins and `/<0;1>/*` children.

```
wallet     descriptor   packed   sealed           open
2-of-3     457          252      182 / 298 / 9    150 / 246 / 8
3-of-5     743          404      191 / 312 / 9    159 / 261 / 8
10-of-20   2889         1545     210 / 342 / 10   178 / 291 / 9
```

Split as text, as in Draft 3, the same wallets needed QR versions 11, 12
and 13 for a sealed set. descriptor/wallets_test.go holds the keys and
checks the packed sizes.

```
go run ./cmd/descbackup split < wallet.txt > plates.txt
go run ./cmd/descbackup split -open < wallet.txt > plates.txt
go run ./cmd/descbackup split -k 2 -n 3 < wallet.txt > plates.txt
go run ./cmd/descbackup recover < plates.txt
go run ./cmd/descbackup replace 2 < plates.txt
go run ./cmd/descbackup -h
```

descbackup follows DESCRIPTOR.md. Split puts the descriptor in canonical
form, packs it and cuts a derived set of it, so that it cuts the same
plates from the same wallet and k every time. With -open it cuts an open
set: every plate is 32 bytes shorter and shows part of the descriptor; the
first k plates hold slices of it, whole public keys among them. It refuses
to cut an open set of a descriptor that holds a private key, an xprv, a
tprv, a SLIP-132 form such as zprv or a WIF key, or a key whose text
starts like one. It reads the descriptor from standard input, or from its
argument, which leaves the keys in the shell's history. By default k and n
are the wallet's quorum, which it reads from a descriptor whose keys all
sit in one multi. -k and -n override either, since a set is not tied to
the keys: a 3-of-5 wallet can go on 2-of-3 plates, or on more plates than
it has keys. For any other descriptor give -k and -n. It labels share x
with its set, the quorum of the set and the format, and names no key, as
in `# share 1 of set #7B63 (2-of-3, sealed)`. The owner decides who keeps
which plate. It checks the origin and the path of every key and the
base58check of every extended key, and warns when the descriptor has no
checksum, since then nothing shows that it is the wallet's. A k of 1, the
default of a 1-of-n descriptor, makes no set, and split prints the
descriptor that goes on every plate. Every other line it prints that is
not a share starts with `#`. Recover reads its input as one text, in any
case and wrapped over any number of lines. It reports every share it
leaves out and why, by the line it starts on. Once the id and the content
type pass and the payload unpacks, it prints the descriptor of every set
it holds k shares of, with the checksum unpacking computes, byte for byte.
It warns when that text is not a descriptor in canonical form, which no
tool that follows DESCRIPTOR.md cuts, and prints it all the same. A
payload that fails to unpack, or unpacks to text that packs to other
bytes, is reported and printed nowhere. Where two texts claim one x and
too few other x values remain, it tries each, and the id decides. Replace
makes share x of the one set it holds k shares of. A share does not tell
n, so its label gives the wallet's number of keys when the set's k is the
wallet's threshold, or the n of `replace -n N X`. Messages name a set by
its tag.

## Site

site/ is a static page that splits a descriptor or any other text into
plates and recovers it from any k of them, in the browser. The Pages
workflow deploys it to https://shaqr.org/ on every push
to main. For that, the repository's Pages source must be GitHub Actions.

```
python3 -m http.server -d site
```

serves it at http://localhost:8000/. app.js is an ES module, and the shaQR
module hashes with WebCrypto, which browsers offer only to secure
contexts. So the page runs over HTTPS or from localhost, and not from a
file:// URL. The camera also needs a secure context.

site/js is a link to ../js, so the page runs the module of this checkout.
The Pages workflow copies the site with `cp -rL`, which turns the link
into files.

`node site/tools/make-cards.js` (node 22 or later) cuts the 3-of-5 example
of site/examples.js into its derived set and writes site/cards/: its five
plates as 85 x 55 mm SVG cards, an A4 sheet of them and, when inkscape is
installed, a PDF of the sheet. Run it again after a change to the module,
to cards.js or to the example. The cards draw their text from the glyph
outlines in site/vendor/mono-glyphs.js, which site/tools/build-glyphs.py
writes from DejaVu Sans Mono with fontTools.

The other files in site/vendor/ are third-party libraries. qrcode.js is
the npm package qrcode 1.5.4, bundled with esbuild into one script that
defines `QRCode`. jsQR.js is jsqr 1.4.0, minified with esbuild. zxing/
is the reader script of zxing-wasm 3.1.4 and its wasm. The page reads
codes with the browser's BarcodeDetector where there is one, then zxing,
then jsQR.

## License

CC0 1.0, see LICENSE. It covers the specification, the profile and notes, the
code and the test vectors. The descriptor checksum in both implementations was
written from the description in BIP 380 and shares only its constants with the
sample code there.

The libraries in site/vendor/ keep their own licenses: MIT for qrcode and
zxing-wasm, Apache 2.0 for jsQR and for the zxing-cpp code in the wasm. The
glyph outlines in site/vendor/mono-glyphs.js come from DejaVu Sans Mono,
under the DejaVu fonts license.

QR Code is a registered trademark of Denso Wave Incorporated.
