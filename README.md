# shaQR

Short secret shares: k-of-n secret sharing where a share is about 1/k the
size of the secret, made to be engraved as QR codes. SPEC.md is the
specification. This is a draft. Nobody has reviewed it. Do not use it with
real secrets.

SPEC.md is at Draft 3, and the code and test vectors here implement it.

```
SPEC.md                    the specification
DESCRIPTOR.md              profile: multisig descriptor backups on seed plates
DECODING.md                note: Berlekamp-Welch decoding of wrong shares
PIECES.md                  note: one way to carry a share over several codes
*.go                       package shaqr, the core
descriptor/                BIP 380 checksum, canonical form and quorum of a
                           multisig descriptor
cmd/descbackup/            splits a descriptor across seed plates and
                           recovers it
js/                        a second implementation, in JavaScript
testdata/vectors.json      test vectors, valid and invalid
testdata/descriptors.json  canonical forms and quorums of descriptors
py/bw_sketch.py            a sketch of the decoder in DECODING.md
site/                      the demo page, https://gangleri42.github.io/shaqr/
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
descriptor/descriptor_test.go. Without -update the Go tests check that both
files are exactly what the inputs give, rebuild every valid set and compare
the text of the shares byte for byte. The JS tests read the same
files and check them, so the two implementations agree. To change the
format, change the Go code and its inputs, rewrite the files and make the
JS tests pass again.

```
go run ./cmd/descbackup split < wallet.txt > plates.txt
go run ./cmd/descbackup recover < plates.txt
go run ./cmd/descbackup replace 2 < plates.txt
go run ./cmd/descbackup -h
```

descbackup follows DESCRIPTOR.md. Split puts the descriptor in canonical
form and cuts a derived set of it, so that it cuts the same plates from the
same wallet every time. It reads the descriptor from standard input, or
from its argument, which leaves the keys in the shell's history. It takes k
and n from a descriptor whose keys all sit in one multi and labels share x
with its set, the quorum and the fingerprint of the x-th key, or the last 8
characters of a key with no origin; for any other descriptor give -k and -n.
It checks the origin and the path of every key, and warns when the
descriptor has no checksum, since then nothing shows that it is the
wallet's. A 1-of-n descriptor makes no set, and split prints
the descriptor that goes on every plate. Every other line it prints that
is not a share starts with `#`. Recover reads its input as one text, in any
case and wrapped over any number of lines. It reports every share it leaves
out and why, by the line it starts on, and prints the descriptor of every
set it holds k shares of, byte for byte, once the id, the content type and
the checksum pass. Where two texts claim one x and too few other x values
remain, it tries each, and the id decides. Replace makes share x of the one
set it holds k shares of. Messages name a set by its tag.

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

## Site

site/ is a static page that splits a descriptor or any other text into
plates and recovers it from any k of them, in the browser. The Pages
workflow deploys it to https://gangleri42.github.io/shaqr/ on every push
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
