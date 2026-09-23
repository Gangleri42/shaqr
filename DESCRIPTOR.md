# shaQR descriptor backups

Follows SPEC.md Draft 4. Nothing here has been reviewed. Do not use it with
real secrets yet.

An application profile of shaQR, not part of the scheme. It says how a
multisig output descriptor is split across the signers' seed plates, so that
every tool that makes or reads such plates can read, and cut again, the plates
of the others. It adds rules on top of SPEC.md and changes nothing underneath.
How a device lays out a plate, and which sizes it accepts, is the device's own
business.

A k-of-n multisig survives the loss of n-k seeds. It does not survive the loss
of one extended public key, because spending needs all n of them. The backup
puts one share of the descriptor on each signer's plate, beside the seed. Any
k plates then hold a signing quorum together with the descriptor that quorum
needs.

The payload is the descriptor in canonical form, packed, with content type D.
The canonical form makes one wallet give one text whichever program exported
it. Packing writes the keys as bytes, which makes the shares about a third
smaller, and it is exact, so every tool gets the same bytes from the same
text.

## Canonical form

A generator deletes white space, verifies a checksum that is present, and
then:

1. writes hardened steps as `h`, and key origin fingerprints and hex keys
   (whole runs of 64 or 66 hex digits) in lower case;
2. writes the children of every extended key outside a `musig()` as
   `/<0;1>/*` when they are absent, `/0/*` or `/<0;1>/*`;
3. in a `sortedmulti` or `sortedmulti_a`, sorts the keys in ascending byte
   order of their text without the children (the origin and the key), the
   full text breaking a tie;
4. computes the checksum afresh.

Everything else stays as given. In `multi` and `multi_a` the order of the keys
is part of the script and does not change. The keys inside a `musig()` keep
their children: BIP 390 allows a derivation after `musig()` only when its keys
have none, and the key of an aggregate of children is another key than a
child of the aggregate.

The three spellings in rule 2 are how exporters write a wallet's receive and
change branches, and the backup is of the wallet. `sortedmulti` orders the keys
in the script by itself, so the order an exporter lists them in carries no
meaning (rule 3). The recovered text can differ from an export in key order,
in `h` and in the children, and so in its checksum. It describes the wallet the
exporter meant.

## Packed payload

Packing turns key origins, extended keys, hex keys and the children
`/<0;1>/*` into binary tokens and drops the `#` and checksum at the end. Every
other character stays as its ASCII byte. A descriptor holds no byte of 0x80 or
above, so every token starts with one.

A packer reads the canonical text without its last nine characters, from left
to right. At each position it applies the first rule that matches, writes its
bytes and moves past the characters it matched:

1. An origin: `[`, eight lower-case hex digits, any number of steps and `]`,
   where a step is `/`, a decimal index below 2^31 with no leading zero, and an
   optional `h`. A step packs as the number 2 * index + 1 when it has `h` and
   2 * index when it does not. When the last origin token had the same steps,
   write 0x92 and the four fingerprint bytes. Otherwise write 0x91, the
   fingerprint bytes, the number of steps and the steps.
2. An extended key: the base58 characters from here to the first character
   that is not base58, where the character before here is not base58 either,
   when they decode as base58check to 78 bytes: version (4), depth (1), parent
   fingerprint (4), child number (4), chain code (32) and key (33). It packs
   as a key token (below). The rule looks at base58check and the length only:
   a packer does not check that the key is a point on the curve or that depth
   and fingerprints make sense, so that every tool packs a text the same
   way.
3. A hex key: the lower-case hex digits from here to the first character that
   is not one, where the character before here is not one either, when there
   are 64 or 66 of them. Write 0x94 and 32 bytes, or 0x95 and 33 bytes.
4. The eight characters `/<0;1>/*`. Write 0x93.
5. Any other character. Write its byte.

Numbers are unsigned LEB128 in their shortest form: seven bits to a byte, the
low bits first, the top bit set on every byte but the last. Base58 is the alphabet of Bitcoin
addresses, and base58check appends the first four bytes of a double SHA-256.

A key token:

```
marker   0x80 + 4 * kind + 2 * implied + parity
kind     0 xpub 0488B21E, 1 tpub 043587CF, 2 xprv 0488ADE4, 3 tprv 04358394
parity   the key's first byte minus 2 for xpub and tpub (02 or 03); 0 for
         xprv and tprv, whose first key byte is 00
implied  1 when an origin token came right before this key, its number of
         steps equals the depth, and its last step, or 0 when it has none,
         equals the child number (the index, plus 2^31 when hardened)
bytes    implied: parent fingerprint, chain code, key bytes 1 .. 32
         otherwise: depth, parent fingerprint, child number, chain code,
         key bytes 1 .. 32
```

A key of any other version, or whose first key byte does not fit its kind,
packs as 0x90 and all 78 bytes. The markers 0x89, 0x8B, 0x8D, 0x8F and those
above 0x95 are not used.

A receiver unpacks each byte below 0x80 as its character and each token as the
text it came from: an origin in lower-case hex with `h`, taking the steps of
the previous origin token for 0x92; a hex key in lower case; an extended key as
base58check, taking depth and child number from the origin before it when
implied is set. It appends `#` and the BIP 380 checksum. It then packs that
text and rejects the payload if the bytes differ from the ones it unpacked.

That last check makes the packed form of a text unique. Without it a token
left as text, a key written with its depth where the origin implies it, or a
number written with an extra byte would unpack to the same descriptor from
other bytes, and a set made from those bytes would not be the set every other
tool cuts from the wallet.

The descriptor checksum is computed on unpacking and so detects nothing; the
check and the id of the shares cover the payload. Text the rules do not match,
such as other children, stays as its ASCII bytes and costs only its length.
Any change to these rules needs a new content type, since the repack check
makes a receiver refuse bytes packed by other rules.

## Threshold

k is the descriptor's signing threshold and n is its number of keys. Both can
be read from the descriptor when it has a single `multi`, `sortedmulti`,
`multi_a` or `sortedmulti_a` and every key sits in it. For any other
descriptor, including a `tr()` whose internal key stands apart, the user gives
k and n.

The k to give is the size of the smallest group of keys that can spend on any
path. A larger k would leave that group able to sign and unable to find its
coins.

A 1-of-n descriptor makes no set, since k is at least 2. Each plate carries
the plain descriptor.

Bitcoin allows 3 keys in a bare `multi`, 15 under `sh`, 20 under `wsh` and 999
in a `multi_a` leaf. A descriptor with more than 255 keys cannot have one share
per key.

## Which share goes where

Share x goes on the plate of the x-th key of the canonical descriptor. Where
that order does not match the signers, as with a `tr()` internal key that signs
for no one, the user assigns the plates.

## Derived and open sets

A descriptor backup uses a derived set, or an open set when the owner accepts
that every plate shows part of the descriptor. Both are functions of the
wallet and k, so every run of every conforming tool cuts the same plates from
the same wallet. That is how an interrupted set is finished, and how a lost
plate is cut again without the other plates, in the format of the plates in
hand.

A derived set is safe here because nobody who lacks one of the extended public
keys can guess the payload. Each key carries as many unknown bits as the seed
behind it, about 128 for a 12-word seed, which just meets the rule of SPEC.md.
Grover's algorithm halves that margin: a descriptor with one key the attacker
lacks falls at about 2^64 quantum steps, the same test an address of the wallet
allows to anyone who knows one. Anyone who already holds every key can confirm
the descriptor from a share, and learns nothing new by it.

An open set is 32 bytes smaller per plate and keeps nothing private. The first
k plates hold slices of the packed descriptor, whole extended public keys
among them, and the others hold mixes of it. A finder of one plate learns
those keys and that they belong to a multisig wallet. Below k plates nobody
learns the wallet's addresses, since its script needs every key. A descriptor
that holds a private key (xprv, tprv or WIF) is never cut as an open set.

A set cannot be refreshed: splitting again gives the same plates. A departed
cosigner normally means a new wallet, a new descriptor and so a new set.

## Recovery

After recovery (SPEC.md) has verified check and id, the receiver confirms that
the content type is D and unpacks the payload, which gives the canonical text
with its checksum. The text goes to wallet software byte for byte.

## Sizes

Share bytes, text characters and QR version (alphanumeric, level L) of the
packed payload, for wallets of `wsh(sortedmulti(..))` with key origins and
`/<0;1>/*` children, and for the same text unpacked for comparison.

```
wallet       descriptor   packed   sealed           open             text, sealed
2-of-3       457          252      182 / 298 / 9    150 / 246 / 8    285 / 462 / 11
3-of-5       743          404      191 / 312 / 9    159 / 261 / 8    304 / 493 / 12
10-of-20     2889         1545     210 / 342 / 10   178 / 291 / 9    345 / 558 / 13
```

A key with its origin and children is 142 characters of text and packs to 75
bytes, or 80 for the first key, whose origin path is written out. The rest of
each share is the 55 bytes of SPEC.md, or 23 in an open set, and the share of
the script around the keys.

## References

BIP 32, Hierarchical Deterministic Wallets. BIP 380, Output Script Descriptors
General Operation. BIP 383, Multisig Output Script Descriptors. BIP 386, tr()
Output Script Descriptors. BIP 387, Tapscript Multisig Output Script
Descriptors. BIP 389, Multipath Descriptor Key Expressions. BIP 390, musig()
Descriptor Key Expressions.
