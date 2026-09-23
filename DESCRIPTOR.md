# shaQR descriptor backups

Follows SPEC.md Draft 3. Nothing here has been reviewed. Do not use it with
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

## Payload

The payload is the ASCII bytes of the descriptor, BIP 380 text in canonical
form, and the content type is D. A generator deletes white space, verifies a
checksum that is present, and then:

1. writes hardened steps as `h` and key origin fingerprints in lower case;
2. writes the children of every extended key as `/<0;1>/*` when they are
   absent, `/0/*` or `/<0;1>/*`;
3. in a `sortedmulti` or `sortedmulti_a`, sorts the keys in ascending byte
   order of their text without the children (the origin and the key), the
   full text breaking a tie;
4. computes the checksum afresh.

Everything else stays as given. In `multi` and `multi_a` the order of the keys
is part of the script and does not change.

The three spellings in rule 2 are how exporters write a wallet's receive and
change branches, and the backup is of the wallet. `sortedmulti` orders the keys
in the script by itself, so the order an exporter lists them in carries no
meaning (rule 3). With the canonical form, one wallet gives one payload
whichever program exported it, and so one derived set. The recovered text can
differ from an export in key order, in `h` and in the children, and so in its
checksum. It describes the wallet the exporter meant.

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

Share x goes on the plate of the x-th key of the payload. Where that order
does not match the signers, as with a `tr()` internal key that signs for no
one, the user assigns the plates.

## Derived sets

A descriptor backup uses a derived set. Every run of every conforming tool
then cuts the same plates from the same wallet. That is how an interrupted set
is finished, and how a lost plate is cut again without the other plates.

A derived set is safe here because nobody who lacks one of the extended public
keys can guess the payload. Each key carries as many unknown bits as the seed
behind it, about 128 for a 12-word seed, which just meets the rule of SPEC.md.
Grover's algorithm halves that margin: a descriptor with one key the attacker
lacks falls at about 2^64 quantum steps, the same test an address of the wallet
allows to anyone who knows one. Anyone who already holds every key can confirm
the descriptor from a share, and learns nothing new by it.

A derived set cannot be refreshed: splitting again gives the same plates. A
departed cosigner normally means a new wallet, a new descriptor and so a new
set.

## Recovery

After recovery (SPEC.md) has verified check and id, the receiver confirms that
the content type is D and verifies the descriptor checksum, which the canonical
form always carries. The text goes to wallet software byte for byte.

## References

BIP 380, Output Script Descriptors General Operation. BIP 383, Multisig Output
Script Descriptors. BIP 386, tr() Output Script Descriptors. BIP 387, Tapscript
Multisig Output Script Descriptors. BIP 389, Multipath Descriptor Key
Expressions.
