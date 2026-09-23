# shaQR: short secret shares

Draft 3, 23 September 2026. Nothing here has been reviewed. Do not use it with
real secrets yet. The code and test vectors in this repository implement
this draft.

Changes from Draft 2: ChaCha20 replaces the HMAC keystream and the key is 32
bytes. The id commits to the whole key polynomial. The open format and pieces
are gone. Every generator draws its key through the seed and checks its set
before it hands out a share. Receivers have rules for white space, text that
does not decode, and two shares with one x. A set has a tag, written after a
`#`, and a label beside a share starts outside base32. Descriptor backups
moved to DESCRIPTOR.md, where they use derived sets over a canonical
descriptor.

License: CC0-1.0. The text of this specification, the profile and notes that
go with it, the code and the test vectors are dedicated to the public domain.
See LICENSE.

## Summary

shaQR splits a secret into n shares. Any k of them recover it. Fewer than k
show how long the secret is, to within k bytes. Beyond that they reveal
nothing, except in a derived set (see Generator options), where they let anyone
confirm a guess at the secret. A share is 55 bytes plus about 1/k of the
secret.

The format is for backups that have to last, on engraved steel or on paper.
The secret is opaque bytes. A wallet descriptor, a password, a TOTP seed and a
text note all take the same path.

The construction is Krawczyk's "Secret Sharing Made Short" (CRYPTO '93).
Encrypt the secret under a one-time key. Spread the ciphertext over the shares
with an erasure code, so that each share holds 1/k of it. Split the key with
Shamir's scheme, which is cheap because the key is 32 bytes. Each share carries
one piece of ciphertext and one piece of key.

A share is one string of text and needs no outer framing. The arithmetic is a
single interpolation routine over GF(2^8). The cryptography is SHA-256,
HMAC-SHA256 and ChaCha20. Standard libraries have the first two. ChaCha20 is
about fifty lines where a library lacks it, and RFC 8439 has test vectors for
it.

This document specifies the scheme for any payload. DESCRIPTOR.md applies it
to multisig descriptor backups, the use the reference implementation is
written for. README.md lists the files.

## Why shares shorter than the secret

A Shamir share is as long as the secret. Split a 457 byte descriptor 2-of-3
and every holder engraves 457 bytes, a version 15 QR code; with shaQR it is
285 bytes, a version 11. The Sizes table has more cases. Small secrets come
out larger: split 2-of-3, a 20 byte TOTP seed makes 66 byte shares, against 29
for a Shamir share with the same header and check. Most of the difference is
the 32 byte key part.

Short shares have a price. A scheme with perfect secrecy cannot have shares
shorter than the secret (Karnin, Greene and Hellman), so secrecy here is
computational. It holds against an attacker who cannot break ChaCha20 or
SHA-256. The wallets and logins these secrets belong to already rest on
assumptions of that kind.

## Conventions

`‖` joins byte strings. `byte(v)` is one byte. `s[a:b]` is bytes a up to
b-1. Quoted strings are ASCII with no terminator.

## Building blocks

### Field

Bytes are elements of GF(2^8) with reduction polynomial
x^8 + x^4 + x^3 + x + 1 (`0x11B`), the AES field. Addition is XOR. The format
needs no primitive element; log tables, where used, can take 3 as their base.
A table indexed by a secret byte can leak through a cache, so the key parts
are better served by a shift-and-add multiplication that does not branch on a
secret bit.

### Interpolation

All polynomial work is one operation. Take k points (x_1, y_1) .. (x_k, y_k)
with distinct x values, and a target x. Exactly one polynomial f of degree
below k passes through the points, and

```
interp(points, x) = XOR over i of   w_i * y_i

w_i = product over j != i of   (x + x_j) / (x_i + x_j)
```

gives f(x). `+` is XOR, `*` and `/` are field multiplication and division. If
x is one of the x_i the result is y_i.

The y values in this spec are byte strings of equal length. interp treats each
byte position on its own and uses the same weights for all of them, so the
weights are computed once per call.

### Stream

```
stream(key, len) = first len bytes of the ChaCha20 keystream
                   for the 32 byte key, a nonce of 12 zero bytes
                   and block counter 0, 1, 2, ...
```

This is ChaCha20 as RFC 8439 section 2.4 defines it, used as a bare stream
cipher with no Poly1305. The nonce stays fixed because no key encrypts more
than one message: seed and S both depend on the payload (Splitting, step 2).
One stream
holds 2^38 bytes, which bounds L.

## Splitting

Inputs are the payload, a content type T of one byte, the threshold k, the
share count n with 2 <= k <= n <= 255, and r: 32 bytes from a cryptographic
random source for a session set, or empty for a derived set (see Generator
options). The payload may be empty.

1. Seal the payload.

   ```
   sealed = T ‖ payload ‖ 0x80 ‖ 0x00 ...
   ```

   Add as many zero bytes as it takes to make the length a multiple of k. A
   generator may add more, k at a time (see Padding). L is the length of
   sealed and B = L / k.

2. Draw the key and the randomness for its shares.

   ```
   seed = HMAC-SHA256(key = "shaQR v1 seed",
                      msg = byte(len(r)) ‖ r ‖ byte(k) ‖ sealed)
   take = stream(seed, 32 * k)
   S    = take[0:32]
   R_i  = take[32*i : 32*i + 32]        for i = 1 .. k-1
   ```

   Every generator draws S and the R_i this way. S is the key of this set.
   Erase r, seed, take, S and stream(S, L) once the shares exist and have
   passed step 6.

   With a sound random source, r alone would do. Mixing in k and sealed makes
   S depend on the payload as well, so a source that repeats, is predictable
   or has stopped cannot give two payloads the same key. Such a set degrades
   to a derived set (see below), and its key is still unknown to anyone who
   cannot guess the payload.

3. Encrypt.

   ```
   C = sealed XOR stream(S, L)
   ```

4. Compute the set id.

   ```
   id = SHA-256("shaQR v1 id" ‖ byte(version) ‖ byte(k) ‖ take ‖ C)[0:16]
   ```

   version is `0x01`, the first byte of every share (see Share layout). take
   is S followed by the R_i, the key polynomial at 0 .. k-1, so the id commits
   to the whole key polynomial and not only to S.

5. Build the shares. Cut C into k blocks C_1 .. C_k of B bytes. For each x
   from 1 to n:

   ```
   key_x  = interp({(0, S), (1, R_1), .., (k-1, R_(k-1))}, x)
   data_x = interp({(1, C_1), (2, C_2), .., (k, C_k)}, x)
   ```

   For x below k, key_x is R_x. For x up to k, data_x is C_x. Only the shares
   past those need any arithmetic.

6. Check the set before any share leaves the generator. Read every share back
   from its text, recover the payload from the k shares with the highest x and
   compare it with the input, then compare every share byte for byte with what
   the recovered polynomials give at its x. A share made wrong by a fault still
   carries a valid check and the right id, since the same code computed them;
   without this step only a recovery finds it, which is too late.

The key part is Shamir's scheme. Picking k-1 share values at random and
interpolating the rest gives the same distribution as picking k-1 random
coefficients. SLIP-39 works in a similar way: it draws some shares at random
and interpolates the others. The data part is a systematic Reed-Solomon
erasure code, which is safe to leave systematic because it only ever sees
ciphertext.

## Share layout

```
offset   size   field
0        1      version   0x01
1        1      k         threshold
2        1      x         index of this share, 1 .. 255
3        16     id        the same on every share of a set
19       32     key_x
51       B      data_x
51+B     4      check     SHA-256("shaQR v1 check" ‖ all bytes before)[0:4]
```

All shares of a set have the same length, at least 56 bytes. n is not
recorded because recovery does not need it. x = 0 is where S sits, so a set
has at most 255 shares.

Tools that label shares or name a set use its tag: the first two bytes of the
id, written as four upper-case hex digits after a `#`, as in `#B962`.

Later versions of the format keep byte 0 as the version and the last four
bytes as check, computed the same way with the string "shaQR v1 check".

## Checks

Checksums are not optional anywhere in this format.

Every share ends in check. Generators must write it. Receivers must verify it
before they read any other field and must drop a share that fails. A failed
check names the damaged share at the moment it is scanned or typed, while the
holder is still there to try again.

Every set has an id and recovery must verify it (Recovering, step 5). check
covers one share against damage; anyone can compute it, so it stops no forger.
The id covers the result and is what stops a forger.

check is a hash and not a CRC or a BCH code. A hash needs no primitive the
format does not already have, and it misses a change with probability 2^-32
whatever the pattern of the damage. It corrects nothing. Correction is left to
the carrier, which for a QR code is its own Reed-Solomon layer, and to spare
shares.

## Text form

```
SHAQR:<base32>
```

Base32 is the RFC 4648 alphabet in upper case with no padding. Generators write
a share as one string in upper case, the prefix included, with no white space.
Every character is then in the QR alphanumeric set and a share encodes at 5.5
bits per character. A single lower case letter puts an encoder that uses one
mode for the whole text into byte mode at 8 bits per character: the 462
character share of a 2-of-3 descriptor goes from version 11 to version 15.

Receivers read more loosely, because shares are also typed by hand from
engraved text that wraps over several lines. They ignore case, in the prefix
too, and delete white space inside a share; white space is any Unicode white
space character, such as the non-breaking space that pasted text can carry. A
share starts after `SHAQR:` and runs to the next `SHAQR:`, to the first
character that is neither base32 nor white space, or to the end of the input,
whichever comes first. Its length is not 1, 3 or 6 modulo 8. The unused low
bits of the last character are written as zero and ignored when read. Text
outside shares is not part of any share and is ignored.

Because a share runs on across white space, a label printed next to it starts
with a character outside base32 in either case, such as the `#` of a tag, so
that the two stay apart when typed.

A share whose text does not decode is reported like one that fails check. It
never stops the recovery of other shares.

A share is one string. A carrier that cannot hold it whole splits and rejoins
it in its own framing, and the format does not see that. PIECES.md describes
one such framing.

## Recovering

A holder may keep the shares of several sets in one place, so a recovery may
be handed shares of more than one set.

1. Decode each share and verify check. Drop the share if it does not decode
   or check does not match; a share too short to hold a check fails it.
   Report a share whose check matches and whose version is not `0x01` as made
   by another version, and leave it out. Then drop, and report, a share
   shorter than 56 bytes, with x = 0, or with k below 2.
2. Group shares by k, id and length. Shares in different groups belong
   to different sets and are never combined. A group short of k is reported,
   for example as "1 of 2 shares", and does not hold up the others.
3. Wait for k distinct x values in one group. If two or more shares in a
   group have the same x and differ, report x as disputed and leave them all
   out. Recovery goes on if k other x values remain. If fewer do, the receiver
   may try each in turn, and the id decides.
4. Interpolate.

   ```
   S    = interp({(x, key_x)}, 0)
   R_i  = interp({(x, key_x)}, i)       for i = 1 .. k-1
   take = S ‖ R_1 ‖ .. ‖ R_(k-1)
   C_i  = interp({(x, data_x)}, i)      for i = 1 .. k
   C    = C_1 ‖ .. ‖ C_k
   ```

   A held share with x = i supplies C_i directly, and R_i too when i is below
   k.

5. Recompute id from take and C. If it differs from the id on the shares, output
   nothing. With spare shares the receiver may look for a subset that passes
   (see Finding a bad share).
6. Decrypt as in step 3 of splitting. Strip trailing zero bytes, then one
   `0x80`. If the `0x80` is missing, or no byte is left before it, stop with
   an error. The first byte of what remains is T and the rest is the
   payload.

Nothing interpolated or decrypted from the shares is displayed or acted on
before step 5 has passed. A receiver that ends up with k shares of more than
one set recovers each of them or asks which one is wanted.

Step 2 keeps a share of another set from counting towards k or setting B for
a set it does not belong to. Step 5 is the safety net: interpolating across
two sets gives a take and a C that fail the id.

## Finding a bad share

check catches damage and typing errors in a single share and names that share
at once. A share that passes check and is still wrong was made wrong on
purpose, or comes from a faulty generator.

With exactly k shares the id fails and the receiver can say only that. With
more than k it may search. Each k-subset yields a candidate take and C, and
the id accepts the true one. The id commits to both polynomials in full, so
every held share whose key_x or data_x disagrees with them is bad, and the
blame is right whenever the id passes.

The number of k-subsets grows fast, 184756 for 20 shares held at k = 10, so a
receiver that searches must bound its work. README.md gives the order the
reference uses.

Every byte position of the shares is a Reed-Solomon codeword (McEliece and
Sarwate), so a receiver can also correct up to (m - k) / 2 wrong shares among
m in polynomial time with Berlekamp-Welch decoding. DECODING.md describes it.

## Replacing a lost share

Any k shares of a set can produce any other share of it. Verify the set first.
Then interpolate the key and data parts at the new x, copy version, k and id,
and compute check. This is how a lost share is made again and how n is raised
later. The device doing it holds k shares and could recover the payload, so
treat the occasion like a recovery.

## Generator options

A share does not record which of these the generator used.

### Session sets and derived sets

A session set takes r from a random source. Two splits of the same payload
give unrelated sets. This is the default. It is the only safe choice for
payloads an attacker could guess, such as passwords, PINs and short notes.

A derived set uses an empty r. The whole set is then a function of T, the
payload and k: the same input gives the same shares on every conforming
generator, another k gives another id, and a lost share can be made again from
the payload alone, with no other shares present. In exchange, a share of a
derived set lets anyone test guesses at the payload, and recognise the shares
of a payload they already know (see Security). Use derived sets only for
payloads with at least 128 bits the attacker cannot know, for example a
descriptor made of extended public keys.

### Padding

Any share shows L, and so the length of the payload to within k bytes. For a
password that is worth hiding. A generator may accept a minimum length for
sealed and add zero bytes until it is reached, keeping L a multiple of k.
Recovery strips them without being told. A derived set gets only the zero
bytes that sealing (Splitting, step 1) requires, so that it stays a function
of T, the payload and k.

## Content types

```
0x42  B    bytes
0x55  U    UTF-8 text, not normalized
0x44  D    output descriptor, BIP 380 text with its checksum (DESCRIPTOR.md)
```

Other values are reserved. T sits inside the encryption, so a share does not
show what kind of secret it protects. The core interprets no type: a payload
with a checksum of its own, such as a descriptor, keeps it, and the
application verifies it. A receiver that meets a type it does not know hands
the type and the bytes to its caller.

## Security

Someone with fewer than k shares of a set sees version, k, id, some x values
and L. From those they learn that the shares belong together, the threshold, a
lower bound on n and the length of the payload to within k bytes.

In a session set that is all. r is uniform, so seed, S and the R_i are
pseudorandom. The key parts are then Shamir shares below the threshold and
reveal nothing about S. The keystream under S is pseudorandom, so the data
parts, which are linear images of the ciphertext, reveal nothing about the
payload. The id cannot be computed or tested without S. This assumes ChaCha20
is a pseudorandom function of its key, and treats HMAC-SHA256 under the fixed
key "shaQR v1 seed" and SHA-256 in the id as random oracles.

In a derived set every field of a share, the id included, is a function of T,
the payload and k. Anyone who holds one share, or has seen its id, can test a
guess at the payload by running the splitting steps once, and anyone who
already knows the payload can recognise its shares. A session set allows
neither.

S is 32 bytes, so Grover's algorithm needs about 2^128 steps to find it, and a
share of a session set taken today stays closed to a quantum computer later. A
derived set is only as strong as its payload is hard to guess, and Grover
halves that exponent too: a payload with 128 bits the attacker does not know
falls at about 2^64 steps.

The id exists because the arithmetic is linear and the stream cipher malleable.
A holder, or any group of holders short of k, who has learned the secret, for
instance by being present at an earlier recovery, knows S and C, and can
compute a replacement share that changes what a later recovery outputs. Bare
Shamir allows this and so does Krawczyk's basic scheme. Here every honest share
carries the id the generator computed, a commitment to version, k, C and the
whole key polynomial, whose opening is take. The forger cannot alter the honest
copies. To pass step 5 of Recovering the forger needs a second take and C with
the same id, a second preimage of a 16 byte hash: about 2^128 work, 2^64 for a
quantum forger, or 2^(128-t) if any one of 2^t sets would do. The forged share
lands in another group or fails the id. A forger can stop a recovery and cannot
change its result, and with spare shares the receiver names the forged share
(see Finding a bad share).

The id does the work a MAC on the ciphertext would do, and it does more: a MAC
keyed by S would not bind a holder who has learned S. The id binds everyone
but the generator.

The generator is trusted. Nothing here detects a generator that hands out bad
shares or keeps a copy of the secret. The recovering device sees the payload
and deserves the same care as the generator.

## Sizes

```
share bytes = 55 + B          B = ceil((payload + 2) / k)
text chars  = 6 + ceil(8 * share bytes / 5)
```

QR versions are for alphanumeric mode at error level L. For comparison, the
last column is a Shamir share of the payload with the same 9 bytes of type,
terminator, header and check, in the same text form.

```
payload                  split      share   text   QR    Shamir QR
TOTP seed, 20 bytes      2-of-3        66    112    4        3
key, 32 bytes            2-of-3        72    122    5        3
key, 32 bytes            3-of-5        67    114    4        3
descriptor, 457 bytes    2-of-3       285    462   11       15
descriptor, 743 bytes    3-of-5       304    493   12       20
descriptor, 2889 bytes   10-of-20     345    558   13     none
```

The descriptors are `wsh(sortedmulti(..))` of 3, 5 and 20 keys with key
origins and `/<0;1>/*` children, checksum included.

## Worked example

The payload is the ASCII text `JBSWY3DPEHPK3PXP`, type U, split 2-of-3 with
r = `00 01 02 .. 1f`.

```
sealed  554a425357593344504548504b3350585080
seed    7868e5a0777f4832079e8a933e2dd37d833f954d1e2bf0f2a5c8a618bc752f64
S       3c4a0309269d72e99a9696f9fd3f92fc69059757c347521c43cde1fb753eedd9
R_1     b6cca4e219281751c973c2513fa4895327fff202d2d1eb6ee64efd806ff1771e
C       54b0b64bba71bfc06b92b4baf857b4cdc01f
id      b96219ec42ff7a50495969396067235c
```

L is 18 and B is 9. The three shares, 64 bytes each:

```
010201b96219ec42ff7a50495969396067235cb6cca4e219281751c973c2513fa4895327fff202d2d1eb6ee64efd806ff1771e54b0b64bba71bfc06b9c6cfef4
010202b96219ec42ff7a50495969396067235c335d56c458ecb8823c473eb26212a4b9f5ea5dfde1703bf812d0d90d41bbc24c92b4baf857b4cdc01f5f709904
010203b96219ec42ff7a50495969396067235cb9dbf12f6759dd3a6fa26a1aa089bf16bb1038a8f0e6828ab753c5765b74588bd041be600cf7e3c033077eaf9c
```

```
SHAQR:AEBADOLCDHWEF732KBEVS2JZMBTSGXFWZSSOEGJIC5I4S46CKE72JCKTE777EAWS2HVW5ZSO7WAG74LXDZKLBNSLXJY37QDLTRWP55A
SHAQR:AEBAFOLCDHWEF732KBEVS2JZMBTSGXBTLVLMIWHMXCBDYRZ6WJRBFJFZ6XVF37PBOA57QEWQ3EGUDO6CJSJLJOXYK62M3QA7L5YJSBA
SHAQR:AEBAHOLCDHWEF732KBEVS2JZMBTSGXFZ3PYS6Z2Z3U5G7ITKDKQITPYWXMIDRKHQ42BIVN2TYV3FW5CYRPIEDPTABT36HQBTA57K7HA
```

Share 1 holds R_1 and C_1 as they are. Share 2 holds C_2 as it is. Its key
part, and both parts of share 3, are interpolated. `testdata/vectors.json`
holds this case and others, valid and invalid.

## Open questions

There is no compression. A compressed payload would arrive as a new content
type and leave the sharing layer alone.

One threshold governs both key and data. A data threshold below k would add
redundancy against damaged shares and make shares larger. It is left out.

Bellare and Rogaway (CCS 2007) define privacy and recoverability for
computational secret sharing. They prove the variant of Krawczyk's scheme that
hashes every share, and state no theorem for the basic scheme, which shaQR is
with one set-wide id. Whether session sets meet their definitions has not been
checked.

## References

H. Krawczyk, "Secret Sharing Made Short", CRYPTO '93, LNCS 773, Springer 1994,
136-146.

R. J. McEliece and D. V. Sarwate, "On Sharing Secrets and Reed-Solomon Codes",
Communications of the ACM 24(9), 1981, 583-584.

A. Shamir, "How to Share a Secret", Communications of the ACM 22(11), 1979,
612-613.

E. Karnin, J. Greene and M. Hellman, "On Secret Sharing Systems", IEEE
Transactions on Information Theory 29(1), 1983, 35-41.

M. Bellare and P. Rogaway, "Robust Computational Secret Sharing and a Unified
Account of Classical Secret-Sharing Goals", ACM CCS 2007, 172-184.

SLIP-0039, Shamir's Secret-Sharing for Mnemonic Codes.

BIP 380, Output Script Descriptors General Operation. BIP 383, Multisig Output
Script Descriptors.

RFC 2104 (HMAC), RFC 4648 (Base32), RFC 8439 (ChaCha20).

QR Code is a registered trademark of Denso Wave Incorporated.
