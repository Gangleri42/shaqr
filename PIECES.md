# shaQR pieces

A note, not part of the specification. A shaQR share is one string, and a
carrier that cannot hold it whole splits and rejoins it in its own framing.
This note describes one such framing for carriers that have nothing of their
own, for example a reader limited to small QR versions. Draft 2 of SPEC.md
had it in the core; Draft 3 moved it here because the reference target
engraves one code per plate and chooses the QR version itself.

## Syntax

```
SHAQR:<p><t><tag>:<piece>
```

- t is the number of pieces and p the position of this one, each one base 36
  digit in upper case (`1` to `9`, then `A` to `Z`). 1 <= p <= t <= 35.
- tag is the first 4 characters of the base32 of the share's check. It is the
  same on every piece of one share. It is unrelated to the set tag of SPEC.md,
  which is taken from the id and names a whole set.
- piece is a run of the share's base32 text.

Base32 has no colon, so a second colon marks a piece and a share without one
is whole.

## Cutting

Let len be the length of the share's base32 text and M the most characters
the carrier holds. t is the smallest count with 13 + ceil(len / t) <= M, and
every piece but the last holds ceil(len / t) characters. The 13 are the
prefix, p, t, tag and the colon.

## Joining

The receiver collects pieces by t and tag and joins them in order of p. It
decodes the result as one share, verifies check, and confirms that tag
matches it. A piece that disagrees with the others of its tag, a position
claimed twice with different text, or a joined share whose check or tag fails
is reported and left out, and the other shares go on.

The tag is 20 bits, so two shares of the same length can collide on it. The
receiver then sees two pieces claim one position, says so, and the plates are
read one at a time.
