# shaQR in JavaScript

The second implementation of SPEC.md Draft 3, beside the Go package in the
directory above. ES modules with no dependencies, for browsers and for node
20 or later. SHA-256 and HMAC-SHA256 come from WebCrypto; ChaCha20 is
written out in chacha20.js and tested against RFC 8439.

```
shaqr.js         the scheme: split, combine, shareAt, audit, group,
                 parseHeader, tag, encode, decode, scan
descriptor.js    DESCRIPTOR.md: checksum, verify, canonical, quorum,
                 fingerprint
chacha20.js      the ChaCha20 keystream, RFC 8439
gf256.js         the field and interpolation
test/            node --test
```

The API follows the Go package. Shares are Uint8Arrays and content types
are bytes, as in `TypeText` (0x55, U). Every function that computes a check
or an id returns a promise. A share or set that recovery cannot use throws
a `ShaqrError`, and a descriptor that `canonical` or `verify` refuses throws
a `DescriptorError`. Each error has a `code`, one of the words the vector
files use, such as `check`, `too-few` or `id`. The comments in shaqr.js and
descriptor.js say what every function does.

Where the two differ: `tag(share)` reads the tag of a share without
verifying it, where Go offers `Header.Tag` after `ParseHeader`; `split`
also refuses a `minLen` that is not an integer, which Go's types rule out;
and a too-few error carries `k`, `held` and `disputed` as properties, where
Go returns a `TooFewError`. The export `internals` is for the tests only.

## Tests

```
cd js
node --test
```

The tests read testdata/vectors.json and testdata/descriptors.json, which
the Go tests write, and pass every case in them. They also run the test
vectors of RFC 8439, compare ChaCha20 with the one in node:crypto, and
split and recover random sets.

## In a page

A page loads shaqr.js as a module, with the other files next to it:

```html
<script type="module">
  import { split, encode, decode, group, combine, tag, TypeText } from './js/shaqr.js';

  const secret = new TextEncoder().encode('correct horse battery staple');
  const shares = await split(secret, TypeText, 2, 3, { minLen: 32 });
  const plates = shares.map((sh, i) => `${tag(sh)} ${i + 1}/3\n${encode(sh)}`);

  // Later: whatever text the user pastes or types back.
  const read = decode(plates[2] + '\n' + plates[0]);
  const { sets } = await group(read.shares);
  const { type, payload } = await combine(sets[0]);
  console.log(new TextDecoder().decode(payload));
</script>
```

A descriptor backup puts the descriptor in canonical form and cuts a
derived set of it (DESCRIPTOR.md):

```js
import { split, combine, TypeDescriptor } from './js/shaqr.js';
import { canonical, quorum, verify } from './js/descriptor.js';

const desc = canonical(exported);
const q = quorum(desc); // null when the keys are not all in one multi
const [k, n] = q === null ? await askUser() : [q.k, q.keys.length];
if (k === 1) {
  // A 1-of-n makes no set: every plate carries desc as it is.
} else {
  const plates = await split(new TextEncoder().encode(desc), TypeDescriptor, k, n, { derived: true });
}

// Recovery: the content type must be D and the checksum must match.
const { type, payload } = await combine(held);
if (type !== TypeDescriptor) throw new Error('the set does not hold a descriptor');
const text = new TextDecoder().decode(payload);
verify(text); // throws unless the checksum matches
```

`askUser` stands for whatever the page does to ask for k and n.

Browsers give WebCrypto only to secure contexts, so the page has to come
over HTTPS or from localhost, and they do not load modules from file://
URLs. `python3 -m http.server` in the repository root serves the files for
a local test at http://localhost:8000/.
