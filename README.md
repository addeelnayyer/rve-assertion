# rve-assertion

Builds RVE-1.b request envelopes for the Veneto regional Identity and Assertion
Provider (IAP), and validates the SAML assertions it returns.

RVE-1.b is the regional specification's transaction for *authorisation issued
for trusted applications*: an application that authenticates its own operators
with its own credentials, trusted by the AULSS on the strength of mutual TLS and
an ApplicationID allowlist. See [`CONTEXT.md`](CONTEXT.md) for the vocabulary.

> **Status: in progress.** The scaffold, the MessageID-to-ID derivation and the
> regional code vocabulary are in place. The request builder and the assertion
> validator are being added.

## The regional code vocabulary

The request context is a closed union over the regional clinical contexts code
system, with `isRequestContext` as the guard for a value arriving from tenant
configuration as a plain string. The ApplicationID is an opaque string that
nothing validates, because the specification describes one format and
demonstrates another; `applicationIdShape` reports which attested form a value
takes and is advisory — no request is refused on the strength of it. Regional
error codes are named constants, in both directions: the vocabulary a caller
reads an inbound fault in, and the vocabulary the validator annotates its own
refusals in.

The code system's plain-language labels are deliberately absent — see
[On the specification](#on-the-specification). Codes are reproduced because the
library has to emit them; the words beside them in the source tables are not.

One consequence is worth stating plainly: **this library refuses to build the
request context that the specification's own worked request declares.** The code
that example carries is not in the code system the same section confines the
attribute to. The reasoning, and the cost of being wrong about it, are in
`docs/spec-questions.md` (Q-004).

## Install and test

```sh
npm install
npm test
```

No compiler, no `node-gyp`, no build step. That is a deliberate constraint, not
a coincidence — see below.

```sh
npm run typecheck   # tsc --noEmit
```

## What it does not do

It performs no network I/O, holds no cache, manages no tenant configuration, and
does not cryptographically verify signatures. Each of those is a seam it exposes
for the layer that owns it, rather than an omission.

## Dependencies

XML is handled by pure-JavaScript packages — `xmlbuilder2` for building,
`@xmldom/xmldom` and `xpath` for parsing and querying — rather than by native
`libxml2` bindings.

The trade-off is the point, so it is stated rather than assumed. The native
option is a closer match for what production SOAP code often uses, and would
collapse three dependencies into one. It also requires `node-gyp` and a working
compiler, and a reviewer whose install fails does not debug it — they stop.
Vitest over Jest for the same reason: ESM-native with TypeScript support out of
the box, so a clean clone runs with an install and a test command.

The three XML packages are declared before anything imports them, because the
no-compiler claim above is only worth making about the dependency set the
library actually ships with — installing them is what tests it.

Development dependencies are limited to TypeScript, Vitest and Node types.

## Documentation

- [`CONTEXT.md`](CONTEXT.md) — the domain vocabulary, as the specification uses
  it. Vocabulary only.
- [`docs/spec-questions.md`](docs/spec-questions.md) — every point where this
  library diverges from the specification, or where the specification
  contradicts or fails to settle something. Each entry carries the section
  citations, what the code does, the basis, the cost, and the question as it
  would be sent to the specification's authors.

## On the specification

The specification excerpt this library was written against was shared under a
no-redistribution condition. **No text from it appears anywhere in this
repository** — behaviours are cited by section number only.

## Licence

MIT. See [`LICENSE`](LICENSE).
