# rve-assertion

Builds RVE-1.b request envelopes for the Veneto regional Identity and Assertion
Provider (IAP), and validates the SAML assertions it returns.

RVE-1.b is the regional specification's transaction for *authorisation issued
for trusted applications*: an application that authenticates its own operators
with its own credentials, trusted by the AULSS on the strength of mutual TLS and
an ApplicationID allowlist. See [`CONTEXT.md`](CONTEXT.md) for the vocabulary.

> **Status: in progress.** The scaffold, the MessageID-to-ID derivation, the
> regional code vocabulary and the request builder are in place. The assertion
> validator has its entry point, its structural phase and the audience check;
> the rest of its semantic phase — validity window, required attributes,
> identity cross-check, signature integrity — is not written yet. **Do not spend
> an assertion on the strength of `validateAssertion` returning valid in this
> build**: it does not yet establish that an assertion is in date or signed at
> all. See [Validating an assertion](#validating-an-assertion).

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

## Building a request

Two steps, deliberately separate. `rve1bRequest` is a smart constructor: it
takes the caller's input, checks every invariant a request cannot be built
without, and throws `RequestInputError` naming the one that failed.
`buildRve1bRequest` takes the result and serialises it, and has no failure mode
— the value it is handed cannot exist unchecked.

```ts
import { buildRve1bRequest, rve1bRequest } from 'rve-assertion';

const bytes = buildRve1bRequest(
  rve1bRequest({
    messageId: `urn:uuid:${crypto.randomUUID()}`,
    recipient: 'https://iap.example-aulss.veneto.it/ws',
    username: { form: 'plaintext', value: operatorUsername },
    applicationId: tenant.applicationId,
    requestContext: 'C.1.1',
    issueInstant: now,
    notBefore: now,
    notOnOrAfter: new Date(now.getTime() + 4 * 60 * 60 * 1000),
    audiences: ['https://fser.regione.veneto.it/Registry'],
  }),
);
```

The output is bytes rather than a string, because the envelope declares its own
encoding and a string does not carry one. Handing back a string would move the
choice of encoding to whatever writes it to the socket, which is where a
mismatch with the declaration gets introduced.

The window is checked for being a window: `NotOnOrAfter` must be strictly after
`NotBefore` once both are truncated to whole seconds, since `NotOnOrAfter`
excludes its own instant. It is *not* checked against the issue instant — the
specification's own worked request would fail that check, which is `D-005`.

The username has two forms and neither has a field for a password, so no input
produces a `wsse:Password` element. An encrypted username is the caller's own
ciphertext: this library does not encrypt.

Three omissions are deliberate and each is written down: no `saml:Issuer`, no
`saml:Subject`, no `Destination` attribute and no `wsa:ReplyTo`. §4.2.5.2 names
none of them and its worked request carries none, but the RVE-1.a
information-content table marks two of them required. Which reading governs
RVE-1.b is `Q-006`.

## Validating an assertion

`validateAssertion` takes the raw bytes of a **bare `saml:Assertion` element**
and the policy of the service about to be called, and returns a discriminated
result.

```ts
import { servicePolicy, validateAssertion } from 'rve-assertion';

const registry = servicePolicy({
  audience: 'https://fser.regione.veneto.it/Registry',
  refusesGenericAssertions: true,
});

const result = validateAssertion(assertionBytes, registry);
if (!result.valid) {
  for (const failure of result.failures) {
    log.warn(failure.code, failure.detail, failure.regionalErrorCode);
  }
}
```

The input is bytes, not a string, and nothing here reserializes them: §4.6
requires the assertion be spent exactly as the IAP returned it, and a round trip
through a document model normalises whitespace, attribute order and namespace
declarations — all of them inside what the region signed. The bytes handed in
are the bytes the caller still holds afterwards.

**Unwrapping is out of scope.** Reaching into a SOAP response to find the
assertion, or into a `wsse:Security` header to find one being presented, is a
transport concern, and transport is a layer this library does not own. A caller
hands over the sub-document it already located; a whole response fails the root
element check, and the failure says so.

The result is a union rather than a boolean, so the compiler makes the caller
handle the refusal. On the failure branch, `failures` is typed non-empty — an
invalid result with nothing to show for it cannot be constructed. Each failure
carries this library's own `code`, a human-readable `detail`, and the regional
error code as `regionalErrorCode`. The regional code is an **annotation, not the
failure's identity**: it exists so a local diagnosis and an IAP's report can be
discussed in the same words, and `code` is what a caller switches on. Details
are constant text and never quote the document — an assertion carries the
operator's tax code, and a detail echoing what it found would put that into
whatever logs the failure.

**Two phases, and the first one stops.** The structural phase asks whether there
is an assertion here at all: parseable, an assertion element at the root, the
attributes §4.1.6.2.2 makes mandatory, and exactly one each of the elements it
requires — the issuer, the subject, and the conditions carrying the validity
window. The signature is mandatory too and is checked elsewhere, because its
absence and its being malformed are different regional errors and this phase has
one code to report. It reports **one** failure and runs nothing further, in
both directions — it does not accumulate structural failures, and it does not
let the semantic phase run. Unparseable bytes have no audience to compare and no
signature to bind, so a list of later failures would report things missing only
because the document is. The semantic phase is the one that runs to completion
and reports every reason. It checks the audience today; the rest arrives with
the tickets that give it something to check.

## The service policy

The policy is **caller-supplied**, and required — there is no validating an
assertion without saying what it is about to be spent on. §3.1.1 is why: a
service holding highly confidential data may turn away any assertion whose
request did not name it, and which services do that is decided by the
organisation, not by the specification.

`servicePolicy` is a smart constructor and throws `ServicePolicyError` on a
blank audience, on one that is not an absolute URL, and on a matching mode it
does not implement. It stores the audience with the whitespace around it
stripped, so `policy.audience` is a value a scoped re-request can carry. What
the caller does not say, `BASELINE_SERVICE_POLICY` fills in:

- `refusesGenericAssertions: false` — **an inference, labelled as one.** §4.2.6
  has no information-content table of its own; the nearest is RVE-1.a's, which
  marks the audience optional in both directions, and §4.1.6.2.2 makes the
  element a `MAY`. Read across, a generic assertion is conforming. Nothing here
  claims the specification states this for RVE-1.b — `D-012`, and `Q-001` for
  why there is no RVE-1.b table to read.
- `audienceMatching: 'exact'` — string comparison, after stripping the
  whitespace an XML formatter put around the value, which a URI could not have
  contained. `'normalised'` is available per service and
  applies the WHATWG URL form: lowercased scheme and host, default port dropped,
  empty path written as `/`. Path case and a trailing slash stay significant.
  Exact is the default because the X-Service Provider runs its own comparison
  and a local *yes* against a remote *no* is worse than no local check —
  `D-013`.

An assertion naming several services is valid if one of them is this one, and an
assertion carrying two `AudienceRestriction` elements must satisfy both, which
is SAML 2.0 core's reading of an element §4.1.6.2.2 describes only in the
singular (`D-015`).

The two audience refusals are distinct codes. `audience-mismatch` says the
assertion is scoped elsewhere; `audience-absent` says it is generic and this
service was declared to refuse that. Both annotate `ERR_00044` and both are
resolved by one re-request, but they are different bugs in the caller.

**The policy carries no permitted contexts and no permitted roles**, and the
omission is deliberate. An X-Service Provider weighs five attributes and can
refuse on any of them; four are decided against boundary tables the organisation
holds, which this library cannot see and cannot be told about when they change.
A stale client-side copy fails closed and is fixed by a redeploy. The audience
is the exception because the caller is the party that asked for it — checking it
is confirming its own request was honoured, not re-deciding an entitlement.
`D-014` has the argument and the cost.

Three refusals are stricter than the specification demands, each argued in
`docs/spec-questions.md`: bytes are decoded as UTF-8 strictly rather than
substituted through (`D-009`), a document a parser would have to recover from is
refused rather than repaired (`D-010`), and a document type declaration is
refused outright (`D-011`).

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
