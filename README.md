# rve-assertion

Builds RVE-1.b request envelopes for the Veneto regional Identity and Assertion
Provider (IAP), and validates the SAML assertions it returns.

RVE-1.b is the regional specification's transaction for *authorisation issued
for trusted applications*: an application that authenticates its own operators
with its own credentials, trusted by the AULSS on the strength of mutual TLS and
an ApplicationID allowlist. See [`CONTEXT.md`](CONTEXT.md) for the vocabulary.

> **Status: in progress.** The scaffold, the MessageID-to-ID derivation, the
> regional code vocabulary and the request builder are in place. The assertion
> validator has its structural phase, its structural signature phase, its
> validity-window check, its audience check, the attributes the calling service
> requires and the identity cross-check. **Do not spend an assertion on the
> strength of `validateAssertion` returning valid in this build**: no signature
> is cryptographically verified unless the caller supplies a verifier, and the
> success branch says so in a warning.
> See [Validating an assertion](#validating-an-assertion).

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

`validateAssertion` takes the raw bytes of a **bare `saml:Assertion` element**,
the clock to judge it at, and the policy of the service about to be called, and
returns a discriminated result.

```ts
import {
  ASSERTION_ATTRIBUTES,
  RECOMMENDED_CLOCK_SKEW_MS,
  RECOMMENDED_FLIGHT_TIME_MS,
  servicePolicy,
  TWO_FACTOR_AUTHENTICATION_LEVEL,
  validateAssertion,
} from 'rve-assertion';

const registry = servicePolicy({
  audience: 'https://fser.regione.veneto.it/Registry',
  refusesGenericAssertions: true,
  requiredAttributes: [ASSERTION_ATTRIBUTES.ROLE, ASSERTION_ATTRIBUTES.REQUEST_CONTEXT],
  requiredAuthenticationLevel: TWO_FACTOR_AUTHENTICATION_LEVEL,
});

const result = validateAssertion(
  assertionBytes,
  {
    now: new Date(),
    clockSkewMs: RECOMMENDED_CLOCK_SKEW_MS,
    flightTimeMs: RECOMMENDED_FLIGHT_TIME_MS,
  },
  registry,
);
if (result.valid) {
  for (const warning of result.warnings) {
    log.info(warning.code, warning.detail);
  }
  call(result.operatorTaxCode, result.audiences, result.authenticationLevel);
  cache.set(assertionBytes, { evictAt: result.usableUntil });
} else {
  for (const failure of result.failures) {
    log.warn(failure.code, failure.detail, failure.regionalErrorCode, failure.unrecoverable);
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

### The identity cross-check

§4.1.6.2.2 has RVE-1.b's IAP derive both the subject's `NameID` and the
`ResponsibleParty` attribute from one directory query for one operator, so the
two carry the same tax code by construction. The validator holds them against
each other. Two different values means the IAP resolved two different people for
one request, and nothing downstream can tell which of them the regional audit
trail should name — so it is refused, and the failure is marked
`unrecoverable`: asking the same IAP the same question returns the same two
answers, and retrying is a loop against a third party.

Every value of the attribute is held against the subject, not the first, so an
assertion naming a second responsible party beside the right one is caught
rather than read as naming whichever a reader reaches first. `ResponsibleParty`
is required whatever the policy asks for, because an assertion that omits it is
one the cross-check cannot be run against (`D-021`).

The tax code's **format is not validated**, on either side (`D-019`). The IAP is
the authority on the value, a format rule this excerpt does not state would
refuse assertions a regional service accepts, and a well-formed tax code is not
a real one anyway. The comparison folds case and nothing else (`D-020`).

### What a result carries

The result is a union rather than a boolean, so the compiler makes the caller
handle the refusal. On the success branch it reports the `operatorTaxCode`, the
`audiences` the assertion is scoped to, the `authenticationLevel` it attests,
and the `usableUntil` deadline a caching layer evicts on — one call, and
everything a caller needs from an assertion it did not build. It also carries
`warnings`: what was accepted about this assertion that a caller may still want
to act on — a deprecated algorithm the region permits, and, unless a verifier
was supplied, the fact that no signature was cryptographically verified.

On the failure branch, `failures` is typed non-empty — an invalid result with
nothing to show for it cannot be constructed. Each failure carries this
library's own `code`, a human-readable `detail`, the regional error code as
`regionalErrorCode`, and `unrecoverable`. The regional code is an **annotation,
not the failure's identity**: it exists so a local diagnosis and an IAP's report
can be discussed in the same words, and `code` is what a caller switches on.
`unrecoverable: true` is a positive claim that no round trip can change the
answer — the identity mismatch is the one failure that carries it today; `false`
is the absence of that claim rather than a promise that a retry will work. Details are constant text and never quote the document — an assertion
carries the operator's tax code, and a detail echoing what it found would put
that into whatever logs the failure.

**Three phases, and the first two stop.** The structural phase asks whether
there is an assertion here at all: parseable, an assertion element at the root,
one assertion element in the whole document, the attributes §4.1.6.2.2 makes
mandatory, exactly one each of the elements it requires — the issuer, the
subject, and the conditions carrying the validity window — and one operator
identifier in the subject. The signature phase then asks whether the signature
covers *this* assertion. Each reports **one** failure and runs nothing further:
neither accumulates its own failures, and neither lets the phase after it run.
The semantic phase is the one that runs to completion and reports every reason —
every missing attribute, not the first, so that a caller does not fix one, spend
a round trip against a third-party IAP, and discover the next. It checks the
validity window, the audience, the attributes the service requires and the
operator's identity.

A short-circuit is not a ranking of severity. It is the claim that a later check
cannot mean anything until an earlier one holds: unparseable bytes have no
audience to compare and no window to check, and an assertion whose signature
covers something else has an audience nobody vouched for — reporting that the
audience was wrong too would invite a caller to fix the audience.

Five refusals are stricter than the specification demands, each argued in
`docs/spec-questions.md`: bytes are decoded as UTF-8 strictly rather than
substituted through (`D-009`), a document a parser would have to recover from is
refused rather than repaired (`D-010`), a document type declaration is refused
outright (`D-011`), and a document carrying more than one assertion element is
refused (`D-024`). A fifth concerns the window: a `NotBefore` or `NotOnOrAfter`
carrying no time zone is refused rather than read in an assumed one, since two
hosts in different zones would otherwise reach different verdicts about the same
assertion (`D-012`). An explicit `+02:00` offset is accepted — it names the same
instant a `Z` value would.

### Structural signature integrity

Named for what it does, which is more than checking that a signature is there.
§4.1.6.2.2 requires the signature's single `ds:Reference` to name the
assertion's **own** identifier, prefixed with a hash, and that binding is the
part that matters: a signature element proves only that something was signed by
someone, while the reference is what says the something is this assertion. A
validator that checked presence alone would accept a genuine signature lifted
from a real assertion and pasted into a forged one. That is signature wrapping,
and two checks here defeat it — the reference must name this assertion's
identifier, and the document must carry exactly one assertion element, so there
is no second element for a reference to have been about.

Failures are distinguished rather than lumped together, because their remedies
differ. `signature-absent` is an IAP that did not sign (`ERR_00053`),
`signature-malformed` is a signature this library could not read (`ERR_00012`),
and `signature-not-bound` is a signature covering something else — the shape of
an attack, and a reasonable thing to alert on rather than log.

A deprecated signature or digest algorithm is **not** a refusal. §4.1.6.2.2
attests SHA-1 in both slots and deprecates it, and then signs its own worked
assertion with it; refusing would refuse a document the region permits and
demonstrates. It arrives instead as a warning on the success branch, so a caller
with a policy against SHA-1 can enforce one without this library imposing that
policy on callers who cannot yet afford it. Accepting it in code while calling
it a risk is the tension `Q-008` exists to reconcile. An algorithm *outside* the
attested pairs is refused.

### Cryptographic verification is a seam, not a feature

**This library does not verify signatures.** It computes no digest and checks no
signature value, because verification needs a key, a trust decision about that
key and a canonicalisation implementation — and there is no single regional
issuer to hold a key for; there is one per AULSS.

The seam is `verifySignature`, a `SignatureVerifier`: it is handed the caller's
exact bytes, since that is what a signature covers, and answers `verified`,
`not-verified` or `not-attempted`. Three answers rather than a boolean, because
*nothing checked* and *checked and bad* are different claims. The default,
`NO_SIGNATURE_VERIFICATION`, answers `not-attempted` — and the success branch
then carries a `signature-not-cryptographically-verified` warning, so the
limitation travels with the result instead of living only in this README.

```ts
const result = validateAssertion(assertionBytes, time, policy, {
  verifySignature: (bytes) => (myXmlDsigVerifier.verify(bytes) ? 'verified' : 'not-verified'),
});
```

A verifier that answers `not-verified` turns the result into a refusal carrying
`signature-verification-failed`. The seam is synchronous, which is a constraint
worth naming: a verifier needing a key must hold its trust material before it is
called, rather than reaching for the network on the request path of a clinician
waiting for a record.

### The validity window, and the time model around it

The current instant is a **required argument with no default**, so the validator
can be driven at a chosen moment by a test and by a caller with a better time
source than this process's clock.

The margin around it is two arguments rather than one, because it was always two
quantities. **Clock skew** is how far this host's clock may be from the IAP's,
and it moves *both* bounds earlier — the same thing as assuming this clock may
be that far behind the issuer's, which is the direction in which being wrong is
dangerous. **Estimated flight time** is how long a call carrying the assertion
takes to reach the service that will check it; it is a real interval that
elapses *after* this library answers, so it moves the far bound earlier again
and the near bound not at all. So the near bound is `NotBefore` less the skew,
and the far bound is `NotOnOrAfter` less the skew and the flight time — one
combined margin cannot produce both, and gets the near bound wrong in the
direction that refuses assertions the IAP has only just issued.

`RECOMMENDED_CLOCK_SKEW_MS` (one minute) and `RECOMMENDED_FLIGHT_TIME_MS` (five
seconds) are exported and never applied silently — a caller taking them has
written down that it did. **Replace the flight time.** It is a placeholder for
your own measured high-percentile round trip to the regional services you call;
nothing in the specification supports the number. Both figures and the reasoning
are `D-014`.

`NotBefore` is inclusive and `NotOnOrAfter` is exclusive, as their SAML names
say. Expired and not yet
valid are distinct failure codes carrying distinct regional codes — `ERR_00032`
and `ERR_00031` — because their remedies differ: one is answered by a fresh
assertion, the other by fixing a clock. A window too short to reach a service
through reports both, which is what is true of it.

On success the result carries `usableUntil`: `NotOnOrAfter` less the skew and
the flight time, which is the deadline a cache layer evicts on. It is exclusive,
like the bound it comes from — holding the assertion *at* that instant is
holding it one instant too long — and it is deliberately earlier than the
assertion's own expiry, because an assertion held until the instant the document
expires is one that expires in flight.

The window's **length** is not checked. §3.1.1's four-hour and fifteen-minute
figures describe what the IAP does under regional policy, not a constraint on
what a client may accept, and the region has its own code (`ERR_00033`) for a
window it dislikes, decided by the party that holds the policy. Enforcing the
figures here would refuse assertions the region considers valid the first time
an AULSS configured a window between them. The argument is `D-013`.

A bad time model **throws** `ValidationInputError` rather than returning a
refusal. The assertion is third-party data whose rejection is a control-flow
outcome; the clock and the margins are the caller's own arguments, and the
silent alternative is the dangerous one — every comparison against `NaN` is
false, so a clock that is not a time would accept every assertion put to it.

### The service policy

The policy is **caller-supplied**, and required — there is no validating an
assertion without saying what it is about to be spent on. §3.1.1 is why: a
service holding highly confidential data may turn away any assertion whose
request did not name it, and which services do that is decided by the
organisation, not by the specification.

`servicePolicy` is a smart constructor and throws `ValidationInputError` on a
blank audience, on one that is not an absolute URL, and on a matching mode it
does not implement. It stores the audience with the whitespace around it
stripped, so `policy.audience` is a value a scoped re-request can carry. What
the caller does not say, `BASELINE_SERVICE_POLICY` fills in:

- `refusesGenericAssertions: false` — **an inference, labelled as one.** §4.2.6
  has no information-content table of its own; the nearest is RVE-1.a's, which
  marks the audience optional in both directions, and §4.1.6.2.2 makes the
  element a `MAY`. Read across, a generic assertion is conforming. Nothing here
  claims the specification states this for RVE-1.b — `D-015`, and `Q-001` for
  why there is no RVE-1.b table to read.
- `audienceMatching: 'exact'` — string comparison, after stripping the
  whitespace an XML formatter put around the value, which a URI could not have
  contained. `'normalised'` is available per service and
  applies the WHATWG URL form: lowercased scheme and host, default port dropped,
  empty path written as `/`. Path case and a trailing slash stay significant.
  Exact is the default because the X-Service Provider runs its own comparison
  and a local *yes* against a remote *no* is worse than no local check —
  `D-016`.

`requiredAttributes` names the attributes the service will not act without, by
the wire names §4.1.6.2.2 gives them — `ASSERTION_ATTRIBUTES` has the ones it
defines, so a policy need not retype an irregular casing that would silently
mean *never present*. The list is open: §4.2.5.2 says regional projects may
provide for further parameters, so a policy may name an attribute this excerpt
never mentions. The check is presence, not value — whether `R.1.1` is a role
that may reach this service is the X-Service Provider's decision against
information the region holds and this library does not.

`requiredAuthenticationLevel` is separate, and its failure has its own code,
because its remedy is unlike any other: the operator must authenticate again
with a second factor, which is the session layer's work rather than a
re-request this library's caller can make. An assertion attesting *two*
different levels is refused whatever the policy asked for, since it contradicts
itself about how strongly the operator authenticated and there is no reading of
it that is safe (`D-023`).

An assertion naming several services is valid if one of them is this one, and an
assertion carrying two `AudienceRestriction` elements must satisfy both, which
is SAML 2.0 core's reading of an element §4.1.6.2.2 describes only in the
singular (`D-018`).

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
`D-017` has the argument and the cost. `requiredAttributes` is not that copy
either: it asks whether an attribute is there, never which value would be
acceptable.

The regional code beside a failure is the region's nearest, not its exact one —
Appendix A.5 names outcomes the region reaches against information this library
does not hold, so each annotation is a best match, and `D-022` says which
neighbours were chosen and why.

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
for the layer that owns it, rather than an omission — for signatures, the seam
is `verifySignature` and the omission is reported in the result itself. See
[Cryptographic verification is a seam, not a feature](#cryptographic-verification-is-a-seam-not-a-feature).

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
