# Specification questions and documented decisions

The single source for every point where this library diverges from the Veneto
regional security specification, or where the specification contradicts or fails
to settle something the library had to decide anyway. Code sites carry a
one-line pointer here rather than the argument itself.

Each question is written as it would actually be sent to the specification's
authors, so that asking it is a task someone can pick up rather than knowledge
held in one person's head.

No text from the specification appears in this repository. Everything below
paraphrases and cites by section number.

**On citations.** The excerpt in hand is partial (see Q-001), so not every
section this document needs to point at has a resolvable number. Where a number
is known it is given as `§n.n.n`. Where the section exists but the excerpt does
not number it in the pages available, it is named descriptively and marked
_(number to confirm)_ — those are the citations to firm up when the full
document is obtained, not gaps in the argument.

---

## Questions for the specification's authors

### Q-001 — The excerpt is missing the pages that define RVE-1.a's request semantics

**Citations.** §4.2.5.2 (the RVE-1.b request); the RVE-1.a request section it
defers to _(number to confirm — these are the absent pages)_.

**The statement.** Roughly ten pages covering the RVE-1.a request semantics are
absent from the excerpt available to us. §4.2.5.2 defines several of the RVE-1.b
request's attributes by reference to that section rather than restating them, so
those definitions cannot be confirmed from the document in hand. The same gap
removes the only place a required-attribute matrix for the RVE-1.b *assertion*
might have been stated; the nearest surviving table describes RVE-1.a.

**What the code does.** Treats the gap as a documented gap rather than filling it
by guessing. Where the library needs a value the absent pages would have
supplied, it takes it from the caller and ships a baseline constant labelled as
*derived from the RVE-1.a table*, not as stated by the specification. Nothing in
the library asserts conformance to a requirement it cannot read.

**The basis.** A guess that happens to be right is indistinguishable, in the
code, from a guess that is wrong. Labelling the inference keeps a later reader
from mistaking it for a citation.

**The cost.** Any claim about attributes RVE-1.b defines by reference is
provisional until the full document is read. Some of them may turn out to be
mandatory where the library currently treats them as caller-supplied.

**The question as it would be sent.**

> The copy of the specification we hold is an excerpt, and it is missing
> approximately ten pages covering the RVE-1.a request semantics. §4.2.5.2
> defines several RVE-1.b request attributes by reference to that section, so we
> cannot confirm their definitions, cardinality or permitted values from the
> document we have. Could you supply the complete document, or at least those
> pages? Separately: is there a required-attribute matrix for the RVE-1.b
> assertion anywhere in the full document, or is the RVE-1.a table intended to
> apply to RVE-1.b as well?

---

### Q-002 — The user client authentication value differs between the request example and the assertion example, on an attribute the specification declares inherited

**Citations.** §4.2.5.2 (the RVE-1.b worked request, which carries one value);
the RVE-1.b worked assertion that follows it _(number to confirm)_, which
carries a different one; and the attribute's own definition, which states that
the assertion inherits it from the request.

**The statement.** The specification defines the user client authentication
attribute as inherited: the value the assertion carries is the value the request
declared. Its two worked examples for RVE-1.b disagree with that — the request
example and the assertion example carry different values for the attribute, and
neither example is annotated as showing the IAP altering it. The three
statements cannot all be true. Either the attribute is not in fact inherited,
or one of the examples is in error, or the IAP is permitted to overwrite the
value in a way the prose does not describe.

**What the code does.** Two consequences, in opposite directions.

On the request side, the RVE-1.b user client authentication value is a named
constant rather than a literal at the call site, because the specification pins
which value RVE-1.b declares. The library emits that value and nothing else.

On the validation side, the library **does not** check that the assertion's user
client authentication value equals the one the request declared, even though
"inherited" would license exactly that check. Enforcing inheritance against an
IAP that reproduces the specification's own assertion example would reject a
conforming assertion.

**The basis.** Where prose and worked example conflict, an IAP implementer is at
least as likely to have followed the example. A check the document's own example
fails is a check that breaks against a real regional service, and the library
would fail closed on an assertion that was never wrong.

**The cost.** If the attribute really is inherited and the assertion example is
simply an error, the library is not detecting an IAP that returns an assertion
asserting a different client authentication method than the one requested. That
would be a meaningful signal, and the library is choosing not to raise it.
Resolving this question is what would let the check be added.

**The question as it would be sent.**

> The user client authentication attribute is defined as inherited by the
> assertion from the request. In the RVE-1.b worked examples, however, the
> request in §4.2.5.2 and the assertion that follows it carry different values
> for that attribute. Which is normative? Specifically: (a) should a client
> treat the assertion's value as necessarily equal to the value it declared in
> the request, and reject the assertion if it differs; or (b) is the IAP
> permitted to substitute a different value, and if so under what circumstances?
> If (a), we read one of the two examples as containing an error and would like
> to know which.

---

## Decisions where the specification is silent

Not contradictions — points the specification simply does not settle, where the
library had to pick a behaviour to be implementable at all. Recorded here so
that each reads as a decision rather than an accident.

### D-001 — An uppercase UUID in a message ID keeps its case

**Citations.** §4.2.5.2 (the MessageID-to-ID derivation); RFC 4122 §3.

§4.2.5.2 derives the SAML `AuthnRequest/@ID` from the SOAP `wsa:MessageID` by
stripping the `urn:uuid:` scheme prefix and applying a `msgId_` prefix. It does
not say whether the hexadecimal is to be case-normalised, and RFC 4122 §3 makes
a UUID case-insensitive on input while recommending lowercase on output.

The library preserves whatever case it was given. The derivation exists to
correlate a SOAP message ID, a request identifier, an assertion identifier and a
response's `wsa:RelatesTo` across four systems, and a system comparing those as
strings — which is what a log search does — would read a normalised form as a
different identifier. Preserving the case makes the round trip exact.

The cost: two callers who differ only in case produce two identifiers the region
would consider equal. That is the caller's inconsistency to fix, and normalising
it away here would hide it.

### D-002 — A message ID with no scheme prefix is rejected

**Citations.** §4.2.5.2; WS-Addressing, which types `wsa:MessageID` as an
absolute IRI.

The library refuses a bare UUID rather than treating the scheme prefix as
optional. Two reasons. A bare UUID is not an absolute IRI, so accepting it would
let the builder emit an addressing header that does not conform. And it would
make the reverse derivation ambiguous — nothing in the derived identifier
records whether a scheme prefix had been present, so recovering the message ID
would be a guess. Rejecting keeps the derivation total in both directions, which
is what makes the reversibility claim worth anything.

### D-003 — The `urn:uuid:` scheme prefix must be in canonical lowercase

**Citations.** §4.2.5.2; RFC 8141 §5.1, which makes a URN's scheme and namespace
identifier case-insensitive while giving lowercase as the canonical form.

`URN:UUID:…` names the same URN as `urn:uuid:…`, so a case-insensitive match
would be the more permissive reading. The library nonetheless requires the
canonical lowercase form, because accepting both would cost the exactness D-001
exists to protect: the derived identifier does not record which case the scheme
was written in, so the reverse derivation would have to emit one canonical form
and the round trip would stop being byte-exact for the other. A derivation that
is reversible for most inputs is not reversible.

Requiring canonical form is affordable here in a way it would not be on the
validation side. This is the request side, where the message ID is a value the
caller generates for itself rather than third-party data it must accept as
given, so the requirement is satisfiable by construction.

The cost: a caller that generates `URN:UUID:` message IDs gets a hard failure
for something the region would have accepted. The error message names the
canonical form, so the fix is a one-line change at the call site rather than an
investigation.
