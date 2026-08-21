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

### Q-003 — The ApplicationID format in the prose is not the format in the worked examples

**Citations.** §4.2.5.2 (the attribute's definition, which gives a
three-part caret-separated format, and the worked request immediately below it,
which carries a single bare identifier); §4.2.5.3.1 (the banned-applications
check, which treats the ApplicationID as one value); §2 (the boundary tables the
IAP keeps, which key permitted contexts by ApplicationID); Appendix A.5,
Table 11 (`ERR_00045`).

**The statement.** §4.2.5.2 defines the ApplicationID as three parts joined by
`^`: the identifier the software product was allocated at labelling, a minor
release, and an installation identifier. The worked request in the same section
carries an ApplicationID with no separator in it at all — a single OID-shaped
token. The prose describes a composite; the example shows an atom. Neither is
annotated as abbreviating the other.

The ambiguity is not cosmetic, because the value is a lookup key. §2 has the IAP
hold permitted contexts against an ApplicationID, and §4.2.5.3.1 has it check an
ApplicationID against a banned list. Whether those tables are keyed by the whole
composite or by the product identifier alone decides whether banning one
installation bans a product, and whether a minor release inherits the contexts
its predecessor was granted. The excerpt does not say.

**What the code does.** Treats the ApplicationID as an opaque string. There is a
type alias so that signatures name what they take, and no validation whatsoever:
both the caret-separated form and the bare form build, as does anything else.
The library transmits the value the caller was allocated.

Alongside it, `applicationIdShape` reports which of the two attested forms a
value takes, or `unrecognised` for neither. It is exported for a caller checking
tenant configuration at startup, and **nothing in the library consults it** — no
request is refused on the strength of it.

**The basis.** The value is allocated by the AULSS, not composed by this
library. Between a prose rule and an example that breaks it, an enforcement
either rejects values the region issues or silently blesses a format the region
may not accept, and the library cannot tell which from the document. Refusing to
build is the more expensive error of the two: it fails a deployment that would
otherwise have worked, at a site where nobody can change the allocated value.
Reporting the shape instead puts the observation where a human can act on it —
during onboarding, against the registration paperwork — rather than in the
request path.

**The cost.** A caller that concatenates the three parts wrongly — wrong
separator, wrong order, a missing installation identifier — gets no complaint
from the library and finds out from `ERR_00045`, or worse from an authorisation
that silently matches the wrong boundary-table row. The advisory checker
narrows that only for a caller that chooses to run it.

**The question as it would be sent.**

> §4.2.5.2 defines the ApplicationID attribute as three parts joined by `^` —
> the labelled product identifier, the minor release, and the installation —
> but the worked request in the same section carries a single identifier with no
> `^` separators. Which form should a client emit? If the composite form is
> correct, is the example abbreviated for readability, and are all three parts
> mandatory or may trailing parts be omitted? Separately, and for us the more
> important question: are the
> boundary tables of §2 and the banned-applications list of §4.2.5.3.1 keyed by
> the full composite value or by the product identifier alone — that is, does
> banning one installation ban the product, and does a new minor release inherit
> the contexts granted to the previous one?

---

### Q-004 — §4.2.5.2's worked request declares a request context code that Appendix A.2 does not define

**Citations.** §4.2.5.2 (the RequestContext attribute's definition, which
confines it to the Appendix A codes, and the worked request below it, which
carries `C.1.6`); Appendix A.2, Table 5 (the clinical contexts code system,
whose continuity-of-care rows stop at `C.1.4`); §4.2.5.3.1 (the mandatory check
of the declared context against the contexts enabled for the ApplicationID);
Appendix A.5, Table 11 (`ERR_00041`).

**The statement.** §4.2.5.2 states that the RequestContext attribute is
populated with codes defined in Appendix A. Its own worked request populates it
with `C.1.6`. Table 5 defines four codes in that group, ending at `C.1.4`; there
is no `C.1.5` and no `C.1.6` anywhere in the table. The prose and the example
cannot both be right.

Two readings are available. Either the table was shortened between document
versions and `C.1.6` is a live code the appendix has lost, or the example was
written against a draft table and is stale. The excerpt gives no way to tell,
and the table carries independent signs of drift that make neither reading
comfortable: `C.4.2` appears under the same macro-activity as `C.5.1` where the
numbering suggests `C.5.2` was meant, and the administrative group skips `C.6.4`
altogether.

**What the code does.** Follows the prose and refuses the example. The request
context is a closed union over Table 5, `isRequestContext` is the guard for
values arriving as plain strings, and `C.1.6` is not a member — so the one
context code the specification demonstrates is the one context code this library
will not build a request from.

`src/vocabulary.test.ts` asserts that rejection by name, so that it reads as
this decision rather than as an oversight in the table transcription. `C.4.2` is
reproduced exactly as Table 5 gives it, on the same principle: the table is the
vocabulary, and an IAP may well have implemented the row literally.

**The basis.** The check that matters happens at the IAP: the declared context
must be a member of the set the organisation enabled for the calling
ApplicationID (§4.2.5.3.1). A code absent from the regional code system cannot
be a member of any such set, so declaring `C.1.6` gets an `ERR_00041` after a
round trip rather than an assertion. Failing at the call site costs a developer
one error message; failing at the IAP costs a support ticket in which nobody can
see why. Where prose and example conflict, this is the direction in which
following the prose is cheap and following the example is not — the inverse of
Q-002, where following the prose would have broken against a live service.

**The cost.** If `C.1.6` is in fact live and Table 5 is what is stale, this
library refuses a context that the region accepts, and a caller entitled to
declare it has no way through. The refusal is loud and immediate rather than
silent, so the failure mode is a blocked integration and a fast question, not a
wrong assertion. Adding the code back is a one-line change once the answer
arrives.

**The question as it would be sent.**

> §4.2.5.2 states that the RequestContext attribute is populated with the codes
> defined in Appendix A, but the worked request in that section carries
> `C.1.6`, which does not appear in Table 5 — the continuity-of-care group ends
> at `C.1.4`. Is `C.1.6` a valid code that Table 5 is missing, or is the example
> stale? We currently reject it, so we would be refusing a request the
> specification's own example makes. Two related points in Table 5, which may
> share a cause: `C.4.2` is listed under the same macro-activity as `C.5.1`,
> where the numbering scheme suggests `C.5.2`; and `C.6.4` is absent from an
> otherwise contiguous administrative group. Are those intentional, and is
> `C.4.2` the code an IAP will actually accept?

---

### Q-005 — The worked fault carries an error code no table defines, and two tables are left open

**Citations.** §4.6.1 (the management of fault conditions, whose worked fault
carries `ERR_00010`); Appendix A.5, Table 11 (the class that fault declares,
whose codes run `ERR_00041` to `ERR_00045`); Appendix A.5, Tables 9 and 10 (both
of which end in an ellipsis rather than a final row).

**The statement.** §4.6.1's worked fault declares the invalid-security-token
class and carries `ERR_00010`. Table 11, which defines that class's codes, does
not contain `ERR_00010` and neither does any other table in Appendix A.5. The
description the fault gives alongside it corresponds to the refusal that
Table 11 codes as `ERR_00041`, so the example looks like a code that was
renumbered when the tables were reorganised and not updated in the prose.

Separately, Tables 9 and 10 each end with an ellipsis where the remaining rows
would be. The appendix is therefore explicitly partial by its own typography,
independently of the excerpt's missing pages (Q-001).

**What the code does.** Names the codes the excerpt lists and treats the
vocabulary as open. `RegionalErrorCode` is a union over what is listed, which is
sound for typing a code this library produces and unsound for parsing an inbound
one — so the module says so, and nothing in the library rejects a fault for
carrying a code it does not recognise. `ERR_00010` deliberately gets no
constant: naming it would assert that the excerpt defines it somewhere, and it
does not.

**The basis.** An undefined code and an ellipsis point the same way. A client
that treats the listed codes as exhaustive would read a legitimate fault as a
malformed one, and would do it precisely when something unusual had gone wrong —
the moment the diagnosis matters most. Failing open on an unknown code costs
nothing, because the code is diagnostic rather than load-bearing: it explains a
refusal that the fault class has already established.

**The cost.** A caller cannot exhaustively switch on `RegionalErrorCode` and
trust the compiler's exhaustiveness check to mean what it usually means, because
the runtime set is larger than the type. The type is honest about the excerpt
and dishonest about the wire, and that asymmetry has to be held in the reader's
head.

**The question as it would be sent.**

> The worked fault in §4.6.1 declares `wsse:InvalidSecurityToken` and carries
> error code `ERR_00010`, but Appendix A.5, Table 11 defines that class as
> `ERR_00041` to `ERR_00045` and no table in the appendix defines `ERR_00010`.
> Its description matches the one Table 11 gives for `ERR_00041`. Is the example
> stale, or is `ERR_00010` a live code the appendix omits? Relatedly, Tables 9
> and 10 both end in an ellipsis: could you supply the complete set of codes for
> those two classes? We would like to know whether the appendix is intended to
> be exhaustive, so that we can decide whether a client may treat an unlisted
> code as a protocol error or must accept it.

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
