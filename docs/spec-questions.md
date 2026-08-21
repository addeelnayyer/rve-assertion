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

One value is refused, and it is not a format judgement: the request builder
rejects a blank or whitespace-only ApplicationID. A blank string is the absence
of a value rather than a form the region might have allocated, and emitting an
empty `AttributeValue` would send the IAP a lookup key it cannot match against
any boundary-table row.

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

`src/request-vocabulary.test.ts` asserts that rejection by name, so that it reads as
this decision rather than as an oversight in the table transcription. `C.4.2` is
reproduced exactly as Table 5 gives it, on the same principle: the table is the
vocabulary, and an IAP may well have implemented the row literally.

The request builder is where this becomes visible to a caller. `rve1bRequest`
re-checks the context at runtime rather than trusting the compiler, because the
value usually arrives from tenant configuration as a plain string, and it throws
on `C.1.6` with a message pointing here. One consequence is worth stating: the
envelope builder's tests cannot use §4.2.5.2's worked request verbatim, so the
test that pins the published example's namespace layout substitutes a context
code the code system does define. Every other value in that fixture is the
example's own.

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

### Q-006 — §4.2.5.2 promises sub-elements that identify the requester and the subject, and then names none

**Citations.** §4.2.5.2 (the prose introducing the `samlp:AuthnRequest`
sub-elements, the list of sub-elements that follows it, and the worked request
below that); §4.2.1 (RVE-1.b's attribute set, which defers to RVE-1.a);
§4.1.8, Table 3 (the RVE-1.a information-content matrix); §4.2.5.3 (the IAP's
expected actions on receipt).

**The statement.** §4.2.5.2 says that the `samlp:AuthnRequest` element contains
sub-elements identifying the actor performing the request, the subject the
assertion is to be created for, and the reason. The list immediately below it
names two sub-elements — `samlp:Extensions` and `saml:Conditions` — and neither
identifies an actor or a subject. The worked request carries the same two and
nothing else: no `saml:Issuer`, no `saml:Subject`, no `Destination` attribute.

Table 3 pulls the other way. It marks the responsible party's Codice Fiscale as
Required in a `saml:Issuer` element and the operator's Codice Fiscale as
Required in `saml:Subject/saml:NameID` — but it is the RVE-1.a matrix, and §4.2.1
says RVE-1.b carries username, UserClientAuthentication, RequestContext and
ApplicationID, referring to RVE-1.a only for the *description* of those
attributes rather than for the set. §4.2.5.3 then has the IAP recover the Codice
Fiscale by querying its Directory Server from the username, which is precisely
the work an `Issuer` element would have made unnecessary.

**What the code does.** Emits neither, and emits no `Destination` attribute and
no `wsa:ReplyTo` element either. The header carries exactly the three
WS-Addressing elements §4.2.5.2 names and the body carries exactly the two
sub-elements it lists. Tests assert each absence by name, so that a later reader
finds a decision rather than a gap.

**The basis.** The three sources are consistent under one reading: RVE-1.b
substitutes the `wsse:Username` for the identity elements RVE-1.a carries in the
SAML body, which is what makes it the *trusted application* transaction — the
application asserts who the operator is by naming them, and the IAP resolves the
rest. Under that reading the prose sentence is inherited boilerplate from the
RVE-1.a section and Table 3 is scoped to RVE-1.a, as its own title says. The
worked example is the only artefact that shows an RVE-1.b request whole, and it
agrees.

Emitting an `Issuer` this library cannot populate correctly would be worse than
omitting it. The value Table 3 wants there is the responsible party's Codice
Fiscale, which the calling application may not hold — §4.2.5.3 exists because
the IAP is the party that can look it up.

**The cost.** If Table 3 does govern RVE-1.b, every request this library builds
is missing two required elements and will be refused, and the refusal will not
say which. That is a loud, immediate, whole-integration failure rather than a
subtle one, so it would be found on the first call rather than in production —
but it would block the integration until the elements were added.

**The question as it would be sent.**

> §4.2.5.2 introduces the `samlp:AuthnRequest` sub-elements as identifying the
> actor performing the request and the subject the assertion is for, but the
> list that follows names only `samlp:Extensions` and `saml:Conditions`, and the
> worked request carries no `saml:Issuer`, no `saml:Subject` and no
> `Destination` attribute. Table 3, however, marks `Issuer` and
> `Subject/NameID` as Required — for RVE-1.a. Should an RVE-1.b request carry
> `saml:Issuer` and `saml:Subject`, or does the `wsse:Username` in the security
> header take their place, as §4.2.5.3's transcoding step suggests? If they are
> required, what should a trusted application that holds only the operator's
> username — and not their Codice Fiscale — populate them with? Separately,
> should the request carry a `Destination` attribute or a `wsa:ReplyTo` element?
> §4.2.5.2 names neither, and we currently emit neither.

---

### Q-007 — `codAziendaAuth` is defined as a list, and no encoding for a list is given

**Citations.** §4.2.5.2 (the `codAziendaAuth` attribute, defined as conveying a
list of FLS11 codes); the RVE-1.a assertion's attribute list _(number to
confirm)_, which repeats the same wording; §4.2.5.2's worked request, which does
not carry the attribute.

**The statement.** `codAziendaAuth` is defined as carrying a *list* of FLS11
codes — one per organisation that authorised the document viewing or retrieval.
Every other request attribute §4.2.5.2 defines is single-valued, and the worked
example — which carries none of the optional attributes — shows one
`AttributeValue` per `Attribute`.
Nothing says whether a list is written as several `AttributeValue` children of
one `Attribute`, as one delimited string in a single `AttributeValue`, or as
several `Attribute` elements sharing a name. The three are not
interchangeable to a receiver.

**What the code does.** Emits one `Attribute` element carrying one
`AttributeValue` per code. An empty or omitted list emits no element at all.

**The basis.** SAML 2.0 defines `Attribute` as carrying zero or more
`AttributeValue` children precisely so that a multi-valued attribute needs no
encoding of its own, and §4.2.5.2 says the body is structured in accordance with
the SAML specifications. A delimited string would have to invent a separator the
document does not give, and the region's other composite value — the
ApplicationID of Q-003 — separates on `^`, which is not a separator any SAML
reader would split on. Between a guess that follows the ambient standard and a
guess that invents a convention, the first is the one a receiver is more likely
to have implemented.

**The cost.** An IAP expecting a delimited string reads only the first code, or
none, and authorises against a shorter list than the caller intended. That
failure is silent: the request succeeds and the assertion comes back scoped more
narrowly than asked for, and the caller finds out at the X-Service Provider.
This is the one place in the request builder where being wrong does not announce
itself, which is why it is written down.

**The question as it would be sent.**

> `codAziendaAuth` is defined as conveying the list of FLS11 codes of the
> organisations that authorised document viewing or retrieval, but no worked
> example carries the attribute and no encoding for the list is given. Should a
> client emit one `Attribute` element with one `AttributeValue` child per code —
> which is what we currently do — or a single `AttributeValue` containing a
> delimited string, and if the latter, which separator? The same question
> applies to the `codAziendaAuth` attribute of the assertion, since it is
> described as inherited from the request.

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

### D-004 — Timestamps are written as whole seconds in UTC with a `Z` suffix

**Citations.** §4.2.5.2 (`IssueInstant`, `NotBefore` and `NotOnOrAfter`, each
of which it requires to be in UTC, and the worked request that carries all
three); XML Schema Part 2, `xs:dateTime`, which is the type SAML 2.0 declares
these attributes as.

Requiring UTC does not pin a lexical form. `xs:dateTime` admits fractional
seconds and admits any timezone offset, so `2026-08-21T09:00:00.123456+00:00`
and `2026-08-21T11:00:00+02:00` both name instants in UTC and both differ from
what the specification's examples write. The examples — `2014-01-20T13:51:13Z`,
`2013-10-15T16:09:30Z` — are the only evidence available, and they agree with
one another: whole seconds, `Z` rather than `+00:00`, no fractional part.

The library emits that form and no other. A caller's `Date` is truncated to a
whole second on the way in, towards the past, so a `NotBefore` never moves later
than the caller asked and a `NotOnOrAfter` never moves earlier — the requested
window is never widened by rounding. The truncated values are what the validity
check runs against, because they are what the IAP will see.

The cost: a caller needing sub-second precision cannot express it, and two
requests issued within the same second carry the same `IssueInstant`. Neither
matters for a validity window measured in hours, and the message ID is what
distinguishes two requests in any case. If a regional service ever needs finer
resolution, this is the decision to revisit.

### D-005 — The issue instant is not checked against the requested validity window

**Citations.** §4.2.5.2 (`IssueInstant` on the `AuthnRequest`, and `NotBefore` /
`NotOnOrAfter` on the `Conditions`, and the worked request carrying all three).

It would be natural to require that a request be issued inside the window it
asks for — a request created after its own `NotOnOrAfter` is asking for an
assertion that has already expired. The library does not check it, because
§4.2.5.2's worked request fails that check: it carries an `IssueInstant` in
January 2014 and a requested window in October 2013, some three months earlier.

Nothing in the prose relates the two values, so the example is not contradicting
a stated rule; it is simply showing that they are independent, or that the
example's timestamps were written at different times and never reconciled. Given
that, a check would be this library's invention rather than the specification's
requirement, and it would refuse the specification's own example.

What is checked is the window's internal consistency: `NotOnOrAfter` must be
strictly after `NotBefore`, once both are truncated to whole seconds. That one
does not depend on any reading of the document — `NotOnOrAfter` excludes its own
instant, so an equal or inverted pair asks for an assertion that is valid at no
moment at all, which no caller can have meant.

The cost: a caller with a clock error, or one that computes its window from the
wrong base, gets a request built and an assertion it cannot use. The failure
surfaces at the X-Service Provider as an expired assertion rather than at the
call site.

### D-006 — The schema-location hints in the worked example are not emitted

**Citations.** §4.2.5.2's worked request, which carries `xsi:schemaLocation` on
its `soap:Envelope`, `soap:Header`, `wsse:Security` and `soap:Body` elements;
XML Schema Part 1, which defines `xsi:schemaLocation` as a hint.

The example's hints pair each namespace with a bare filename —
`soap-envelope.xsd`, `ws-addr.xsd`, `saml-schema-protocol-2.0.xsd` — resolved
relative to the document. On the wire there is no document base to resolve them
against, so they name nothing. They are a validating editor's artefact, retained
when the example was pasted into the specification.

The library omits them. A processor is free to ignore `xsi:schemaLocation`
entirely, and one that honours it would be handed unresolvable references.
Copying them would also mean declaring the `xsi` namespace for no other purpose.

The cost: the output is not a byte-level match for the published example, and
anyone diffing the two will see these attributes as the difference. That is why
it is written down here rather than left to be rediscovered.

### D-007 — An authentication level other than the one attested is refused

**Citations.** §4.2.5.2 (the `authLevel` attribute, and the note that regional
projects may provide for further request parameters, deferring their definition
to RVE-1.d); §4.1.8, Table 3, which lists `authLevel` as Optional in both
directions.

`authLevel` is optional, and §4.2.5.2 names exactly one value for it — the URN
declaring two-factor authentication. It gives no code system to draw others
from, and unlike the request context (Q-004) there is no table to be a member
of. Whether the region has since defined a level above or below it, this excerpt
cannot say.

The library models the attribute as a union of one: omit it, or declare the one
level the specification attests. The smart constructor re-checks the value at
runtime, since a level typically reaches it from the same tenant configuration
the request context does.

The basis is the asymmetry with Q-003. An ApplicationID is a value the AULSS
allocated to the caller, so refusing an unrecognised one fails a deployment
nobody on site can fix. An authentication level is a value the caller *chooses*,
from a vocabulary of one, and an unattested URN is a claim about how the
operator authenticated that no regional document backs — the sort of claim an
IAP is entitled to reject, and one this library should not put on the wire
silently.

The cost: if the region has added a third level and this excerpt predates it, a
caller entitled to declare it cannot, and there is no escape hatch short of a
change here. The refusal is immediate and names the value it will accept, so the
failure is a blocked feature and a fast question rather than a wrong assertion.

### D-008 — The encrypted-username marker is written as an unprefixed attribute

**Citations.** §4.2.5.2 (the rule signalling an encrypted username, written as
`wsse:Username/@type`); §4.2.5.3 (the IAP's handling, which reads it back the
same way); the worked request, which carries a plaintext username and therefore
does not show the attribute at all.

The specification writes the rule in XPath. In XPath, a prefix on the element
step qualifies the element, and an unprefixed attribute name is in no namespace
— so `wsse:Username/@type` names an unprefixed `type` attribute on a qualified
`wsse:Username` element. Read as a literal fragment of XML instead, the same
string could be taken to mean `type` is itself in the `wsse` namespace. No
example settles it, because the only worked request sends a plaintext username.

The library emits the unprefixed form. Both occurrences in the document are
XPath — the rule and the IAP's handling of it — which is the reading that makes
them consistent, and an unprefixed attribute on a qualified element is the norm
throughout WS-Security and SAML, including every other attribute this library
emits.

The cost is the highest of any decision here, because unlike a namespace prefix
on an element this one is not cosmetic: `type` and `wsse:type` are different
attributes to a namespace-aware receiver. An IAP expecting the qualified form
would not see the marker at all, and would then attempt to use ciphertext as a
Directory Server username — a lookup failure reported as an unknown user, which
names neither the attribute nor the encryption. A caller sending encrypted
usernames should confirm this against its AULSS before going live; a caller
sending plaintext ones is unaffected, since the attribute is then absent.

### D-009 — A returned assertion is decoded as UTF-8, strictly

**Citations.** §4.1.6.2.2 (the assertion structure), which §4.2.6 adopts for the
RVE-1.b response; §4.6, which requires the assertion be spent exactly as
returned.

The specification names no character encoding for the assertion, and gives no
rule for reading the XML declaration of a document arriving as bytes. Every
worked example in the excerpt is ASCII, so none of them settles it either.

The validator decodes as UTF-8 and refuses bytes that are not valid UTF-8,
rather than consulting the document's own encoding declaration or falling back
to a legacy single-byte encoding. UTF-8 is the XML default for a document
without a declaration, it is what the request side emits, and the alternative —
implementing encoding detection over an unauthenticated document in order to
decide how to read it — is a parser this library has no reason to own.

Strict rather than replacing is the part that matters. A decoder substituting
`U+FFFD` for an undecodable sequence produces a document that parses, validates
and reads as an operator's tax code with one character silently changed. The
substitution is invisible at every subsequent step, including the identity
cross-check, which would then be comparing two corrupted values that agree.

The cost: an AULSS whose IAP returns an assertion in ISO-8859-1 — which nothing
in the excerpt forbids — would have every such assertion refused as malformed,
including ones the region considers valid. The refusal is loud and local, which
is the failure mode to prefer over a quietly altered identity, and the fix is
one decision in this module rather than a hunt through downstream comparisons.

### D-010 — A document a parser has to recover from is refused, not repaired

**Citations.** §4.1.6.2.2 (the mandatory `ds:Signature` over the assertion);
§4.6 (spent without modification of any kind).

The specification says nothing about how a client should parse what it receives,
because from its point of view a non-conforming document is simply not an
assertion. That leaves the choice of parser strictness to the client, and the
default of the parser this library uses is to recover from an error-level
problem and carry on.

The validator turns recovery off. A recovered document is one whose element tree
no longer corresponds to the bytes it came from, and every check downstream of
the parse — the window, the audience, the identity, and above all the binding of
the signature reference to the assertion identifier — would then be evaluated
against the parser's reconstruction rather than against what the region signed
and what the caller will spend. A validator whose answer is about a different
document than the one being sent is worse than one that declines to answer.

The cost: an IAP emitting an assertion with a defect a lenient parser would
paper over gets its assertions refused here, and the caller sees `malformed`
where a more forgiving client would have proceeded. That is the intended
trade: this library's answer is only meaningful about bytes it read exactly.

### D-011 — An assertion carrying a document type declaration is refused

**Citations.** §4.1.6.2.2, which lists the elements and attributes an assertion
carries and names no document type declaration; §4.6 (spent without
modification of any kind).

The excerpt neither permits nor forbids a `DOCTYPE`, and no worked example
carries one. The validator refuses any document that has one.

An internal subset is where an entity declaration would live, and an entity is a
name in the document that stands for content the parser substitutes. Against a
signed credential that is a way to make the element tree say something other
than what the bytes say — the same hazard D-010 describes, arriving through a
feature rather than through a defect. Refusing before reading the tree is
cheaper and more certain than reasoning about which substitutions are harmless.

The cost is small and worth naming anyway: an IAP that emitted a `DOCTYPE` for
some local reason would have its assertions refused as malformed, and the detail
says which check refused them.

### D-012 — An assertion timestamp must carry a time zone, and may carry anything else `xs:dateTime` allows

**Citations.** §4.1.6.2.2 (`NotBefore` and `NotOnOrAfter` on the assertion's
`Conditions`, each required to be in UTC format, and the worked assertion that
carries both); §4.2.5.2 (the same attributes on the request).

The specification says "in UTC format" and shows `Z`-suffixed whole seconds. It
does not say what a reader should do with the other lexical forms `xs:dateTime`
admits — fractional seconds, an explicit `+02:00` offset, or no time zone at
all — and a client has to decide, because a window it cannot read is a window it
cannot check.

The validator accepts any `xs:dateTime` that names an instant on its own:
whole or fractional seconds, `Z` or an explicit numeric offset. It refuses a
value with no time zone. A local time is a wall-clock reading rather than a
moment, so comparing one to a clock compares it to whichever zone the reader
happens to be in — two hosts in different zones would then reach different
verdicts about the same assertion, which is worse than either of them refusing
it. An explicit offset, by contrast, denotes exactly the same instant a `Z`
value would, and refusing it would be refusing a spelling.

The shape is checked with a pattern before the value reaches `Date.parse`, not
after. `Date.parse` is free to accept implementation-defined formats beyond the
one the language pins, and engines do; leaving the decision to it would make
whether an assertion is refused depend on which JavaScript runtime is running.

The cost: an IAP emitting a local-time `NotOnOrAfter` — which "in UTC format"
already forbids, so this is a cost only against a non-conforming IAP — has its
assertions refused as malformed rather than read in some assumed zone.

### D-013 — The returned window is not checked against the four-hour or fifteen-minute figures

**Citations.** §3.1.1 (the audience-restriction use case, where both figures
appear); Appendix A.5, Table 10 (`ERR_00033`, an assertion whose time interval
does not conform to the regional policies).

§3.1.1 says a generic assertion lasts four hours and that more restrictive
policies may be defined, giving fifteen minutes for document retrieval as an
example. The validator does not compare a returned window's length to either
figure, and does not refuse an assertion for being longer or shorter than the
service it names would suggest.

Both figures appear in a narrative use case describing what the Identity and
Assertion Provider does, not in a table of constraints on what an X-Service User
may accept, and the passage introduces them as an example of a policy mechanism
rather than as the policy. The mechanism is explicitly open: policies are
"defined at regional level" and per service, so the set of legitimate window
lengths is one the region holds and this library does not. `ERR_00033` exists
precisely because that judgement belongs to the party holding the policy — an
X-Service Provider — and this library is not one (see `src/regional-error-codes.ts`).

A client enforcing the figures anyway would refuse assertions the region
considers valid the first time an AULSS configured a five-hour window or a
thirty-minute one, and the refusal would be local, silent as to its real cause,
and wrong. Not checking has the opposite cost: an IAP misconfigured to issue a
year-long assertion is accepted here and refused at the service, which is a
failure that surfaces where the policy lives.

What *is* checked is that the caller's clock is inside the window, which needs
no policy to evaluate. An inverted or empty window is not given a verdict of its
own either: both bounds fail on their own terms and both are reported, which is
the whole truth about such a window and needs nothing invented.

### D-014 — Clock skew and estimated flight time are separate, required, caller-supplied inputs

**Citations.** §4.1.6.2.2 (`NotBefore` and `NotOnOrAfter`); Appendix A.5, Table
10 (`ERR_00031`, `ERR_00032`) and Table 12 (`ERR_00055`, date and time
misaligned).

The specification names no tolerance for a client whose clock differs from the
IAP's, and none for the time a call takes to arrive, while naming a regional
error code for a misaligned clock — so it expects the condition and leaves the
allowance to the client.

The validator takes the current instant as a required argument with no default,
and takes the two allowances as two separate required arguments rather than one
combined margin.

They are separate because they are different quantities that happen to share a
unit.

Clock skew moves **both** bounds earlier by the same amount, which is the same
thing as assuming this host's clock may be that far *behind* the issuer's. That
is the direction in which being wrong is dangerous: a clock that is behind
believes a window that has closed is still open, and spends an assertion the
X-Service Provider will refuse. A clock that is ahead makes the opposite
mistakes, and both of those are cheap — refusing an assertion just issued, or
refusing one that is genuinely still open a moment before its far bound.

Estimated flight time moves the far bound earlier again, and the near bound not
at all. It is not uncertainty; it is a real interval that will have elapsed
*after* this library answers, so an assertion that is valid now but expires
before the call carrying it lands is one this library should refuse rather than
let the X-Service Provider refuse.

The net effect is what the code reads: the near bound is `NotBefore` less the
skew, and the far bound is `NotOnOrAfter` less the skew *and* the flight time.
A single combined margin cannot produce both, and collapsing them gets the near
bound wrong in the direction that refuses assertions the IAP has only just
issued.

The recommended values are exported as named constants and never applied
silently, so a caller taking them has written down that it did.
`RECOMMENDED_CLOCK_SKEW_MS` is one minute — larger than the drift of a host that
synchronises its clock at all, smaller than any window the excerpt describes.
`RECOMMENDED_FLIGHT_TIME_MS` is five seconds and is documented in the source as
a **placeholder**: it stands in for the caller's own measured high-percentile
round trip to the regional services it calls, and nothing in the specification
supports the number. Neither figure is the region's, and the source says so.

The current instant is required rather than defaulted so that the validator can
be driven at a chosen moment by a test, and by a caller with a better time
source than this process's clock. The cost is one more argument at every call
site, which is the visible choice being bought.
### D-015 — The baseline service policy accepts a generic assertion, on an inference from RVE-1.a's table

**Citations.** §3.1.1 (the audience-restriction use case: a service holding
highly confidential data may turn away any assertion whose request did not name
it); §4.1.6.2.2 (the `AudienceRestriction` element, which it makes
optional, and the `Audience` sub-elements it puts no lower bound on); §4.1.8,
Table 3 (the RVE-1.a information-content table, which marks the audience
Optional in the request and Optional in the assertion); §4.2.6, which defines
the RVE-1.b response by reference to §4.1.6.2.2 and states nothing of its own.

Whether a regional service accepts an assertion that names no audience is not a
property of RVE-1.b. §3.1.1 makes it a property of the service, decided by the
organisation's own policies, and gives no list of which services decide which
way — only the worked example of a document consultation that needs a named
assertion where prescription sending does not. So the policy is caller-supplied: the audience is the URL of the one
service about to be called, and only the caller knows it.

The library still has to answer for a caller that names a service and says
nothing else. `BASELINE_SERVICE_POLICY` answers *accepts a generic assertion*,
and the code labels that as an inference from the RVE-1.a table rather than as
something the specification states for RVE-1.b. The read-across is: §4.2.6 has
no table of its own, the nearest one is RVE-1.a's, that table marks the audience
optional in both directions, and §4.1.6.2.2 makes the element a MAY. An
assertion without one is therefore conforming, and a library that refused it by
default would be refusing a document the region is entitled to issue.

The basis for labelling rather than simply choosing: Q-001 is the reason there
is no RVE-1.b table to read, and a default presented as a citation would be a
guess that a later reader could not tell from a fact. A caller whose service is
one of §3.1.1's confidential ones sets `refusesGenericAssertions` and the
inference stops mattering for them.

The cost is a fail-open in exactly one shape: a deployment that forgets to mark
a confidential service as confidential will accept a generic assertion locally
and have it refused by the X-Service Provider with `ERR_00044`, one round trip
later. That is the direction the specification's own optionality points, and the
alternative — refusing by default — would break every caller of every service
that has no audience policy at all.

### D-016 — Audience matching is exact, with normalisation behind a flag the caller sets

**Citations.** §4.1.6.2.2 (an `Audience` names its service by a URL given in
full); Appendix A.5, Table 11
(`ERR_00044`); §4.6 (the assertion is spent, unmodified, on the X-Service
Provider, which does its own check).

The specification says an `Audience` carries a complete URL and says nothing
about how to compare two of them. RFC 3986 makes a scheme and a host
case-insensitive, a default port removable and an empty path equivalent to `/`,
while leaving the path case-sensitive — so two spellings of one service are
possible and the document does not say whether they are one audience.

The library compares exactly by default and offers `audienceMatching:
'normalised'` per service.

The basis is which way each mode fails. This library's answer does not decide
anything: the X-Service Provider will run its own comparison on the assertion,
in a way §4.6 does not specify, and its answer is the one that matters.
Normalising by default would therefore let the library accept an assertion that
the real service then refuses — a local check that says yes where the remote one
says no is worse than no local check, because it moves the failure past the
point where the caller could still have re-requested cheaply. Exact matching
fails the other way: it may re-request an assertion that would in fact have been
accepted, which costs one round trip and no correctness.

Normalisation, when a caller does turn it on, is the WHATWG URL parser's own —
lowercased scheme and host, the scheme's default port dropped, an empty path
written as `/` — and nothing beyond it. The path case and a trailing slash on a
non-empty path stay significant, because RFC 3986 makes them significant and an
IAP that distinguishes two paths is entitled to. A value that does not parse as
a URL falls back to a comparison of the trimmed strings rather than throwing;
the value on the assertion's side is whatever the IAP wrote, and a validator
that crashed on it would turn a mismatch into an outage.

Whitespace around the value is stripped in both modes and is not part of the
choice: a URI cannot contain whitespace, so an indent an XML formatter added was
never part of the value. Stripping is not `xs:anyURI` collapse, which would also
fold internal whitespace runs — internal whitespace is left alone, and a value
carrying it correctly fails to match. On the policy's side the strip happens
once, where the policy is built, so `policy.audience` is a value the caller can
put into the re-request the refusal calls for.

The cost of the default is the round trip described above, and the cost of the
flag is that a caller can turn it on for a service whose real comparison is
stricter, reintroducing exactly the fail-open the default avoids. That is why it
is per-service and explicit rather than a global setting.

### D-017 — The service policy carries no permitted contexts and no permitted roles

**Citations.** §4.2.5.3.1 (the IAP's mandatory checks: the declared context
against the contexts enabled for the ApplicationID, the user client
authentication against the permitted types, the digital identity against a
configurable list); Appendix A.5, Table 11, which gives an X-Service Provider a
code for each of request context, role, user client authentication, audience and
ApplicationID; §2 (the boundary tables the organisation holds).

The X-Service Provider weighs five attributes and can refuse on any of them.
The service policy this library takes models one: the audience. The omission is
deliberate and is a trade-off rather than a gap.

Every one of the other four is decided against a table the organisation holds
and maintains — which contexts an ApplicationID may declare, which roles reach
which service, which authentication methods are permitted. This library has no
sight of those tables and no way to be told when one changes. A client-side copy
would be a second answer to a question the region already answers, and a staler
one: the day an AULSS grants a context, every deployment still carrying the old
list starts refusing assertions that have just become good. A local check that
fails closed against a stale list is worse than no local check, because the
remedy is a redeploy rather than a re-request.

The audience is the exception, and the reason is specific: the caller is the
party that asked for the audience. Checking it is the caller confirming its own
request was honoured before spending it, not the caller re-deciding an
entitlement the organisation granted. Nothing about it needs a table.

The cost: a context, role, authentication-method or ApplicationID problem is
discovered from the X-Service Provider's fault rather than locally, one round
trip later, and the library reports no failure for any of them. The regional
codes for all five are named in `src/regional-error-codes.ts` so that an inbound
fault can be branched on, which is where that diagnosis belongs.

### D-018 — Two AudienceRestriction elements are conjoined, not flattened

**Citations.** §4.1.6.2.2 (the optional `AudienceRestriction` element under
`Conditions`, whose sub-elements each name one X-Service Provider entitled to
accept the assertion, and of which there may be several or none); SAML 2.0 core,
which the specification profiles.

§4.1.6.2.2 describes one `AudienceRestriction` and neither permits nor forbids a
second, and no worked example carries one. SAML 2.0 core does settle it: each
`AudienceRestriction` is a condition in its own right, all conditions must hold,
and the audiences within one are a disjunction — so an assertion carrying two
restrictions is scoped to their intersection.

The validator implements the SAML reading: every restriction must name the
service, and one matching audience within a restriction satisfies it. A
restriction naming no service at all — which §4.1.6.2.2 permits, putting no
lower bound on the sub-elements — is satisfied by nobody, and is reported as a mismatch rather than as
the generic assertion of §3.1.1, because the document did declare a restriction.

The basis is that the X-Service Provider validates with a SAML stack, so the
SAML reading is the one that will actually be applied to the assertion, and
where the two readings differ this one is the stricter. A regional document that
never produces two restrictions costs nothing either way; one that does, and
means the intersection, is handled correctly.

The cost: if the region ever emits two restrictions intending their union, the
library refuses an assertion its X-Service Provider would have accepted. That
would be visible immediately, as a refusal naming the audience, rather than as a
silent acceptance.

### D-019 — The operator's tax code is compared, never validated

**Citations.** §4.1.6.2.2 (the subject's `NameID`, and the `ResponsibleParty`
attribute, both of which RVE-1.b populates with the tax code the IAP determined
by querying its DB or Directory Server); §4.1.8, Table 3, which marks both
Required and marks the responsible party *Checked*.

Neither section states a format for the value, and nothing in the excerpt names
a code system for it, gives a length, or offers a check character rule. The
validator therefore compares the two places the assertion carries the identity
and reports the value on the success branch, and does not ask whether either is
a well-formed Codice Fiscale.

The basis is that the question the library can answer is a different question
from the one a format check answers. §4.1.6.2.2 makes the IAP the authority on
the value: it derives it from the organisation's directory, and a regionally
issued temporary or surrogate identifier is exactly the sort of thing that
directory can hold and this library has never heard of. A format check would
therefore refuse assertions a regional service accepts, which is the failure
mode that leaves a paediatrician unable to retrieve a record.

It would also buy nothing. A well-formed tax code is not a real one, and the
identity risk §4.1.6.2.2 actually creates is the IAP resolving *two* people for
one request — which a format check passes and a comparison catches. So the
library checks that the assertion says one thing about who the operator is, and
leaves believing the thing to the region.

The cost: an assertion carrying an obviously corrupt identifier in both places
consistently is accepted here and refused by the X-Service Provider, one round
trip later, in the region's vocabulary rather than this library's.

### D-020 — The two identities are compared with case folded away

**Citations.** §4.1.6.2.2 (`NameID` and `ResponsibleParty`, both the tax code);
§4.1.6.2.2's worked assertion, which writes the same code in upper case in both
places.

The comparison folds case — locale-independently — and is otherwise exact. The
values are already free of the whitespace an indented document puts around them,
since a comparison that refused an assertion for how it was formatted would be
refusing formatting rather than identity.

The basis is that folding cannot lose a distinction that matters. A Codice
Fiscale is defined over letters and digits and the region writes it in upper
case, and case folding is injective on distinct letters — so two different tax
codes cannot fold to one, and the only pairs it merges are two spellings of the
same code. Folding therefore removes a way of refusing a correct assertion and
gives up no part of the check. Locale-independent, because whose operator this
is must not depend on the locale of the machine asking.

The cost: an IAP that used case to distinguish two identifiers — which no
regional document suggests, and which the tax code's own definition forbids —
would have that distinction ignored here. Contrast D-019: not validating the
format is a decision to leave a question alone, whereas this one answers a
question, and the answer is that case is not part of who the operator is.

### D-021 — The responsible party is required whatever the calling service asks

**Citations.** §4.1.8, Table 3, which marks `ResponsibleParty` Required in the
assertion and Checked by the actor; §4.2.5.3.1 (the checks are the
organisation's policy); Q-001, the absent pages where a required-attribute
matrix for the RVE-1.b *assertion* would have been stated.

Attribute presence is otherwise driven entirely by the policy the caller passes,
because §4.2.5.3.1 makes the checks an actor performs a matter of organisational
policy and §3.1.1 describes services that refuse an assertion another service
accepts. `ResponsibleParty` is the one exception: the validator requires it of
every assertion, whether the calling service named it or not.

The basis is that the library's own identity cross-check reads it. An assertion
that omits it is not an assertion that failed the cross-check — it is one the
cross-check cannot be run against, and a validator that quietly skipped the
check would make omitting the attribute the cheapest way past it. Table 3 marks
the attribute Required in the nearest surviving matrix, so requiring it is also
what the document in hand says, as far as it says anything.

The cost is a policy a caller cannot express: a service that genuinely accepts
an assertion with no responsible party cannot say so here. Nothing in the
excerpt describes such a service, and Q-001 is the question that would settle
it.

### D-022 — A local failure is annotated with the region's nearest code, not its exact one

**Citations.** Appendix A.5, Tables 11 and 12 (the codes an X-Service Provider
raises); Q-005, which establishes that those tables are open-ended; §4.2.5.3.1,
which makes the checks an actor performs a matter of organisational policy.

Every failure this library reports carries a regional error code beside it, and
no code in Appendix A.5 names the check that produced it. The tables name
outcomes the region reaches — *this value does not permit access*, *this tax
code does not match the one the AULSS holds* — reached against information the
region holds and this library does not. The library therefore annotates each
local failure with the nearest code the region has, and says in the type that
the annotation is a best match rather than a verdict.

Three of those choices are worth naming, because a reader could reasonably have
expected another:

- A **missing required attribute** takes the Table 11 code for that attribute
  where one exists, and ERR_00058 where none does. Table 11 grades values rather
  than noticing absences, and a required-attribute list is precisely an
  organisation's policy, which is what ERR_00058 names.
- A **missing `Role`** takes ERR_00060 rather than Table 11's ERR_00042. Both
  concern the role; only ERR_00060 concerns one that is not there, and ERR_00042
  is a judgement about a value that this library does not make.
- An **identity mismatch** takes ERR_00059. The region reaches that code by
  comparing the assertion against the AULSS's directory and this library reaches
  it by comparing the assertion against itself, but the disagreement is about
  the same value and no other code is about that value at all.

The basis is that the annotation exists to make one support conversation
possible, not to predict a fault. A caller branching on `regionalErrorCode`
rather than on the library's own failure code is branching on a best match, and
the type documentation says so.

The cost: an IAP or X-Service Provider that refused the same assertion might
report a different code, and a support engineer comparing the two would see two
codes for one problem. The library's own code is the stable one.

### D-023 — An assertion attesting more than one authentication level attests none

**Citations.** §4.1.6.2.2 (`authLevel`, and the one value it names); §4.1.8,
Table 3, which lists `authLevel` as a single optional parameter in both
directions; D-007.

The specification writes `authLevel` as one attribute with one value and never
contemplates two. SAML permits an attribute to carry several values, so an
assertion can arrive attesting two levels at once. The validator refuses it,
whether or not the calling service asked for a level at all.

The basis is that there is no safe reading. Taking the first value is the
collapsing this library refuses everywhere else — an assertion attesting the
required level *and* a weaker one would pass a check the weaker value was hidden
behind. Taking the strongest would have the library rank a scale the excerpt
does not publish (D-007). Reporting nothing on the success branch would hide an
attribute that is there. What is left is that an assertion contradicting itself
about how strongly the operator authenticated attests nothing, and no service is
safe for that — which is why the refusal is not conditional on the policy.

Annotated with ERR_00058 rather than ERR_00065, deliberately: ERR_00065 says a
service demanded a second factor, and on this path none did. See D-022.

The cost: if the region later defines `authLevel` as a list — as it did define
`codAziendaAuth` as one (Q-007) — this refuses a conforming assertion, and the
fix is here rather than in a caller's configuration.
