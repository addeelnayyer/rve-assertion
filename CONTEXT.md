# Glossary

The vocabulary this repository uses, as the Veneto regional security
specification uses it. These terms are load-bearing — an approximation of them
will not survive a technical conversation with the region — so the code, the
issues, the tests and the documents all use the words defined here rather than
synonyms.

Vocabulary only. Nothing here describes how the library implements anything;
that lives in the README, in `docs/spec-questions.md`, and in the code.

---

**AULSS** — *Azienda ULSS*, a local health authority in the Veneto region. Each
AULSS runs its own instance of the regional identity infrastructure, holds its
own directory of operators, and issues its own trust material. There is no
single regional issuer; there is one per AULSS.

**IAP** — Identity and Assertion Provider. The AULSS-operated service that
authenticates or vouches for an operator and issues the SAML assertion that
authorises a call to a regional healthcare service. It is the counterparty this
library talks to: the recipient of the request, and the issuer of the assertion.

**Assertion** — the signed SAML 2.0 statement the IAP issues, carrying who the
operator is, what they are entitled to do, which services it is scoped to, how
strongly they authenticated, and for how long it remains usable. It is the
credential every outbound call to a regional service must carry.

**X-Service User** — the role of the party consuming a regional healthcare
service and therefore needing an assertion to present. The calling application
is the X-Service User: it requests the assertion and later spends it.

**X-Service Provider** — the role of the party exposing a regional healthcare
service and therefore consuming a presented assertion. The electronic health
record, document query and retrieval, e-prescription and the patient registry
are X-Service Providers.

**Responsible party** — the human being answerable for the transaction: the
identified operator on whose behalf the call is made, and to whom the regional
audit trail attributes it. For this library's host application this is the
family pediatrician who is signed in. The assertion carries the responsible
party's identity in its own right, distinctly from the identity of the software
making the call.

**Operator tax code** — the *Codice Fiscale*, the Italian personal tax
identifier, and the value the regional infrastructure identifies the responsible
party by. The IAP derives it from its own directory rather than from anything
the caller sends, and an assertion carries it in two places that must agree.
This repository says "operator tax code" in prose and code, and "Codice Fiscale"
only where it cites the specification's own wording.

**ApplicationID** — the identifier of a specific installation of a specific
software product, registered with the AULSS and allowlisted by it. It names
*which deployment is calling*, not which person — the responsible party covers
that. It is the value against which the IAP checks whether a caller is entitled
to the request context it declares.

**Tenant** — the calling application's own unit of separation: one customer
practice, bound to the one AULSS whose IAP serves it, with its own endpoint,
credentials and ApplicationID. "Tenant" is the application's vocabulary, not
the specification's; the specification's corresponding notion is the AULSS the
caller is registered with.

**Audience** — the regional service, or set of services, an assertion is scoped
to. An assertion carries the audiences it is valid for, and a service that
considers itself confidential refuses one that names an audience broader than
itself. An audience is what makes an assertion usable for *this* call rather
than for calls in general.

**Request context** — the declared purpose of the transaction the operator is
performing, drawn from the regional vocabulary of purposes. The IAP checks the
declared context against the contexts the calling application is permitted.

**User client authentication** — how the operator's client established the
operator's identity in the first place: the method, rather than the strength.
The regional vocabulary pins one value per assertion transaction, and RVE-1.b's
value says that the trusted application authenticated the operator itself. It is
distinct from the **authentication level**, which grades how strong that
authentication was rather than naming what performed it.

**Authentication level** — how strongly the responsible party authenticated,
expressed on the regional scale. A service may require a level above the one the
operator's current session was established at, which is a demand for further
authentication rather than a rejection of the operator.

**RVE-1.b** — the assertion transaction for *authorisation issued for trusted
applications*: an application that authenticates its own operators with its own
credentials, and is trusted by the AULSS on the strength of mutual TLS and an
ApplicationID allowlist, asking the IAP for an assertion for one of them. It is
the one of the specification's four assertion transactions that the calling
application performs.

**Regional error code** — a code from the region's own vocabulary of failure
reasons, reported by an IAP or an X-Service Provider. It is the vocabulary a
support conversation with the region is conducted in.
