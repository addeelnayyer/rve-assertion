/**
 * The single remedy that resolves a whole refusal.
 *
 * A validation can fail for several reasons at once — the semantic phase
 * reports every one it finds, deliberately — and a caller holding a list of
 * reasons still has to decide what to *do*. Doing it one reason at a time is
 * the failure mode this module exists to prevent: refresh, be refused for the
 * audience, re-request, be refused for the authentication level, and so on,
 * one round trip against a third-party IAP per reason, with a real chance of
 * cycling between two of them forever. So the answer is one remedy for the
 * whole set, and it is the remedy that resolves every reason at once.
 *
 * §3.1.1 is the reason a remedy is a value rather than prose. It describes the
 * audience case in exactly these terms: the client meets an error code,
 * re-requests naming the target service, and the operator never sees it — and
 * it offers the expired assertion as the case this is already familiar from.
 * Automatic recovery driven by what the refusal was is the behaviour the
 * specification expects of a client. This is that behaviour, derived once and
 * typed.
 *
 * ## Derived from a mapping, not from a ranking
 *
 * {@link RESOLVES} declares, for each remedy, the set of failure codes that
 * remedy resolves. Nothing declares an order. The aggregate is the **least**
 * remedy whose resolved set covers every observed failure, and the ordering
 * that talk of "escalating" refers to is read back out of those sets: a remedy
 * comes before another exactly when everything the first resolves the second
 * resolves too.
 *
 * That is subsumption, and it is what makes the one-round-trip claim true
 * rather than hopeful. A remedy chosen this way, executed correctly, also
 * resolves everything below it — so the caller does not fix one reason, spend a
 * round trip, and meet the next.
 *
 * The two cases worth working through are the two the tests pin:
 *
 * - *Expired and wrongly scoped.* A refresh returns a fresh assertion carrying
 *   the same wrong audience, which fails again. A scoped re-request returns one
 *   that is both fresh and correctly scoped. So a scoped re-request subsumes a
 *   refresh — because its resolved set contains `expired`, not because someone
 *   wrote it down as more severe.
 * - *Wrongly scoped and attesting no authentication level.* A scoped re-request
 *   returns a correctly scoped assertion that still attests no second factor.
 *   The step-up resolves both — but only because the escalation carries the
 *   audience forward, which is why {@link Remedy} threads the audience through
 *   every branch that acts.
 *
 * ## Fail-hard is outside the order, not on top of it
 *
 * `fail-hard` resolves the empty set. Modelling it as the greatest remedy would
 * have the aggregate claim it resolves everything beneath it, which is
 * backwards — it resolves nothing. It is what a caller gets when no remedy
 * covers the failures, and because it resolves nothing it can never be the
 * least covering remedy, so the search cannot return it by accident. One
 * failure nothing resolves removes every candidate at once, whatever is beside
 * it: that is what makes it absorbing.
 *
 * ## What a remedy is not
 *
 * It is not a promise. It names the round trip that *can* resolve the failures,
 * given an IAP that honours the request — a re-request naming this service can
 * only produce a correctly scoped assertion if the IAP is willing to scope one
 * that way. A caller that executes a derived remedy, is refused again in the
 * same way, and executes the same remedy again is looping on its own choice,
 * not on this library's. {@link AssertionFailure.unrecoverable} is the separate,
 * stronger claim, and the failures carry it.
 */

import type { AssertionFailure, AssertionFailureCode } from './assertion.js';
import { TWO_FACTOR_AUTHENTICATION_LEVEL, type AuthenticationLevel } from './request.js';
import type { ServicePolicy } from './service-policy.js';

/**
 * The one thing a caller does about a refusal.
 *
 * Four actions, and the payload of each says what executing it needs.
 *
 * - `fail-hard` — no round trip from here changes the answer. Something has to
 *   be fixed by someone: the caller's own slicing of a SOAP response, a clock,
 *   an AULSS directory. It carries nothing, because there is nothing to carry.
 * - `refresh` — ask the IAP for another assertion. The request that produced
 *   this one was acceptable to this service in every respect but its age.
 * - `rerequest-scoped` — ask again, naming this service as the audience. §3.1.1's
 *   own worked case: the client meets a refusal, re-requests specifying the
 *   service, and the operation is invisible to the user.
 * - `step-up-auth` — the operator authenticates again with a second factor, and
 *   the re-request follows. **This escalates out of the assertion layer**: this
 *   library names it, and the session layer performs it. See
 *   {@link deriveRemedy} for the contract that crosses the layers.
 *
 * ## The audience threads through every branch that acts
 *
 * `withAudience` is populated on every non-`fail-hard` remedy this library
 * derives, from the policy the assertion was validated against. It is not a
 * diff against what the caller sent — it is the service the next assertion must
 * be good for, so that a caller can execute the remedy holding nothing but the
 * remedy. On `rerequest-scoped` it is **required**, and that is the point: a
 * scoped re-request cannot be constructed without the audience it must be
 * scoped to. On the other two it is optional, because a refresh and a step-up
 * are both defined without reference to a service and a caller synthesising one
 * by hand may legitimately have no audience — but nothing here derives one
 * without it, so an escalation resumes into a correctly scoped request rather
 * than starting over.
 *
 * `withAuthenticationLevel` is the level the next request must ask for, and is
 * required on `step-up-auth` for the same structural reason: a step-up that
 * named no level would be one a caller could not execute.
 *
 * ## On the names
 *
 * The four action strings are the ticket's own prototype verbatim, discriminant
 * literals included — `step-up-auth` keeps its abbreviation, which the rest of
 * this repository would spell out, because it is the value on the public
 * surface and the specification-facing ticket is what named it.
 *
 * The payload fields do not: the prototype writes `withAuthLevel`, and this
 * writes `withAuthenticationLevel`. That is not the same call. "Authentication
 * level" is a glossary term (`CONTEXT.md`), and the repository already carries
 * it spelled out in every neighbouring place a caller reads — `authLevel` here
 * would be a synonym for a term the glossary pins, sitting beside
 * `ServicePolicy.requiredAuthenticationLevel` and
 * `ValidAssertion.authenticationLevel`.
 */
export type Remedy =
  | { readonly action: 'fail-hard' }
  | {
      readonly action: 'refresh';
      readonly withAudience?: string | undefined;
      readonly withAuthenticationLevel?: AuthenticationLevel | undefined;
    }
  | {
      readonly action: 'rerequest-scoped';
      readonly withAudience: string;
      readonly withAuthenticationLevel?: AuthenticationLevel | undefined;
    }
  | {
      readonly action: 'step-up-auth';
      readonly withAudience?: string | undefined;
      readonly withAuthenticationLevel: AuthenticationLevel;
    };

/** A remedy that resolves something — everything the aggregate is chosen from. */
type ResolvingAction = Exclude<Remedy['action'], 'fail-hard'>;

/**
 * What each remedy resolves. **The single source for the whole derivation** —
 * a failure carries no remedy field, so there is nowhere else this could be
 * said and nowhere else to keep in step with. Each membership is argued in
 * `docs/spec-questions.md` (D-025).
 *
 * Read each entry as a claim about a round trip, not as a severity:
 *
 * - A **refresh** asks the IAP the same question again, so the only thing it
 *   can change is the assertion's age. `expired` and nothing else. It cannot
 *   change the audience — that is the loop the design exists to prevent — and
 *   it cannot change an attribute or an authentication level, which come from
 *   the request and from the operator's session rather than from the passage
 *   of time.
 * - A **scoped re-request** names this service in the request. That fixes both
 *   audience refusals by construction, and yields a fresh assertion on the way,
 *   which is why `expired` is here too. `attribute-missing` is here because a
 *   re-request is the only round trip that can change what an assertion
 *   carries: §3.1.1 has the IAP parametrise an assertion by the service it was
 *   requested for, and §4.2.5.2 has the request declare what it wants in it. If
 *   the IAP will not supply the attribute, the re-request is refused the same
 *   way and the caller has spent one round trip rather than looped — see the
 *   module comment on what a remedy is not.
 * - A **step-up** ends in that same re-request, after the operator has reached
 *   the level. So it resolves everything the re-request does, plus the level.
 *
 * `malformed`, the four signature refusals, `not-yet-valid` and
 * `identity-mismatch` appear in no set, and their absence is the claim: no
 * remedy this library can name resolves them. A malformed document or a
 * signature that covers something else needs someone to look at what the IAP
 * returned; `not-yet-valid` needs a clock corrected, and a retry loop will not
 * outlast an issuer whose windows open in the future; `identity-mismatch` needs
 * the AULSS's own directory fixed, and asking it the same question returns the
 * same two answers.
 */
const RESOLVES: Readonly<Record<ResolvingAction, readonly AssertionFailureCode[]>> = {
  refresh: ['expired'],
  'rerequest-scoped': ['expired', 'audience-mismatch', 'audience-absent', 'attribute-missing'],
  'step-up-auth': [
    'expired',
    'audience-mismatch',
    'audience-absent',
    'attribute-missing',
    'authentication-level-not-attested',
  ],
};

/**
 * The remedies the aggregate is chosen from, read off {@link RESOLVES} rather
 * than listed again, so that a remedy cannot be added to one and forgotten in
 * the other.
 *
 * Insertion order, and not a ranking — nothing reads it as one. While the
 * resolved sets are comparable the fold below reaches the same answer whichever
 * order they arrive in, and where they are not it still answers with a remedy
 * that resolves every observed failure.
 */
const RESOLVING_ACTIONS = Object.keys(RESOLVES) as readonly ResolvingAction[];

/**
 * Whether `action` resolves every one of `codes`.
 *
 * Asked of two things, because they are one question. Handed the failures
 * observed, it says whether this remedy covers the refusal. Handed another
 * remedy's set, it says whether this remedy sits at or above that one — which
 * is the whole of the ordering. There is no list of remedies in severity order
 * anywhere in this module, and adding a code to a remedy's set moves that
 * remedy in the order rather than leaving a written one to contradict it.
 */
function resolves(action: ResolvingAction, codes: Iterable<AssertionFailureCode>): boolean {
  return [...codes].every((code) => RESOLVES[action].includes(code));
}

/**
 * The single remedy that resolves every failure in `failures`, for an assertion
 * validated against `policy`.
 *
 * The validator calls it and puts the answer on the refusal, so a caller
 * handling one validation has the remedy already and need not call this. It is
 * on the public surface for the case the validator cannot serve: a caller
 * merging failures from more than one source — this library's, and the codes an
 * IAP or X-Service Provider returned in a fault of its own — which is one
 * refusal to a user and must reach one remedy, not two.
 *
 * ## The step-up crosses a layer, and the contract is that it comes back
 *
 * `step-up-auth` is the one remedy this library cannot describe the execution
 * of. Acquiring a second factor is the session's work — the operator
 * authenticates again inside the calling application, and Appendix A.5's
 * ERR_00065 is the region's name for a service demanding it. What this layer
 * owes the session layer is the audience, and what the session layer owes this
 * one is to come back with it: resumption re-enters a re-request naming the
 * same service, rather than starting over generically and meeting the audience
 * refusal it had already got past. `withAudience` on the step-up is that
 * contract written into the payload.
 */
export function deriveRemedy(
  failures: readonly [AssertionFailure, ...AssertionFailure[]],
  policy: ServicePolicy,
): Remedy {
  const codes = new Set(failures.map((failure) => failure.code));

  const covering = RESOLVING_ACTIONS.filter((action) => resolves(action, codes));

  // Fail-hard first, and outside the order rather than on top of it. It
  // resolves the empty set, so it can never be the least covering remedy and
  // the fold below can never reach it — this is the only place it is decided.
  // One failure that no remedy resolves empties this list whatever is beside
  // it, which is what absorbing means. It carries nothing: see {@link Remedy}.
  if (covering.length === 0) {
    return { action: 'fail-hard' };
  }

  // The least of them. Folded rather than searched so that it is total, and so
  // that it does not quietly depend on the sets forming a chain: keep whichever
  // candidate the other resolves everything of, which is the one whose resolved
  // set is contained in the other's. If two remedies ever became incomparable,
  // this still answers with one that resolves every observed failure — where a
  // search for a unique least element would answer fail-hard, which would be a
  // lie about remedies that demonstrably resolve them.
  const least = covering.reduce((best, action) =>
    resolves(best, RESOLVES[action]) ? action : best,
  );

  const withAudience = policy.audience;
  const withAuthenticationLevel = policy.requiredAuthenticationLevel;

  switch (least) {
    case 'refresh':
      return { action: 'refresh', withAudience, withAuthenticationLevel };

    case 'rerequest-scoped':
      return { action: 'rerequest-scoped', withAudience, withAuthenticationLevel };

    case 'step-up-auth':
      return {
        action: 'step-up-auth',
        withAudience,
        // The service's own requirement, and otherwise the one level
        // §4.1.6.2.2 attests. The fallback is reached: an assertion attesting
        // two levels attests none whatever the policy asked for (D-023), so
        // this failure arises against a service that required nothing, and a
        // step-up naming no level is one a caller cannot execute. Today the two
        // sides are the same value, since `AuthenticationLevel` is a union of
        // one (D-007); the day the region publishes a second, the service's
        // requirement is the one that must win. See D-026.
        withAuthenticationLevel: withAuthenticationLevel ?? TWO_FACTOR_AUTHENTICATION_LEVEL,
      };
  }
}
