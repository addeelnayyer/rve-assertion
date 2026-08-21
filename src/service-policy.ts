/**
 * The policy of the regional service an assertion is about to be spent on.
 *
 * §3.1.1 is the reason this exists. A highly confidential service — the
 * consultation of clinical documents is the example it gives — may refuse an
 * assertion created generically, and accept only one requested expressly for
 * it. Whether a given X-Service Provider does that is a property of that
 * service and of the organisation's own policies, decided outside the
 * specification and outside this library.
 *
 * So the policy is **caller-supplied**. The library holds no tenant
 * configuration, and the audience an assertion must name is the URL of the one
 * service about to be called, which only the caller knows. What ships here is a
 * baseline for the two questions the caller may not have an answer to, and the
 * baseline is labelled as an inference rather than as a citation — see
 * {@link BASELINE_SERVICE_POLICY}.
 *
 * ## What the policy does not carry
 *
 * No permitted request contexts, and no permitted roles. Both are checked —
 * §4.2.5.3.1 has the IAP check the declared context against the contexts
 * enabled for the ApplicationID, and Appendix A.5, Table 11 gives the X-Service
 * Provider a code for each of context, role, user client authentication,
 * audience and ApplicationID. All of those checks run against boundary tables
 * held by the organisation, which this library cannot see and does not sync.
 *
 * A client-side copy of them would be a second answer to a question the region
 * already answers, and a staler one: the day an AULSS grants a context, every
 * deployment carrying the old list starts refusing assertions that are now
 * good. The audience is the exception, and the reason it is the exception is
 * that the caller is the one that asked for the audience — it is checking its
 * own request was honoured, not re-deciding an entitlement. Argued in
 * `docs/spec-questions.md` (D-014).
 */

import { ServicePolicyError } from './types.js';

/**
 * How an assertion's audience is compared against the service's own URL.
 *
 * `exact` is the baseline and fails closed — see {@link BASELINE_SERVICE_POLICY}.
 * `normalised` is for a tenant whose IAP is known to rewrite the URL it was
 * handed; it is argued, with its cost, in `docs/spec-questions.md` (D-013).
 */
export type AudienceMatching = 'exact' | 'normalised';

/** The matching modes {@link servicePolicy} will build, for the runtime check. */
const AUDIENCE_MATCHING_MODES: readonly AudienceMatching[] = ['exact', 'normalised'];

/** Brands a policy as having been through {@link servicePolicy}. */
const CHECKED = Symbol('servicePolicy');

/**
 * What a caller says about the service it is about to call.
 *
 * Only the audience is required. The rest is the baseline unless the caller
 * knows better, which is the shape a value drawn from tenant configuration
 * actually has: an audience per service, and an override for the one or two
 * services whose behaviour the deployment has learned.
 */
export interface ServicePolicyInput {
  /**
   * The complete URL of the X-Service Provider about to be called, as
   * §4.1.6.2.2 has an `Audience` carry it.
   */
  readonly audience: string;

  /**
   * Whether this service refuses an assertion that names no audience at all —
   * the "created in a generic way" case of §3.1.1.
   */
  readonly refusesGenericAssertions?: boolean;

  /** How to compare. Omit for {@link BASELINE_SERVICE_POLICY}'s `exact`. */
  readonly audienceMatching?: AudienceMatching;
}

/**
 * A checked service policy, as {@link validateAssertion} takes it.
 *
 * Branded, so that the validator cannot be handed a policy whose audience was
 * never checked for being a URL. The request side brands `Rve1bRequest` for the
 * same reason and it is the same bargain: one place that can refuse, and no
 * re-checking anywhere downstream of it.
 */
export interface ServicePolicy {
  readonly [CHECKED]: true;

  /** The complete URL of the service about to be called. */
  readonly audience: string;

  /** Whether a generic assertion is refused for this service — §3.1.1. */
  readonly refusesGenericAssertions: boolean;

  /** How {@link audienceMatches} compares. */
  readonly audienceMatching: AudienceMatching;
}

/**
 * What the library assumes about a service the caller has said nothing about.
 *
 * **An inference, and labelled as one.** §4.2.6 defines the RVE-1.b response by
 * reference to §4.1.6.2.2 and states nothing of its own about audiences, and
 * there is no RVE-1.b information-content table — the nearest one is §4.1.8,
 * Table 3, which is RVE-1.a's. That table marks the audience Optional in both
 * the request and the assertion, and §4.1.6.2.2 says the `AudienceRestriction`
 * element *may* be present. Read across to RVE-1.b, that is a service which
 * accepts an assertion naming no audience — so the baseline does not refuse
 * one.
 *
 * The read-across is the inference. The excerpt in hand is missing the pages
 * that would confirm it (`docs/spec-questions.md`, Q-001), so nothing here
 * claims the specification states this for RVE-1.b. A caller that knows its
 * service is one of §3.1.1's confidential ones overrides it, and the override
 * is the point of the policy being caller-supplied.
 *
 * `exact` is not an inference from anything; it is the conservative half of a
 * choice the specification does not address at all (D-013).
 */
export const BASELINE_SERVICE_POLICY = {
  refusesGenericAssertions: false,
  audienceMatching: 'exact',
} as const satisfies Omit<ServicePolicy, typeof CHECKED | 'audience'>;

/**
 * Builds a checked {@link ServicePolicy}, or throws {@link ServicePolicyError}
 * naming the value it refused.
 *
 * Throws rather than returning a result because a policy is assembled from the
 * caller's own configuration — see {@link ServicePolicyError}.
 */
export function servicePolicy(input: ServicePolicyInput): ServicePolicy {
  const audienceMatching = input.audienceMatching ?? BASELINE_SERVICE_POLICY.audienceMatching;
  if (!AUDIENCE_MATCHING_MODES.includes(audienceMatching)) {
    throw new ServicePolicyError(
      `${JSON.stringify(audienceMatching)} is not an audience matching mode. The modes are ${AUDIENCE_MATCHING_MODES.map((mode) => JSON.stringify(mode)).join(' and ')}.`,
    );
  }

  return {
    [CHECKED]: true,
    audience: absoluteUri(input.audience),
    refusesGenericAssertions:
      input.refusesGenericAssertions ?? BASELINE_SERVICE_POLICY.refusesGenericAssertions,
    audienceMatching,
  };
}

/**
 * Returns `value` if it is an absolute URI, and throws otherwise.
 *
 * The request builder makes the same check on an audience it is about to
 * request, for the same reason: §4.1.6.2.2 has an `Audience` carry the complete
 * url of the service, and a relative reference cannot be compared against one.
 */
function absoluteUri(value: string): string {
  if (value.trim().length === 0) {
    throw new ServicePolicyError(
      'The service audience is blank. It must be the complete URL of the service about to be called.',
    );
  }

  try {
    new URL(value);
  } catch {
    throw new ServicePolicyError(
      `The service audience is ${JSON.stringify(value)}, which is not an absolute URI.`,
    );
  }

  return value;
}

/**
 * Strips the whitespace an XML pretty-printer put around a URI.
 *
 * Not normalisation: `xs:anyURI` collapses whitespace, so a newline and an
 * indent around the value are not part of the value in the first place, and a
 * comparison that treated them as part of it would be comparing the IAP's
 * formatting. Internal whitespace is left alone — it is not legal in a URI, so
 * a value carrying it correctly fails to match.
 */
function collapsed(value: string): string {
  return value.trim();
}

/**
 * The WHATWG-normalised form of `value`, or the value itself when it does not
 * parse as a URL.
 *
 * The fallback matters: the value on the assertion's side of the comparison is
 * whatever the IAP wrote, and a validator that threw on an unparseable one
 * would turn a mismatch into a crash on a document the caller cannot control.
 */
function normalised(value: string): string {
  try {
    return new URL(value).href;
  } catch {
    return value;
  }
}

/**
 * Whether `candidate`, an `Audience` value read off an assertion, names the
 * service `policy` describes.
 *
 * Exported for a caller inspecting an assertion it is not about to spend — a
 * cache deciding whether the entry it holds is the one this call needs, which
 * is the same question and should not be answered by a second implementation
 * of it.
 */
export function audienceMatches(policy: ServicePolicy, candidate: string): boolean {
  const wanted = collapsed(policy.audience);
  const found = collapsed(candidate);

  return policy.audienceMatching === 'exact'
    ? wanted === found
    : normalised(wanted) === normalised(found);
}
