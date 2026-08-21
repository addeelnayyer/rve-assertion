/**
 * The policy of the regional service an assertion is about to be spent on.
 *
 * §3.1.1 is the reason this exists. A service holding highly confidential data
 * — consulting a clinical document is its example — may turn away any assertion
 * whose request did not name it. Whether a given X-Service Provider does that
 * is a property of that service and of the organisation's own policies, decided
 * outside the specification and outside this library.
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
 * `docs/spec-questions.md` (D-017).
 */

import { ValidationInputError } from './types.js';
import { isAbsoluteUri } from './uri.js';

/**
 * How an assertion's audience is compared against the service's own URL.
 *
 * `exact` is the baseline and fails closed — see {@link BASELINE_SERVICE_POLICY}.
 * `normalised` is for a tenant whose IAP is known to rewrite the URL it was
 * handed; it is argued, with its cost, in `docs/spec-questions.md` (D-016).
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
   * Whether this service refuses an assertion that names no audience at all,
   * which is the case §3.1.1 describes a confidential service as entitled to
   * refuse.
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
 * claims the specification states this for RVE-1.b — the argument, and the cost
 * of being wrong about it, are in `docs/spec-questions.md` (D-015). A caller
 * that knows its service is one of §3.1.1's confidential ones overrides it, and
 * the override is the point of the policy being caller-supplied.
 *
 * `exact` is not an inference from anything; it is the conservative half of a
 * choice the specification does not address at all (D-016).
 */
export const BASELINE_SERVICE_POLICY = {
  refusesGenericAssertions: false,
  audienceMatching: 'exact',
} as const satisfies Omit<ServicePolicy, typeof CHECKED | 'audience'>;

/**
 * Builds a checked {@link ServicePolicy}, or throws {@link ValidationInputError}
 * naming the value it refused.
 *
 * Throws rather than returning a result because a policy is assembled from the
 * caller's own configuration — see {@link ValidationInputError}.
 */
export function servicePolicy(input: ServicePolicyInput): ServicePolicy {
  const audienceMatching = input.audienceMatching ?? BASELINE_SERVICE_POLICY.audienceMatching;
  if (!AUDIENCE_MATCHING_MODES.includes(audienceMatching)) {
    throw new ValidationInputError(
      `${JSON.stringify(audienceMatching)} is not an audience matching mode. The modes are ${AUDIENCE_MATCHING_MODES.map((mode) => JSON.stringify(mode)).join(' and ')}.`,
    );
  }

  return {
    [CHECKED]: true,
    audience: checkedAudience(input.audience),
    refusesGenericAssertions:
      input.refusesGenericAssertions ?? BASELINE_SERVICE_POLICY.refusesGenericAssertions,
    audienceMatching,
  };
}

/**
 * The audience `input` names, checked and stored without the whitespace around
 * it. Throws {@link ValidationInputError} otherwise.
 *
 * Trimmed here rather than at each comparison, so that `policy.audience` is the
 * value a caller can use — an indent that arrived from tenant configuration
 * would otherwise be compared away silently and then travel onward into the
 * re-request the failure calls for. §4.1.6.2.2 asks an `Audience` to name its
 * service by a URL given in full, which `src/uri.ts` is the shared check for.
 */
function checkedAudience(value: string): string {
  const audience = value.trim();

  if (audience.length === 0) {
    throw new ValidationInputError(
      'The service audience is blank. It must be the URL, in full, of the service about to be called.',
    );
  }

  if (!isAbsoluteUri(audience)) {
    throw new ValidationInputError(
      `The service audience is ${JSON.stringify(value)}, which is not an absolute URI.`,
    );
  }

  return audience;
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
 * Module-internal: the validator is the only caller. Not on the public surface,
 * because nothing outside the library has an `Audience` value in hand to ask
 * about.
 */
export function audienceMatches(policy: ServicePolicy, candidate: string): boolean {
  // Trimmed, not normalised. A URI cannot contain whitespace, so an indent an
  // XML formatter put around the value was never part of the value, and a
  // comparison that kept it would be comparing the IAP's formatting. Internal
  // whitespace is left alone: a value carrying it is not a URI, and correctly
  // fails to match. The policy's own audience was trimmed when it was built.
  const found = candidate.trim();

  return policy.audienceMatching === 'exact'
    ? policy.audience === found
    : normalised(policy.audience) === normalised(found);
}
