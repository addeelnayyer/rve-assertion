/**
 * The regional code vocabulary an RVE-1.b request declares itself in —
 * Appendix A.
 *
 * Three request attributes draw on this vocabulary, and the specification
 * treats them differently, so this module does too: the request context is
 * drawn from a closed table and validated against it, the user client
 * authentication code is pinned to one value for the transaction, and the
 * ApplicationID is an opaque string nothing here constrains.
 *
 * **No label from the specification's tables appears here.** The excerpt was
 * shared under a no-redistribution condition, so the codes are reproduced —
 * they are identifiers the library has to emit — and the plain-language names
 * beside them in the source tables are not. A reader who needs to know which
 * clinical context a code names reads Appendix A.2, Table 5. The cost is real:
 * a caller choosing a context cannot do it from this file alone.
 */

/**
 * The clinical context codes of Appendix A.2, Table 5, in the table's own row
 * order so that a reader with the specification open can follow along.
 *
 * Transcribed as the table gives it, including the two places the table looks
 * to have drifted — `C.4.2` where the numbering suggests `C.5.2`, and the
 * absent `C.6.4` — and excluding `C.1.6`, which §4.2.5.2's worked request
 * declares and this table does not define. All three are argued in
 * `docs/spec-questions.md` (Q-004).
 */
export const REQUEST_CONTEXTS = [
  'C.1.1',
  'C.1.2',
  'C.1.3',
  'C.1.4',
  'C.2.1',
  'C.2.2',
  'C.2.3',
  'C.2.4',
  'C.3.1',
  'C.3.2',
  'C.4',
  'C.5.1',
  'C.4.2',
  'C.6.1',
  'C.6.2',
  'C.6.3',
  'C.6.5',
  'C.6.6',
  'C.6.7',
  'C.7.1',
  'C.7.2',
  'C.7.3',
  'C.7.4',
  'C.7.5',
  'C.7.6',
  'C.7.7',
  'C.7.8',
  'C.7.9',
  'C.7.10',
  'C.7.11',
  'C.7.12',
  'C.7.13',
  'C.7.14',
  'C.7.15',
  'C.7.16',
  'C.8',
  'C.9',
  'C.10',
  'C.11',
  'C.11.1',
  'C.12',
  'C.13.1',
] as const;

/**
 * The declared purpose of the transaction, as a closed union over
 * {@link REQUEST_CONTEXTS}.
 *
 * Closed because the check the IAP performs is a membership test against the
 * contexts the organisation has enabled for the calling ApplicationID
 * (§4.2.5.3.1), and a code outside the regional table cannot be a member of any
 * such set. The cost of closing it is argued in `docs/spec-questions.md`
 * (Q-004).
 */
export type RequestContext = (typeof REQUEST_CONTEXTS)[number];

const REQUEST_CONTEXT_LOOKUP: ReadonlySet<string> = new Set(REQUEST_CONTEXTS);

/**
 * Narrows an unknown value to a {@link RequestContext}.
 *
 * Takes `unknown` rather than `string` because a request context typically
 * reaches the library from tenant configuration — a database column, a
 * deployment secret, a JSON file — where it is a string only by convention and
 * the compiler's word for it is worth nothing. This is the seam at which that
 * convention gets checked.
 *
 * Reports rather than throws, so the caller decides whether a misconfigured
 * tenant is a startup failure or a per-request one.
 */
export function isRequestContext(value: unknown): value is RequestContext {
  return typeof value === 'string' && REQUEST_CONTEXT_LOOKUP.has(value);
}

/**
 * The user client authentication code RVE-1.b declares — §4.2.5.2.
 *
 * Pinned by the specification rather than chosen per request: RVE-1.b *is* the
 * transaction in which the trusted application authenticated the operator
 * itself, so a caller able to pass a different code would be able to describe a
 * transaction it is not performing. A constant rather than a literal at the
 * call site because `docs/spec-questions.md` (Q-002) may yet move this value,
 * and when it does there should be one place to move it.
 */
export const RVE_1B_USER_CLIENT_AUTHENTICATION = 'A.1.1';

/**
 * The identifier of a registered installation — §4.2.5.2.
 *
 * A plain string alias, carrying no validation and no branding. The AULSS
 * allocates the value and the IAP checks it against its own allowlist; the
 * library's only job is to transmit what it was given. The alias exists so that
 * signatures name what they take.
 */
export type ApplicationId = string;

/**
 * What an {@link ApplicationId} looks like, measured against the two forms the
 * specification attests.
 *
 * - `caret-separated` — the three-part form §4.2.5.2's prose describes.
 * - `bare` — the single-token form its worked example carries.
 * - `unrecognised` — neither. Not a verdict of invalidity, and the boundary is
 *   this library's reading rather than the excerpt's: the specification states
 *   no arity rule and no rule about empty or space-padded parts, so a value
 *   such as `app^3` is reported `unrecognised` on the strength of the
 *   three-part form alone.
 */
export type ApplicationIdShape = 'caret-separated' | 'bare' | 'unrecognised';

/** Segment count of the caret-separated form: product, minor release, installation. */
const CARET_SEPARATED_SEGMENTS = 3;

/**
 * Reports which attested form `applicationId` takes, for a caller that wants to
 * check tenant configuration at startup.
 *
 * **Advisory. Nothing in this library consults it**, and a request builds with
 * any ApplicationID the caller supplies, including an `unrecognised` one. Why
 * neither form is enforced is argued in `docs/spec-questions.md` (Q-003). What
 * this affords instead is a deployment check: a tenant whose ApplicationID is
 * `unrecognised` is worth a warning in an onboarding log, where a human can
 * compare it against the registration the AULSS issued.
 *
 * Never throws. There is no input it can be handed that is a programming error,
 * because every input is a value some AULSS might have allocated.
 */
export function applicationIdShape(applicationId: ApplicationId): ApplicationIdShape {
  if (applicationId !== applicationId.trim() || applicationId.length === 0) {
    return 'unrecognised';
  }

  const segments = applicationId.split('^');
  if (segments.length === 1) {
    return 'bare';
  }

  const wellFormed =
    segments.length === CARET_SEPARATED_SEGMENTS &&
    segments.every((segment) => segment.length > 0 && segment === segment.trim());

  return wellFormed ? 'caret-separated' : 'unrecognised';
}
