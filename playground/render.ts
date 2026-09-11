/**
 * The page's DOM. It is built once and then brought up to date from a
 * {@link Model} and the view composed from it, so a pill keeps focus through
 * every change it causes. Whatever the library says reaches the page as text:
 * nothing here writes markup from a value.
 */

import type { Remedy } from '../src/index.js';
import {
  ASSERTION_SECTIONS,
  followsRequest,
  PRESETS,
  REQUEST_CONTROLS,
  type AssertionResult,
  type ComposerState,
  type ComposerView,
  type Control,
  type DerivedFact,
  type PresetId,
  type RequestResult,
} from './composer.js';
import { pretty } from './fixtures.js';

export type XmlTab = 'assertion' | 'request';

export interface Model {
  readonly state: ComposerState;
  /** The preset the assertion and service policy still match, if any. */
  readonly preset: PresetId | null;
  readonly xmlTab: XmlTab;
}

export type Action =
  | { readonly type: 'control'; readonly control: Control; readonly value: string }
  | { readonly type: 'preset'; readonly id: PresetId }
  | { readonly type: 'follow'; readonly on: boolean }
  | { readonly type: 'tab'; readonly tab: XmlTab };

type Dispatch = (action: Action) => void;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = '',
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className !== '') element.className = className;
  element.append(...children);
  return element;
}

interface MountedControl {
  readonly control: Control;
  readonly fieldset: HTMLFieldSetElement;
  readonly inputs: readonly (readonly [string, HTMLInputElement])[];
  readonly note: HTMLElement | null;
}

function mountControl(control: Control, dispatch: Dispatch): MountedControl {
  const legend = el('legend', 'control-label', control.label);
  const note = followsRequest(control) ? el('span', 'control-note', 'Follows the request') : null;
  if (note !== null) legend.append(note);

  const pills = el('div', control.mono ? 'pills pills--mono' : 'pills');
  const inputs = control.options.map((option) => {
    const input = el('input');
    input.type = 'radio';
    input.name = `${control.group}.${control.key}`;
    input.value = option.value;
    input.addEventListener('change', () => dispatch({ type: 'control', control, value: option.value }));

    const face = el('span', 'pill-face', option.label);
    if (option.note !== undefined) face.append(el('span', 'pill-note', option.note));
    pills.append(el('label', 'pill', input, face));
    return [option.value, input] as const;
  });

  return { control, fieldset: el('fieldset', 'control', legend, pills), inputs, note };
}

/** The value a control shows: the request as set, the rest as judged. */
function shownValue(control: Control, state: ComposerState, view: ComposerView): string {
  switch (control.group) {
    case 'request':
      return state.request[control.key];
    case 'assertion':
      return view.assertion[control.key];
    case 'policy':
      return view.policy[control.key];
  }
}

function requestStatus(request: RequestResult): HTMLElement {
  if (request.outcome === 'built') {
    const bytes = request.byteLength.toLocaleString('en-GB');
    return el('div', 'status status--built', el('p', 'status-head', `Envelope built · ${bytes} bytes`));
  }
  return el(
    'div',
    'status status--thrown',
    el('p', 'status-head', `${request.errorName}: no envelope was built`),
    el('p', 'status-detail', request.message),
  );
}

function derivedRows(facts: readonly DerivedFact[]): HTMLElement[] {
  return facts.map((fact) =>
    el(
      'div',
      fact.holds ? 'derived-row' : 'derived-row derived-row--fails',
      el('dt', '', fact.label),
      el('dd', '', fact.value),
    ),
  );
}

// ------------------------------------------------------------ assertion --

const REMEDY_GLOSS: Record<Remedy['action'], string> = {
  refresh: 'Ask the IAP again for an assertion with the same scope.',
  'rerequest-scoped': 'Ask the IAP again, scoped to this service.',
  'step-up-auth': 'Authenticate the operator further, then ask again.',
  'fail-hard': 'No further request helps. Stop, and report the failures.',
};

const plural = (count: number, noun: string): string => `${count} ${noun}${count === 1 ? '' : 's'}`;

function orUnset(value: string | undefined, unset: string): Node | string {
  return value === undefined ? el('span', 'unset', unset) : value;
}

function verdictOf(result: AssertionResult): { word: string; sub: string } {
  switch (result.outcome) {
    case 'valid':
      return {
        word: 'Accepted',
        sub: result.warnings.length === 0 ? 'With no warnings.' : `With ${plural(result.warnings.length, 'warning')}.`,
      };
    case 'invalid':
      return { word: 'Refused', sub: `${plural(result.failures.length, 'failure')}, one remedy.` };
    case 'thrown':
      return { word: 'Threw', sub: `${result.where} refused its input, so no assertion was judged.` };
  }
}

function field(term: string, name: string, value: Node | string): HTMLElement {
  return el(
    'div',
    'field',
    el('dt', '', el('span', 'field-term', term), el('code', 'field-name', name)),
    el('dd', '', value),
  );
}

function remedyRow(term: Node | string, ...value: (Node | string)[]): HTMLElement {
  return el('div', 'remedy-row', el('dt', '', term), el('dd', '', ...value));
}

function resultBody(result: AssertionResult): HTMLElement[] {
  switch (result.outcome) {
    case 'valid': {
      const fields = el(
        'dl',
        'fields',
        field('Operator tax code', 'operatorTaxCode', result.operatorTaxCode),
        field('Usable until', 'usableUntil', result.usableUntil),
        field(
          'Audiences',
          'audiences',
          result.audiences.length === 0
            ? el('span', 'unset', 'None: a generic assertion')
            : result.audiences.join('\n'),
        ),
        field('Authentication level', 'authenticationLevel', orUnset(result.authenticationLevel, 'Not attested')),
      );
      const warnings = el(
        'ul',
        'warnings',
        ...result.warnings.map((warning) =>
          el(
            'li',
            'warning',
            el('code', 'warning-code', warning.code),
            el('p', 'warning-detail', warning.detail),
          ),
        ),
      );
      return result.warnings.length === 0 ? [fields] : [fields, warnings];
    }

    case 'invalid': {
      const { remedy } = result;
      const action = remedyRow(
        'Remedy',
        el('code', '', remedy.action),
        el('span', 'remedy-gloss', REMEDY_GLOSS[remedy.action]),
      );
      action.classList.add('remedy-row--action');
      const rows =
        remedy.action === 'fail-hard'
          ? [action]
          : [
              action,
              remedyRow(el('code', '', 'withAudience'), orUnset(remedy.withAudience, 'Not set')),
              remedyRow(
                el('code', '', 'withAuthenticationLevel'),
                orUnset(remedy.withAuthenticationLevel, 'Not set'),
              ),
            ];

      const failures = el(
        'ol',
        'failures',
        ...result.failures.map((failure) =>
          el(
            'li',
            'failure',
            el(
              'div',
              'failure-head',
              el('code', 'failure-code', failure.code),
              el('code', 'chip', failure.regionalErrorCode),
              el(
                'span',
                failure.unrecoverable ? 'recover recover--yes' : 'recover',
                `unrecoverable: ${failure.unrecoverable ? 'yes' : 'not established'}`,
              ),
            ),
            el('p', 'failure-detail', failure.detail),
          ),
        ),
      );
      return [el('dl', 'remedy', ...rows), failures];
    }

    case 'thrown':
      return [
        el(
          'div',
          'thrown',
          el('p', 'thrown-head', el('code', '', result.errorName), ' from ', el('code', '', `${result.where}()`)),
          el('p', 'thrown-message', result.message),
        ),
      ];
  }
}

function xmlText(tab: XmlTab, view: ComposerView): string {
  if (tab === 'request') {
    return view.request.outcome === 'built'
      ? view.request.xml
      : `No envelope was built: ${view.request.errorName}.`;
  }
  return view.result.xml === '' ? '(zero bytes)' : pretty(view.result.xml);
}

// ----------------------------------------------------------------- page --

function columnHeading(id: string, number: string, title: string): HTMLElement {
  const numeral = el('span', 'col-number', number);
  numeral.setAttribute('aria-hidden', 'true');
  const heading = el('h2', 'col-heading', numeral, title);
  heading.id = id;
  return heading;
}

function column(className: string, headingId: string, ...children: HTMLElement[]): HTMLElement {
  const section = el('section', `col ${className}`, ...children);
  section.setAttribute('aria-labelledby', headingId);
  return section;
}

const XML_TABS: readonly (readonly [XmlTab, string])[] = [
  ['assertion', 'Assertion bytes'],
  ['request', 'Request envelope'],
];

export function mountComposer(root: HTMLElement, dispatch: Dispatch) {
  // Masthead
  const arrow = el('span', 'arrow');
  arrow.setAttribute('aria-hidden', 'true');
  const title = el('h1', '', 'Request', arrow, el('span', 'visually-hidden', ' to '), 'Assertion');

  const presetButtons = (Object.keys(PRESETS) as PresetId[]).map((id) => {
    const button = el('button', 'preset', PRESETS[id].label);
    button.type = 'button';
    button.addEventListener('click', () => dispatch({ type: 'preset', id }));
    return [id, button] as const;
  });
  const presetLabel = el('p', 'eyebrow', 'Start from');
  presetLabel.id = 'presets-label';
  const presetList = el('div', 'preset-list', ...presetButtons.map(([, button]) => button));
  presetList.setAttribute('role', 'group');
  presetList.setAttribute('aria-labelledby', presetLabel.id);

  const masthead = el(
    'header',
    'masthead',
    el(
      'div',
      '',
      title,
      el(
        'p',
        'lede',
        'Shape an RVE-1.b request, break the assertion the IAP returns, and read what the library decides.',
      ),
    ),
    el('div', 'presets', presetLabel, presetList),
  );

  // 01: the request
  const status = el('div');
  const derived = el('dl', 'derived');
  const requestControls = REQUEST_CONTROLS.map((control) => mountControl(control, dispatch));
  const requestColumn = column(
    'col--request',
    'heading-request',
    columnHeading('heading-request', '01', 'Build the request'),
    status,
    el('section', 'section', el('h3', 'section-title', 'Derived from the request'), derived),
    el('div', 'section', ...requestControls.map((mounted) => mounted.fieldset)),
  );

  // 02: the assertion and service policy
  const followInput = el('input');
  followInput.type = 'checkbox';
  followInput.setAttribute('role', 'switch');
  followInput.addEventListener('change', () => dispatch({ type: 'follow', on: followInput.checked }));
  const followTrack = el('span', 'follow-track');
  followTrack.setAttribute('aria-hidden', 'true');
  const follow = el(
    'label',
    'follow',
    followInput,
    followTrack,
    el(
      'span',
      'follow-text',
      el('span', 'follow-title', 'Follow the request'),
      el(
        'span',
        'follow-detail',
        'The request’s audiences become the audience restriction, and its authentication level becomes the one the service policy requires.',
      ),
    ),
  );
  const followRefused = el(
    'p',
    'follow-refused',
    'The request was refused, so there is nothing to follow. The controls below apply as set.',
  );

  const assertionControls: MountedControl[] = [];
  const sections = ASSERTION_SECTIONS.map((section) => {
    const mounted = section.controls.map((control) => mountControl(control, dispatch));
    assertionControls.push(...mounted);
    return el(
      'section',
      'section',
      el('h3', 'section-title', section.title),
      ...mounted.map((control) => control.fieldset),
    );
  });
  const assertionColumn = column(
    'col--assertion',
    'heading-assertion',
    columnHeading('heading-assertion', '02', 'Shape the assertion and service policy'),
    follow,
    followRefused,
    ...sections,
  );

  const verdict = el('p', 'verdict');
  const verdictSub = el('p', 'verdict-sub');
  const verdictBlock = el('div', 'verdict-block', verdict, verdictSub);
  verdictBlock.setAttribute('aria-live', 'polite');
  const body = el('div', 'result-body');

  const xml = el('pre', 'xml');
  xml.id = 'xml-panel';
  xml.tabIndex = 0;
  xml.setAttribute('role', 'tabpanel');
  const tabList = el('div', 'tabs');
  tabList.setAttribute('role', 'tablist');
  tabList.setAttribute('aria-label', 'XML');
  const tabs = XML_TABS.map(([id, label], index) => {
    const tab = el('button', 'tab', label);
    tab.type = 'button';
    tab.id = `tab-${id}`;
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', xml.id);
    tab.addEventListener('click', () => dispatch({ type: 'tab', tab: id }));
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      const next = XML_TABS[(index + 1) % XML_TABS.length];
      if (next === undefined) return;
      dispatch({ type: 'tab', tab: next[0] });
      document.getElementById(`tab-${next[0]}`)?.focus();
    });
    tabList.append(tab);
    return [id, tab] as const;
  });

  const resultColumn = column(
    'col--result',
    'heading-result',
    columnHeading('heading-result', '03', 'validateAssertion says'),
    verdictBlock,
    body,
    el('div', 'xml-block', tabList, xml),
  );

  // On a narrow screen the verdict sits below every control, so a bar at the
  // foot of the screen carries it until the result column scrolls into view.
  const dockWord = el('span', 'dock-word');
  const dockSub = el('span', 'dock-sub');
  const dock = el('a', 'dock', dockWord, dockSub, el('span', 'dock-go', 'Read the result'));
  dock.href = '#heading-result';
  new IntersectionObserver(([entry]) => {
    dock.hidden = entry?.isIntersecting ?? false;
  }).observe(resultColumn);

  root.replaceChildren(
    el('div', 'page', masthead, el('main', 'columns', requestColumn, assertionColumn, resultColumn), dock),
  );

  return {
    update(model: Model, view: ComposerView): void {
      const { state } = model;
      arrow.dataset['following'] = view.following;

      for (const [id, button] of presetButtons) {
        button.setAttribute('aria-pressed', String(model.preset === id));
      }

      status.replaceChildren(requestStatus(view.request));
      derived.replaceChildren(...derivedRows(view.derived));

      followInput.checked = state.followRequest;
      followRefused.hidden = view.following !== 'request-refused';

      for (const mounted of [...requestControls, ...assertionControls]) {
        const shown = shownValue(mounted.control, state, view);
        for (const [value, input] of mounted.inputs) input.checked = value === shown;
        const coupled = view.following === 'on' && followsRequest(mounted.control);
        mounted.fieldset.disabled = coupled;
        if (mounted.note !== null) mounted.note.hidden = !coupled;
      }

      const { word, sub } = verdictOf(view.result);
      verdict.textContent = word;
      verdict.dataset['outcome'] = view.result.outcome;
      verdictSub.textContent = sub;
      dockWord.textContent = word;
      dockSub.textContent = sub;
      dock.dataset['outcome'] = view.result.outcome;
      body.replaceChildren(...resultBody(view.result));

      for (const [id, tab] of tabs) {
        const selected = model.xmlTab === id;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected) xml.setAttribute('aria-labelledby', tab.id);
      }
      xml.textContent = xmlText(model.xmlTab, view);
    },
  };
}
