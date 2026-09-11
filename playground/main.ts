/**
 * Holds the page's one piece of state and redraws from it. `composer.ts`
 * decides what the library says; `render.ts` decides how that looks.
 */

import { applyPreset, compose, INITIAL_STATE, setControl } from './composer.js';
import { mountComposer, type Action, type Model } from './render.js';

function reduce(model: Model, action: Action): Model {
  switch (action.type) {
    case 'control':
      return {
        ...model,
        state: setControl(model.state, action.control, action.value),
        preset: action.control.group === 'request' ? model.preset : null,
      };
    case 'preset':
      return { ...model, state: applyPreset(model.state, action.id), preset: action.id };
    case 'follow':
      return { ...model, state: { ...model.state, followRequest: action.on }, preset: null };
    case 'tab':
      return { ...model, xmlTab: action.tab };
  }
}

const root = document.getElementById('app');
if (root === null) throw new Error('The page has no #app element to mount the playground in.');

let model: Model = { state: INITIAL_STATE, preset: 'happy', xmlTab: 'assertion' };
const page = mountComposer(root, (action) => {
  model = reduce(model, action);
  page.update(model, compose(model.state));
});
page.update(model, compose(model.state));
