import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vite';

/** A file beside this config, as the absolute path an alias needs. */
const local = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    // xmlbuilder2 and @oozcitak/url import Node built-ins that have no browser
    // build. Both are satisfied by a few lines each — see the shims.
    alias: {
      events: local('./shims/events.ts'),
      url: local('./shims/url.ts'),
    },
  },
});
