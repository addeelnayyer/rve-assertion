/**
 * A browser stand-in for the part of Node's `events` module that xmlbuilder2
 * reaches for.
 *
 * xmlbuilder2's callback builder extends `EventEmitter`. The library never uses
 * that builder, but the class is evaluated when the module loads, so it has to
 * exist. Only the methods the builder calls are here.
 */

type Listener = (...args: unknown[]) => void;

export class EventEmitter {
  #listeners = new Map<string | symbol, Listener[]>();

  on(name: string | symbol, listener: Listener): this {
    this.#listeners.set(name, [...(this.#listeners.get(name) ?? []), listener]);
    return this;
  }

  emit(name: string | symbol, ...args: unknown[]): boolean {
    const listeners = this.#listeners.get(name) ?? [];
    for (const listener of listeners) {
      listener(...args);
    }
    return listeners.length > 0;
  }

  removeAllListeners(): this {
    this.#listeners.clear();
    return this;
  }
}

export default EventEmitter;
