/**
 * A browser stand-in for the two functions `@oozcitak/url` imports from Node's
 * `url` module.
 *
 * Identity functions. Every host the page puts in front of the library is
 * ASCII already, so there is nothing to convert; an internationalised host
 * would pass through unconverted, which no control on the page can produce.
 */

export const domainToASCII = (domain: string): string => domain;

export const domainToUnicode = (domain: string): string => domain;
