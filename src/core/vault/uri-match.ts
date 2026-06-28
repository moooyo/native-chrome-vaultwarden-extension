import { getBaseDomain, getHostAndPort, isHttpUrl } from './domain.js';

export const UriMatchStrategy = {
  Domain: 0,
  Host: 1,
  StartsWith: 2,
  Exact: 3,
  RegularExpression: 4,
  Never: 5,
} as const;

export type UriMatchStrategySetting = (typeof UriMatchStrategy)[keyof typeof UriMatchStrategy];

export interface LoginUri {
  uri: string;
  match?: number | null;
}

export interface UriMatchResult {
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  score: number;
}

const MAX_REGEX_PATTERN_LENGTH = 512;

const MATCH_SCORE: Record<UriMatchStrategySetting, number> = {
  [UriMatchStrategy.Exact]: 0,
  [UriMatchStrategy.StartsWith]: 1,
  [UriMatchStrategy.Host]: 2,
  [UriMatchStrategy.Domain]: 3,
  [UriMatchStrategy.RegularExpression]: 4,
  [UriMatchStrategy.Never]: 99,
};

export function isUriMatchStrategySetting(value: unknown): value is UriMatchStrategySetting {
  return value === UriMatchStrategy.Domain
    || value === UriMatchStrategy.Host
    || value === UriMatchStrategy.StartsWith
    || value === UriMatchStrategy.Exact
    || value === UriMatchStrategy.RegularExpression
    || value === UriMatchStrategy.Never;
}

export function matchLoginUri(
  loginUri: LoginUri,
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
): UriMatchResult | undefined {
  if (!isHttpUrl(frameUrl)) return undefined;
  const savedUri = loginUri.uri.trim();
  if (!savedUri) return undefined;
  const strategy = isUriMatchStrategySetting(loginUri.match) ? loginUri.match : defaultStrategy;
  if (strategy === UriMatchStrategy.Never) return undefined;

  const matched = matchesStrategy(savedUri, frameUrl, strategy);
  if (!matched) return undefined;
  return { matchedUri: savedUri, matchType: strategy, score: MATCH_SCORE[strategy] };
}

export function compareMatchResults(a: UriMatchResult, b: UriMatchResult): number {
  return a.score - b.score;
}

function matchesStrategy(savedUri: string, frameUrl: string, strategy: UriMatchStrategySetting): boolean {
  switch (strategy) {
    case UriMatchStrategy.Domain:
      return domainMatches(savedUri, frameUrl);
    case UriMatchStrategy.Host:
      return hostMatches(savedUri, frameUrl);
    case UriMatchStrategy.StartsWith:
      return frameUrl.startsWith(savedUri);
    case UriMatchStrategy.Exact:
      return frameUrl === savedUri;
    case UriMatchStrategy.RegularExpression:
      return regexMatches(savedUri, frameUrl);
    case UriMatchStrategy.Never:
      return false;
  }
}

function domainMatches(savedUri: string, frameUrl: string): boolean {
  const savedDomain = getBaseDomain(savedUri);
  const frameDomain = getBaseDomain(frameUrl);
  return Boolean(savedDomain && frameDomain && savedDomain === frameDomain);
}

function hostMatches(savedUri: string, frameUrl: string): boolean {
  const saved = getHostAndPort(savedUri);
  const frame = getHostAndPort(frameUrl);
  if (!saved || !frame) return false;
  if (saved.host !== frame.host) return false;
  return saved.port === undefined || saved.port === frame.port;
}

function regexMatches(pattern: string, frameUrl: string): boolean {
  if (pattern.length > MAX_REGEX_PATTERN_LENGTH) return false;
  try {
    return new RegExp(pattern).test(frameUrl);
  } catch {
    return false;
  }
}
