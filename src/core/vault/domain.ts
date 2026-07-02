import { getDomain } from 'tldts';

export interface HostAndPort {
  host: string;
  port?: string;
}

export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function getHostAndPort(value: string): HostAndPort | undefined {
  const url = parseAsUrlOrHost(value);
  if (!url) return undefined;
  const host = url.hostname.toLowerCase();
  if (!host) return undefined;
  return url.port ? { host, port: url.port } : { host };
}

export function getBaseDomain(value: string): string | undefined {
  const hostAndPort = getHostAndPort(value);
  if (!hostAndPort) return undefined;
  const host = hostAndPort.host;
  if (host === 'localhost' || isIpv4Address(host) || isIpv6Address(host)) return host;
  return getDomain(host, { allowPrivateDomains: true })?.toLowerCase() ?? host;
}

function parseAsUrlOrHost(value: string): URL | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  try {
    return new URL(trimmed);
  } catch {
    try {
      return new URL(`https://${trimmed}`);
    } catch {
      return undefined;
    }
  }
}

function isIpv4Address(value: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
}

function isIpv6Address(value: string): boolean {
  return value.includes(':');
}

/**
 * WebAuthn rpId validity: rpId must equal the frame host or be a registrable-domain suffix of it,
 * and must itself be a registrable domain (never a bare public suffix like github.io / co.uk). Uses
 * the Public Suffix List via tldts. `localhost` is allowed only for an exact localhost match (dev).
 */
export function isRegistrableRpId(rpId: string, host: string): boolean {
  const r = rpId.trim().toLowerCase();
  const h = host.trim().toLowerCase();
  if (!r || !h) return false;
  if (r === 'localhost') return h === 'localhost';
  if (h !== r && !h.endsWith(`.${r}`)) return false;
  const rBase = getDomain(r, { allowPrivateDomains: true });
  const hBase = getDomain(h, { allowPrivateDomains: true });
  if (!rBase || !hBase) return false; // public suffix, IP, or invalid
  return rBase.toLowerCase() === hBase.toLowerCase();
}
