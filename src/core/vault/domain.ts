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
