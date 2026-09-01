import { describe, expect, it, vi } from 'vitest';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import {
  WebsitePasskeyPermissionsPolicyResolver,
  type WebsitePasskeyIframeAllowReportEntry,
  type WebsitePasskeyPolicyBrowserFrame,
} from './website-passkey-permissions-policy.js';
import type { WebsitePasskeyFeaturePolicyProbeResult } from './website-passkey-feature-policy-probe.js';

const TOP_URL = 'https://top.example/page';
const CHILD_URL = 'https://child.example/frame';
const CHILD: WebsitePasskeyDocumentContext = {
  tabId: 7,
  frameId: 1,
  documentId: 'child-document',
  url: CHILD_URL,
  origin: 'https://child.example',
};

function crossOriginFrames(): WebsitePasskeyPolicyBrowserFrame[] {
  return [
    { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
    { frameId: 1, parentFrameId: 0, documentId: 'child-document', url: CHILD_URL },
  ];
}

function harness(options: { ttl?: number; headers?: number; reports?: number; epochs?: number } = {}) {
  let now = 1_000;
  const frames = { value: crossOriginFrames() };
  const getAllFrames = vi.fn(async () => frames.value);
  const resolver = new WebsitePasskeyPermissionsPolicyResolver({
    getAllFrames,
    now: () => now,
    cacheTtlMs: options.ttl ?? 10_000,
    maxHeaderEntries: options.headers ?? 32,
    maxReportEntries: options.reports ?? 32,
    maxEpochEntries: options.epochs ?? 64,
  });
  const observe = (
    frame: Required<WebsitePasskeyPolicyBrowserFrame>,
    policy?: string,
    tabId = 7,
  ) => resolver.recordResponse({
    tabId,
    frameId: frame.frameId,
    documentId: frame.documentId,
    url: frame.url,
    type: frame.frameId === 0 ? 'main_frame' : 'sub_frame',
    responseHeaders: policy === undefined ? [] : [{ name: 'Permissions-Policy', value: policy }],
  });
  const report = (
    parent: Required<WebsitePasskeyPolicyBrowserFrame>,
    iframes: readonly WebsitePasskeyIframeAllowReportEntry[],
    tabId = 7,
  ) => resolver.recordIframeAllowReport({
    tabId,
    frameId: parent.frameId,
    documentId: parent.documentId,
    url: parent.url,
  }, { iframes });
  return {
    resolver,
    frames,
    getAllFrames,
    observe,
    report,
    setNow(value: number) { now = value; },
  };
}

function requiredFrame(value: WebsitePasskeyPolicyBrowserFrame): Required<WebsitePasskeyPolicyBrowserFrame> {
  return value as Required<WebsitePasskeyPolicyBrowserFrame>;
}

function iframe(src: string, allow = ''): WebsitePasskeyIframeAllowReportEntry {
  return { src, allow, srcdoc: false };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function seedCrossOrigin(
  fixture: ReturnType<typeof harness>,
  allow = 'publickey-credentials-get',
  topPolicy?: string,
): Promise<void> {
  const [top, child] = fixture.frames.value.map(requiredFrame);
  expect(fixture.observe(top!, topPolicy)).toBe(true);
  expect(fixture.observe(child!)).toBe(true);
  expect(await fixture.report(top!, [iframe(CHILD_URL, allow)])).toBe(true);
}

describe('WebsitePasskeyPermissionsPolicyResolver authorization', () => {
  it('allows a same-origin child through known default header and container semantics', async () => {
    const fixture = harness();
    fixture.frames.value[1] = {
      ...fixture.frames.value[1],
      url: 'https://top.example/frame',
      documentId: 'same-origin-document',
    };
    const context = {
      ...CHILD,
      documentId: 'same-origin-document',
      url: 'https://top.example/frame',
      origin: 'https://top.example',
    };
    const [top, child] = fixture.frames.value.map(requiredFrame);
    fixture.observe(top!);
    fixture.observe(child!);
    await fixture.report(top!, [iframe(context.url)]);

    const proof = await fixture.resolver.capture(context, 'get');
    expect(proof).toMatchObject({ crossOrigin: false, topOrigin: 'https://top.example', operation: 'get' });
    expect(() => fixture.resolver.assert(proof, context, 'get')).not.toThrow();
  });

  it('allows only the separately delegated WebAuthn operation in a cross-origin child', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);

    const proof = await fixture.resolver.capture(CHILD, 'get');
    expect(proof).toMatchObject({ crossOrigin: true, topOrigin: 'https://top.example' });
    await expect(fixture.resolver.capture(CHILD, 'create')).rejects.toMatchObject({ code: 'denied' });
  });

  it('denies ambiguous same-source browser siblings under one parent', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const proof = await fixture.resolver.capture(CHILD, 'get');
    fixture.frames.value.push({
      frameId: 2,
      parentFrameId: 0,
      documentId: 'closed-shadow-sibling',
      url: CHILD_URL,
    });

    await expect(fixture.resolver.assertCurrent(proof, CHILD, 'get'))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(fixture.resolver.capture(CHILD, 'get'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('denies unknown observations, missing delegation, malformed allow, and parent header denial', async () => {
    const unknown = harness();
    await expect(unknown.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });

    const missing = harness();
    await seedCrossOrigin(missing, 'camera *');
    await expect(missing.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });

    const malformed = harness();
    const [top, child] = malformed.frames.value.map(requiredFrame);
    malformed.observe(top!);
    malformed.observe(child!);
    await expect(malformed.report(top!, [iframe(CHILD_URL, "publickey-credentials-get 'none' *")]))
      .resolves.toBe(false);
    await expect(malformed.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });

    const denied = harness();
    await seedCrossOrigin(denied, 'publickey-credentials-get', 'publickey-credentials-get=()');
    await expect(denied.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
  });

  it('requires every level of a nested cross-origin chain to delegate the final origin', async () => {
    const fixture = harness();
    fixture.frames.value = [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 2, parentFrameId: 0, documentId: 'middle-document', url: 'https://middle.example/frame' },
      { frameId: 1, parentFrameId: 2, documentId: 'child-document', url: CHILD_URL },
    ];
    const [top, middle, child] = fixture.frames.value.map(requiredFrame);
    fixture.observe(top!);
    fixture.observe(middle!);
    fixture.observe(child!);
    await fixture.report(middle!, [iframe(CHILD_URL, 'publickey-credentials-get')]);
    await fixture.report(top!, [iframe(middle!.url, 'publickey-credentials-get')]);
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });

    await fixture.report(top!, [iframe(middle!.url, 'publickey-credentials-get *')]);
    await expect(fixture.resolver.capture(CHILD, 'get')).resolves.toMatchObject({
      crossOrigin: true,
      lineage: [{ frameId: 1 }, { frameId: 2 }, { frameId: 0 }],
    });
  });

  it('does not let a child report the allow attribute owned by its parent', async () => {
    const fixture = harness();
    const [top, child] = fixture.frames.value.map(requiredFrame);
    fixture.observe(top!);
    fixture.observe(child!);
    expect(await fixture.report(child!, [iframe(CHILD_URL, 'publickey-credentials-get')])).toBe(true);

    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
    await fixture.report(top!, [iframe(CHILD_URL, 'publickey-credentials-get')]);
    await expect(fixture.resolver.capture(CHILD, 'get')).resolves.toMatchObject({ crossOrigin: true });
  });

  it('rejects a parent report whose browser document binding is stale', async () => {
    const fixture = harness();
    const top = requiredFrame(fixture.frames.value[0]!);
    await expect(fixture.resolver.recordIframeAllowReport({
      tabId: 7,
      frameId: 0,
      documentId: 'forged-document',
      url: TOP_URL,
    }, { iframes: [iframe(CHILD_URL, 'publickey-credentials-get')] })).resolves.toBe(false);
    expect(await fixture.report(top, [iframe(CHILD_URL, 'publickey-credentials-get')])).toBe(true);
  });

  it('denies ambiguous duplicate iframe sources instead of choosing one allow attribute', async () => {
    const fixture = harness();
    const [top, child] = fixture.frames.value.map(requiredFrame);
    fixture.observe(top!);
    fixture.observe(child!);
    await fixture.report(top!, [
      iframe(CHILD_URL, 'publickey-credentials-get'),
      iframe(CHILD_URL, "publickey-credentials-get 'none'"),
    ]);
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
  });
});

describe('WebsitePasskeyPermissionsPolicyResolver browser effective-policy proof', () => {
  function browserHarness(
    results: WebsitePasskeyFeaturePolicyProbeResult[],
    initialFrames = crossOriginFrames(),
  ) {
    const frames = { value: initialFrames };
    const probe = vi.fn(async () => results.shift()
      ?? Object.freeze({ status: 'available' as const, get: true, create: true }));
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: async () => frames.value,
      featurePolicyProbe: { probe },
    });
    return { resolver, frames, probe };
  }

  it('authorizes after worker restart without response-header or parent inventory caches', async () => {
    const fixture = browserHarness([
      { status: 'available', get: true, create: false },
      { status: 'available', get: true, create: false },
    ]);

    await expect(fixture.resolver.capture(CHILD, 'get')).resolves.toMatchObject({
      crossOrigin: true,
      topOrigin: 'https://top.example',
    });
    await expect(fixture.resolver.capture(CHILD, 'create'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('does not fall back to permissive reconstruction after an explicit browser denial', async () => {
    const fixture = browserHarness([{ status: 'available', get: false, create: true }]);
    const [top, child] = fixture.frames.value.map(requiredFrame);
    fixture.resolver.recordResponse({
      tabId: 7, frameId: top!.frameId, documentId: top!.documentId, url: top!.url,
      type: 'main_frame', responseHeaders: [],
    });
    fixture.resolver.recordResponse({
      tabId: 7, frameId: child!.frameId, documentId: child!.documentId, url: child!.url,
      type: 'sub_frame', responseHeaders: [],
    });
    await fixture.resolver.recordIframeAllowReport({
      tabId: 7, frameId: top!.frameId, documentId: top!.documentId, url: top!.url,
    }, { iframes: [iframe(CHILD_URL, 'publickey-credentials-get')] });

    await expect(fixture.resolver.capture(CHILD, 'get'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('retains strict header and container reconstruction only when the API is unavailable', async () => {
    const fixture = harness();
    const probe = vi.fn(async () => ({ status: 'unavailable' as const }));
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: fixture.getAllFrames,
      featurePolicyProbe: { probe },
    });
    const [top, child] = fixture.frames.value.map(requiredFrame);
    resolver.recordResponse({
      tabId: 7, frameId: top!.frameId, documentId: top!.documentId, url: top!.url,
      type: 'main_frame', responseHeaders: [],
    });
    resolver.recordResponse({
      tabId: 7, frameId: child!.frameId, documentId: child!.documentId, url: child!.url,
      type: 'sub_frame', responseHeaders: [],
    });
    await resolver.recordIframeAllowReport({
      tabId: 7, frameId: top!.frameId, documentId: top!.documentId, url: top!.url,
    }, { iframes: [iframe(CHILD_URL, 'publickey-credentials-get')] });

    await expect(resolver.capture(CHILD, 'get')).resolves.toMatchObject({ crossOrigin: true });
  });

  it('uses browser lineage without duplicate-src or redirect mapping ambiguity', async () => {
    const redirected = 'https://child.example/final';
    const context = { ...CHILD, url: redirected };
    const fixture = browserHarness(
      [{ status: 'available', get: true, create: true }],
      [
        { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
        { frameId: 1, parentFrameId: 0, documentId: 'child-document', url: redirected },
        { frameId: 2, parentFrameId: 0, documentId: 'sibling-document', url: redirected },
      ],
    );

    await expect(fixture.resolver.capture(context, 'get')).resolves.toMatchObject({
      lineage: [{ frameId: 1 }, { frameId: 0 }],
    });
  });

  it('rejects a slow probe when its exact browser document navigates before settlement', async () => {
    const pending = deferred<WebsitePasskeyFeaturePolicyProbeResult>();
    const frames = { value: crossOriginFrames() };
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: async () => frames.value,
      featurePolicyProbe: { probe: () => pending.promise },
    });
    const capture = resolver.capture(CHILD, 'get');
    frames.value[1] = { ...frames.value[1], documentId: 'replacement-document' };
    pending.resolve({ status: 'available', get: true, create: true });

    await expect(capture).rejects.toMatchObject({ code: 'denied' });
  });

  it('ignores unrelated-tab policy churn while retaining exact-lineage probe fences', async () => {
    const pending = deferred<WebsitePasskeyFeaturePolicyProbeResult>();
    const frames = crossOriginFrames();
    const probe = vi.fn(() => pending.promise);
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: async () => frames,
      featurePolicyProbe: { probe },
    });
    const capture = resolver.capture(CHILD, 'get');
    await vi.waitFor(() => expect(probe).toHaveBeenCalledOnce());

    resolver.invalidateFrame(99, 0);
    pending.resolve({ status: 'available', get: true, create: true });

    await expect(capture).resolves.toMatchObject({ tabId: CHILD.tabId, frameId: CHILD.frameId });
  });

  it('rejects relevant-lineage policy churn during a slow direct probe', async () => {
    const pending = deferred<WebsitePasskeyFeaturePolicyProbeResult>();
    const frames = crossOriginFrames();
    const probe = vi.fn(() => pending.promise);
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: async () => frames,
      featurePolicyProbe: { probe },
    });
    const capture = resolver.capture(CHILD, 'get');
    await vi.waitFor(() => expect(probe).toHaveBeenCalledOnce());

    resolver.invalidateFrame(CHILD.tabId, 0);
    pending.resolve({ status: 'available', get: true, create: true });

    await expect(capture).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects explicit allow revocation on fresh assertCurrent without reconstruction fallback', async () => {
    const fixture = browserHarness([
      { status: 'available', get: true, create: true },
      { status: 'available', get: false, create: true },
    ]);
    const proof = await fixture.resolver.capture(CHILD, 'get');

    await expect(fixture.resolver.assertCurrent(proof, CHILD, 'get'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('revokes a browser proof synchronously when a newer parent allow report reaches the worker', async () => {
    const fixture = browserHarness([{ status: 'available', get: true, create: true }]);
    const proof = await fixture.resolver.capture(CHILD, 'get');
    const top = requiredFrame(fixture.frames.value[0]!);

    await fixture.resolver.recordIframeAllowReport({
      tabId: 7, frameId: top.frameId, documentId: top.documentId, url: top.url,
    }, { iframes: [iframe(CHILD_URL, "publickey-credentials-get 'none'")] });

    expect(() => fixture.resolver.assert(proof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('rejects accessor-bearing probe results without invoking them', async () => {
    const getter = vi.fn(() => true);
    const result = { status: 'available', create: true } as Record<string, unknown>;
    Object.defineProperty(result, 'get', { enumerable: true, get: getter });
    const resolver = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames: async () => crossOriginFrames(),
      featurePolicyProbe: { probe: async () => result as never },
    });

    await expect(resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
    expect(getter).not.toHaveBeenCalled();
  });
});

describe('WebsitePasskeyPermissionsPolicyResolver revocation', () => {
  it('revokes the previous report before awaiting browser frame validation', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const proof = await fixture.resolver.capture(CHILD, 'get');
    const pending = deferred<WebsitePasskeyPolicyBrowserFrame[]>();
    fixture.getAllFrames.mockImplementationOnce(() => pending.promise);
    const top = requiredFrame(fixture.frames.value[0]!);

    const refresh = fixture.report(top, [iframe(CHILD_URL, 'publickey-credentials-get')]);
    expect(() => fixture.resolver.assert(proof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
    pending.resolve(fixture.frames.value);
    await expect(refresh).resolves.toBe(true);
  });

  it('preserves an exact pre-commit header while revoking the previous document proof', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const proof = await fixture.resolver.capture(CHILD, 'get');

    expect(fixture.resolver.recordCommittedNavigation({
      tabId: CHILD.tabId,
      frameId: CHILD.frameId,
      documentId: CHILD.documentId,
      url: CHILD.url,
    })).toBe(true);
    expect(() => fixture.resolver.assert(proof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
    await expect(fixture.resolver.capture(CHILD, 'get')).resolves.toMatchObject({ crossOrigin: true });

    expect(fixture.resolver.recordCommittedNavigation({
      tabId: CHILD.tabId,
      frameId: CHILD.frameId,
      documentId: 'different-document',
      url: CHILD.url,
    })).toBe(false);
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
  });

  it('requires a fresh parent inventory after parent commit and accepts an explicit empty report', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const top = requiredFrame(fixture.frames.value[0]!);

    expect(fixture.resolver.recordCommittedNavigation({
      tabId: 7,
      frameId: top.frameId,
      documentId: top.documentId,
      url: top.url,
    })).toBe(true);
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
    expect(await fixture.report(top, [])).toBe(true);
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
  });

  it('rebinds same-document parent evidence without extending its lifetime', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const proof = await fixture.resolver.capture(CHILD, 'get');
    const nextTopUrl = `${TOP_URL}#next`;
    fixture.frames.value[0] = { ...fixture.frames.value[0], url: nextTopUrl };

    expect(fixture.resolver.recordSameDocumentNavigation({
      tabId: 7,
      frameId: 0,
      documentId: 'top-document',
      url: nextTopUrl,
    })).toBe(true);
    expect(() => fixture.resolver.assert(proof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
    await expect(fixture.resolver.capture(CHILD, 'get')).resolves.toMatchObject({ crossOrigin: true });
  });

  it('invalidates proofs on response and allow-report A-B-A replacements', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const first = await fixture.resolver.capture(CHILD, 'get');
    const [top, child] = fixture.frames.value.map(requiredFrame);

    fixture.observe(child!);
    expect(() => fixture.resolver.assert(first, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));
    const second = await fixture.resolver.capture(CHILD, 'get');
    await fixture.report(top!, [iframe(CHILD_URL, "publickey-credentials-get 'none'")]);
    await fixture.report(top!, [iframe(CHILD_URL, 'publickey-credentials-get')]);
    expect(() => fixture.resolver.assert(second, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('invalidates a proof on TTL expiry and cache-capacity eviction', async () => {
    const expiring = harness({ ttl: 50 });
    await seedCrossOrigin(expiring);
    const proof = await expiring.resolver.capture(CHILD, 'get');
    expiring.setNow(1_050);
    expect(() => expiring.resolver.assert(proof, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));
    expiring.setNow(1_049);
    expect(() => expiring.resolver.assert(proof, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));

    const bounded = harness({ headers: 2 });
    await seedCrossOrigin(bounded);
    const boundedProof = await bounded.resolver.capture(CHILD, 'get');
    bounded.resolver.recordResponse({
      tabId: 8,
      frameId: 0,
      documentId: 'other-document',
      url: 'https://other.example/',
      type: 'main_frame',
      responseHeaders: [],
    });
    expect(() => bounded.resolver.assert(boundedProof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('invalidates active proofs on report eviction and epoch-capacity rollover', async () => {
    const reportBounded = harness({ reports: 1 });
    await seedCrossOrigin(reportBounded);
    const reportProof = await reportBounded.resolver.capture(CHILD, 'get');
    const child = requiredFrame(reportBounded.frames.value[1]!);
    expect(await reportBounded.report(child, [])).toBe(true);
    expect(() => reportBounded.resolver.assert(reportProof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));

    const epochBounded = harness({ epochs: 3 });
    await seedCrossOrigin(epochBounded);
    const epochProof = await epochBounded.resolver.capture(CHILD, 'get');
    epochBounded.resolver.invalidateFrame(8, 0);
    epochBounded.resolver.invalidateFrame(9, 0);
    expect(() => epochBounded.resolver.assert(epochProof, CHILD, 'get'))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('detects browser document replacement and explicit frame/tab invalidation', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const first = await fixture.resolver.capture(CHILD, 'get');
    fixture.frames.value[1] = { ...fixture.frames.value[1], documentId: 'replacement' };
    await expect(fixture.resolver.assertCurrent(first, CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });

    fixture.frames.value[1] = { ...fixture.frames.value[1], documentId: 'child-document' };
    const second = await fixture.resolver.capture(CHILD, 'get');
    fixture.resolver.invalidateFrame(7, 1);
    expect(() => fixture.resolver.assert(second, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));

    const child = requiredFrame(fixture.frames.value[1]!);
    fixture.observe(child);
    const third = await fixture.resolver.capture(CHILD, 'get');
    fixture.resolver.invalidateTab(7);
    expect(() => fixture.resolver.assert(third, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('turns a malformed newer response into an authoritative fail-closed invalidation', async () => {
    const fixture = harness();
    await seedCrossOrigin(fixture);
    const proof = await fixture.resolver.capture(CHILD, 'get');
    const child = requiredFrame(fixture.frames.value[1]!);
    expect(fixture.observe(child, 'publickey-credentials-get=(self')).toBe(false);
    expect(() => fixture.resolver.assert(proof, CHILD, 'get')).toThrowError(expect.objectContaining({ code: 'denied' }));
    await expect(fixture.resolver.capture(CHILD, 'get')).rejects.toMatchObject({ code: 'denied' });
  });
});
