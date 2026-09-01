import { describe, expect, it, vi } from 'vitest';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import {
  WebsitePasskeyDocumentGate,
  type WebsitePasskeyBrowserFrameRecord,
} from './website-passkey-document-gate.js';
import { WebsitePasskeyPermissionsPolicyResolver } from './website-passkey-permissions-policy.js';

const TOP_URL = 'https://login.example.com/top';
const FRAME_URL = 'https://login.example.com/frame';
const DOCUMENT: WebsitePasskeyDocumentContext = {
  tabId: 7,
  frameId: 1,
  documentId: 'frame-document',
  url: FRAME_URL,
  origin: 'https://login.example.com',
};

function sameOriginFrames(): WebsitePasskeyBrowserFrameRecord[] {
  return [
    { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
    { frameId: 1, parentFrameId: 0, documentId: 'frame-document', url: FRAME_URL },
    {
      frameId: 2,
      parentFrameId: 1,
      documentId: 'nested-document',
      url: 'https://login.example.com/nested',
    },
    {
      frameId: 3,
      parentFrameId: 0,
      documentId: 'sibling-document',
      url: 'https://login.example.com/sibling',
    },
  ];
}

function makeGate(frames: { value: WebsitePasskeyBrowserFrameRecord[] } = { value: sameOriginFrames() }) {
  const getAllFrames = vi.fn(async () => frames.value);
  return { gate: new WebsitePasskeyDocumentGate({ getAllFrames }), frames, getAllFrames };
}

describe('WebsitePasskeyDocumentGate', () => {
  it('captures one exact same-origin frame and its browser-owned ancestor chain', async () => {
    const { gate } = makeGate();

    const lease = await gate.capture(DOCUMENT);

    expect(lease).toMatchObject({
      tabId: 7,
      frameId: 1,
      documentId: 'frame-document',
      url: FRAME_URL,
      origin: 'https://login.example.com',
    });
    expect(lease.lineage.map(({ frameId, documentId }) => ({ frameId, documentId }))).toEqual([
      { frameId: 1, documentId: 'frame-document' },
      { frameId: 0, documentId: 'top-document' },
    ]);
    expect(() => gate.assert(lease, DOCUMENT)).not.toThrow();
    await expect(gate.assertCurrent(lease, DOCUMENT)).resolves.toBeUndefined();
  });

  it('ignores an unrelated unsupported frame while requiring every target ancestor', async () => {
    const frames = { value: [
      ...sameOriginFrames(),
      { frameId: 99, parentFrameId: 0, documentId: 'about-blank', url: 'about:blank' },
    ] };
    const { gate } = makeGate(frames);

    await expect(gate.capture(DOCUMENT)).resolves.toMatchObject({ frameId: 1 });
  });

  it.each([
    ['cross-origin target', [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 1, parentFrameId: 0, documentId: 'frame-document', url: 'https://evil.example/frame' },
    ]],
    ['cross-origin ancestor', [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 4, parentFrameId: 0, documentId: 'middle-document', url: 'https://evil.example/middle' },
      { frameId: 1, parentFrameId: 4, documentId: 'frame-document', url: FRAME_URL },
    ]],
    ['missing parent', [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 1, parentFrameId: 99, documentId: 'frame-document', url: FRAME_URL },
    ]],
  ] as const)('rejects a %s chain', async (_case, frames) => {
    const state = { value: frames.map((frame) => ({ ...frame })) as WebsitePasskeyBrowserFrameRecord[] };
    const { gate } = makeGate(state);
    await expect(gate.capture(DOCUMENT)).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects sender metadata that differs from the browser document id or URL', async () => {
    const { gate } = makeGate();
    await expect(gate.capture({ ...DOCUMENT, documentId: 'forged' }))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(gate.capture({ ...DOCUMENT, url: `${FRAME_URL}?changed=1` }))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('revokes only leases whose tab or ancestor frame generation changed', async () => {
    const { gate } = makeGate();
    const lease = await gate.capture(DOCUMENT);

    gate.invalidateFrame(7, 3);
    expect(() => gate.assert(lease, DOCUMENT)).not.toThrow();
    gate.invalidateFrame(7, 0);
    expect(() => gate.assert(lease, DOCUMENT)).toThrowError(expect.objectContaining({ code: 'denied' }));

    const next = await gate.capture(DOCUMENT);
    gate.invalidateTab(7);
    expect(() => gate.assert(next, DOCUMENT)).toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('detects document replacement even before a navigation event reaches the gate', async () => {
    const fixture = makeGate();
    const lease = await fixture.gate.capture(DOCUMENT);
    fixture.frames.value = sameOriginFrames().map((frame) => (
      frame.frameId === 1 ? { ...frame, documentId: 'replacement-document' } : frame
    ));

    await expect(fixture.gate.assertCurrent(lease, DOCUMENT))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(fixture.gate.isCurrent(DOCUMENT)).resolves.toBe(false);
  });

  it('detects a same-document URL transition against the exact sender binding', async () => {
    const fixture = makeGate();
    const lease = await fixture.gate.capture(DOCUMENT);
    fixture.frames.value = sameOriginFrames().map((frame) => (
      frame.frameId === 1 ? { ...frame, url: `${FRAME_URL}?next=1` } : frame
    ));

    await expect(fixture.gate.assertCurrent(lease, DOCUMENT))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('reports a removed frame as unavailable for disconnect cleanup', async () => {
    const fixture = makeGate();
    fixture.frames.value = sameOriginFrames().filter((frame) => frame.frameId !== 1);
    await expect(fixture.gate.isCurrent(DOCUMENT)).resolves.toBe(false);
  });

  it('consumes a feature-specific cross-origin Permissions Policy proof when injected', async () => {
    const frames = { value: [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 1, parentFrameId: 0, documentId: 'frame-document', url: 'https://child.example/frame' },
    ] satisfies WebsitePasskeyBrowserFrameRecord[] };
    const getAllFrames = vi.fn(async () => frames.value);
    const policy = new WebsitePasskeyPermissionsPolicyResolver({ getAllFrames });
    policy.recordResponse({
      tabId: 7, frameId: 0, documentId: 'top-document', url: TOP_URL,
      type: 'main_frame', responseHeaders: [],
    });
    policy.recordResponse({
      tabId: 7, frameId: 1, documentId: 'frame-document', url: 'https://child.example/frame',
      type: 'sub_frame', responseHeaders: [],
    });
    await policy.recordIframeAllowReport({
      tabId: 7, frameId: 0, documentId: 'top-document', url: TOP_URL,
    }, {
      iframes: [{
        src: 'https://child.example/frame',
        allow: 'publickey-credentials-get',
        srcdoc: false,
      }],
    });
    const gate = new WebsitePasskeyDocumentGate({ getAllFrames, permissionsPolicy: policy });
    const context = {
      ...DOCUMENT,
      url: 'https://child.example/frame',
      origin: 'https://child.example',
    };

    const lease = await gate.capture(context, 'get');
    expect(lease).toMatchObject({
      operation: 'get',
      crossOrigin: true,
      topOrigin: 'https://login.example.com',
    });
    expect(lease.permissionsPolicyProof).toBeDefined();
    await expect(gate.assertCurrent(lease, context)).resolves.toBeUndefined();
    await expect(gate.capture(context, 'create')).rejects.toMatchObject({ code: 'denied' });

    expect(gate.recordCommittedNavigation({
      tabId: context.tabId,
      frameId: context.frameId,
      documentId: context.documentId,
      url: context.url,
    })).toBe(true);
    expect(() => gate.assert(lease, context)).toThrowError(expect.objectContaining({ code: 'denied' }));
    await expect(gate.capture(context, 'get')).resolves.toMatchObject({ crossOrigin: true });
  });

  it('keeps direct browser-policy proofs behind document and resolver synchronous epochs', async () => {
    const frames = { value: [
      { frameId: 0, parentFrameId: -1, documentId: 'top-document', url: TOP_URL },
      { frameId: 1, parentFrameId: 0, documentId: 'frame-document', url: 'https://child.example/frame' },
    ] satisfies WebsitePasskeyBrowserFrameRecord[] };
    const getAllFrames = vi.fn(async () => frames.value);
    const policy = new WebsitePasskeyPermissionsPolicyResolver({
      getAllFrames,
      featurePolicyProbe: {
        probe: async () => ({ status: 'available', get: true, create: true }),
      },
    });
    const gate = new WebsitePasskeyDocumentGate({ getAllFrames, permissionsPolicy: policy });
    const context = {
      ...DOCUMENT,
      url: 'https://child.example/frame',
      origin: 'https://child.example',
    };
    const lease = await gate.capture(context, 'get');

    expect(gate.recordSameDocumentNavigation({
      tabId: context.tabId,
      frameId: context.frameId,
      documentId: context.documentId,
      url: context.url,
    })).toBe(false);
    expect(() => gate.assert(lease, context))
      .toThrowError(expect.objectContaining({ code: 'denied' }));

    const refreshed = await gate.capture(context, 'get');
    await policy.recordIframeAllowReport({
      tabId: 7,
      frameId: 0,
      documentId: 'top-document',
      url: TOP_URL,
    }, {
      iframes: [{
        src: context.url,
        allow: "publickey-credentials-get 'none'",
        srcdoc: false,
      }],
    });
    expect(() => gate.assert(refreshed, context))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
  });
});
