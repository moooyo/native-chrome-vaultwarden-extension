import { html, nothing } from 'lit';
import type { FillRole } from '../../core/vault/fill-roles.js';
import { uiIcon } from '../../ui/components/icon.js';
import type { StructuredFillUndo } from '../structured-fill-undo.js';
import { mountRenderSurface } from './render-surface.js';
import { INLINE_SURFACE_CSS } from './surface-theme.js';

export interface StructuredPreviewField {
  readonly role: FillRole;
  readonly hasValue: boolean;
}

export interface StructuredPreviewOptions {
  readonly anchor?: HTMLElement;
  readonly kind: 'card' | 'identity';
  readonly itemName: string;
  readonly site: string;
  readonly fields: readonly StructuredPreviewField[];
  readonly onConfirm: (roles: readonly FillRole[]) => void;
  readonly onDismiss: () => void;
}

export interface StructuredPreviewHandle {
  readonly element: HTMLDivElement;
  readonly root: ShadowRoot;
  showError(message: string): void;
  showReceipt(receipt: StructuredFillUndo): void;
  remove(): void;
}

/** Prefer a side gutter and keep the complete review, including its primary action, in view. */
export function positionStructuredPreview(host: HTMLElement, anchor: HTMLElement): void {
  const view = anchor.ownerDocument.defaultView;
  if (!view) return;
  const rect = anchor.getBoundingClientRect();
  const width = host.offsetWidth || 360;
  const height = host.offsetHeight || 0;
  const viewportWidth = view.innerWidth || anchor.ownerDocument.documentElement.clientWidth;
  const viewportHeight = view.innerHeight || anchor.ownerDocument.documentElement.clientHeight;
  const gap = 12;
  let left = rect.right + gap;
  if (left + width > viewportWidth - gap) {
    left = rect.left - width - gap >= gap ? rect.left - width - gap : rect.left;
  }
  left = Math.max(gap, Math.min(left, Math.max(gap, viewportWidth - width - gap)));
  const top = Math.max(gap, Math.min(rect.top, Math.max(gap, viewportHeight - height - gap)));
  host.style.left = `${left + view.scrollX}px`;
  host.style.top = `${top + view.scrollY}px`;
}

const LABELS: Record<FillRole, string> = {
  cardholderName: '持卡人', brand: '卡片类型', number: '银行卡号', exp: '有效期', expMonth: '到期月份', expYear: '到期年份', code: '安全码',
  title: '称谓', firstName: '名字', middleName: '中间名', lastName: '姓氏', fullName: '姓名', address: '完整街道地址',
  address1: '地址第 1 行', address2: '地址第 2 行', address3: '地址第 3 行', city: '城市', state: '省 / 州', postalCode: '邮政编码',
  country: '国家 / 地区', company: '公司', email: '电子邮箱', phone: '电话号码', username: '用户名',
};

export const STRUCTURED_PREVIEW_STYLES = INLINE_SURFACE_CSS + `
  .box { width:min(360px,calc(100vw - 24px)); }
  .intro { padding:16px 16px 12px; }
  h2 { margin:0 0 5px; font-size:16px; line-height:1.4; font-weight:650; }
  .intro p { margin:0; color:var(--mi-muted); font-size:12px; overflow-wrap:anywhere; }
  .rows { margin:0 8px; max-height:min(300px,45vh); overflow:auto; overscroll-behavior:contain; }
  .row { display:flex; gap:10px; align-items:center; padding:10px 8px; border-top:1px solid var(--mi-inner); border-radius:0; cursor:pointer; }
  .row:hover { background:var(--mi-row-hover); }
  .row input { width:16px; height:16px; flex:none; accent-color:var(--mi-teal); margin:0; }
  .field { min-width:0; flex:1; }
  .field strong { display:block; font-size:13px; font-weight:500; }
  .field small { display:block; color:var(--mi-faint); font-size:11px; margin-top:2px; }
  .protected { color:var(--mi-muted); font-size:11px; flex:none; }
  .protected svg { width:14px; height:14px; }
  .note { padding:10px 16px; color:var(--mi-muted); font-size:11px; line-height:1.6; }
  .actions { position:sticky; bottom:0; display:flex; align-items:center; gap:10px; padding:12px 16px; background:var(--mi-panel); border-top:1px solid var(--mi-line); }
  .actions button { padding:9px 14px; border:1px solid var(--mi-line); background:var(--mi-panel); border-radius:7px; font-weight:500; }
  .actions .primary { flex:1; background:var(--mi-ink-btn); border-color:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); }
  .actions .primary:hover:not(:disabled) { background:var(--mi-ink-hover); }
  .error { color:var(--mi-red); padding:0 16px 12px; font-size:12px; }
  .receipt-body { padding:18px 16px; }
  .receipt-title { display:flex; gap:8px; align-items:center; font-weight:600; }
  .receipt-title svg { color:var(--mi-success); }
  .receipt-body p { color:var(--mi-muted); font-size:12px; margin:8px 0 0; }
`;

/** A metadata-only review. No decrypted card, CVC, identity, or existing form values enter this DOM. */
export function createStructuredPreview(options: StructuredPreviewOptions): StructuredPreviewHandle {
  const surface = mountRenderSurface(STRUCTURED_PREVIEW_STYLES);
  const selected = new Set(options.fields.filter((field) => !field.hasValue).map((field) => field.role));
  let busy = false;
  let error = '';
  let receipt: StructuredFillUndo | undefined;
  let restored: number | undefined;
  let timer: number | undefined;
  let removed = false;
  const view = surface.host.ownerDocument.defaultView;
  const position = (): void => {
    if (options.anchor && !removed) positionStructuredPreview(surface.host, options.anchor);
  };
  view?.addEventListener('resize', position);
  view?.addEventListener('scroll', position, true);
  surface.host.dataset.vwStructuredPreview = '';
  surface.host.style.position = 'absolute';
  surface.host.style.zIndex = '2147483647';
  const dismiss = (): void => options.onDismiss();
  const onKeyDown = (event: KeyboardEvent): void => {
    if (!event.isTrusted || event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    dismiss();
  };
  const draw = (): void => {
    surface.render(html`<section class="box" role="dialog" aria-label="确认填充字段" aria-busy=${busy ? 'true' : 'false'} @keydown=${onKeyDown}>
      <header class="head"><span class="brand">密屿 · ${options.site}</span><button class="panel-close" type="button" aria-label="关闭" @click=${(event: MouseEvent) => { if (event.isTrusted) dismiss(); }}>${uiIcon('close')}</button></header>
      ${receipt ? html`<div class="receipt-body" role="status" aria-live="polite"><div class="receipt-title">${uiIcon('check')}${restored === undefined ? `已填充 ${receipt.count} 个字段` : `已撤销 ${restored} 个字段`}</div><p>${restored === undefined ? '提示即将自动关闭，关闭前可撤销这次填充。' : '之后手动修改的内容已保留。'}</p>${restored === undefined && receipt.count > 0 && receipt.remainingMs() > 0 ? html`<button class="undo" type="button" @click=${(event: MouseEvent) => { if (!event.isTrusted) return; restored = receipt!.undo(); draw(); }}>撤销填充</button>` : nothing}</div>` : html`
        <div class="intro"><h2>选择要填充的字段</h2><p>${options.itemName || (options.kind === 'card' ? '银行卡' : '身份信息')}</p></div>
        <div class="rows">${options.fields.map((field) => html`<label class="row"><input type="checkbox" .checked=${selected.has(field.role)} ?disabled=${busy} aria-label=${LABELS[field.role]} @change=${(event: Event) => {
          if (!event.isTrusted || busy) return;
          if ((event.target as HTMLInputElement).checked) selected.add(field.role); else selected.delete(field.role);
          draw();
        }}><span class="field"><strong>${LABELS[field.role]}</strong><small>${field.hasValue ? (selected.has(field.role) ? '将替换当前内容' : '已有内容 · 默认保留') : '填入保险库中保存的内容'}</small></span>${field.role === 'number' || field.role === 'code' ? html`<span class="protected" aria-label="敏感内容不在预览中显示">${uiIcon('lock')}</span>` : nothing}</label>`)}</div>
        <div class="note">${options.kind === 'card' ? '仅填充已选字段。银行卡号与安全码不会在此预览中显示。' : '仅填充已选字段。已有内容会保留，除非您主动选中该字段。'}</div>
        ${error ? html`<div class="error" role="alert">${error}</div>` : nothing}
        <footer class="actions"><button type="button" @click=${(event: MouseEvent) => { if (event.isTrusted) dismiss(); }}>取消</button><button class="primary" type="button" ?disabled=${busy || selected.size === 0 || Boolean(error)} @click=${(event: MouseEvent) => {
          if (!event.isTrusted || busy || selected.size === 0 || error) return;
          busy = true; draw(); options.onConfirm(options.fields.filter((field) => selected.has(field.role)).map((field) => field.role));
        }}>${busy ? '正在填充…' : `填充 ${selected.size} 个字段`}</button></footer>
      `}
    </section>`);
    position();
  };
  draw();
  surface.root.querySelector<HTMLInputElement>('input')?.focus({ preventScroll: true });
  return {
    element: surface.host,
    root: surface.root,
    showError(message) { busy = false; error = message; draw(); },
    showReceipt(value) {
      receipt?.dispose(); receipt = value; busy = false; draw();
      surface.root.querySelector<HTMLButtonElement>('.undo')?.focus({ preventScroll: true });
      timer = view?.setTimeout(dismiss, receipt.remainingMs());
    },
    remove() {
      if (removed) return;
      removed = true;
      if (timer !== undefined) view?.clearTimeout(timer);
      view?.removeEventListener('resize', position);
      view?.removeEventListener('scroll', position, true);
      receipt?.dispose();
      surface.remove();
    },
  };
}
