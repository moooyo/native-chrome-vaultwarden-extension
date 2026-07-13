// Zero-dependency static server for the MiYu autofill/passkey test page.
//
// WHY a server (not file://): the extension's content scripts only match http/https,
// and passkey create()/get() require a secure context. `http://localhost` is a secure
// context and matches the content-script globs, so it satisfies both. Bound to 127.0.0.1
// so it is never exposed off-box; open it as http://localhost:PORT (an IP host makes MiYu
// reject the rpId as non-registrable — use the localhost name).
//
// Usage: node test-page/serve.mjs [port]   (or: npm run serve:testpage)

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';

const dir = dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2] || process.env.PORT || 8770);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === '/' || pathname === '') pathname = '/index.html';
    // Contain path traversal: resolve under dir and reject anything that escapes it.
    const filePath = normalize(join(dir, pathname));
    if (!filePath.startsWith(dir)) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    const body = await readFile(filePath);
    const ext = pathname.slice(pathname.lastIndexOf('.'));
    res.writeHead(200, {
      'Content-Type': TYPES[ext] || 'application/octet-stream',
      // Always serve the freshest page while iterating.
      'Cache-Control': 'no-store',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`MiYu test page → http://localhost:${port}/`);
  console.log('Open that exact URL (localhost, not 127.0.0.1) so passkeys work. Ctrl+C to stop.');
});
