/** Static workbench server. Bind remotely and access through an explicit SSH tunnel. */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';

const directory = resolve(process.env.MIYU_UI_WORKBENCH_DIR ?? '.ui-workbench');
const port = Number(process.env.PORT ?? '4317');
const host = process.env.HOST ?? '127.0.0.1';
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.woff2': 'font/woff2', '.map': 'application/json' };
const server = createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const path = resolve(directory, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!path.startsWith(directory + sep)) throw new Error('Invalid path');
    response.setHeader('Content-Type', types[extname(path)] ?? 'application/octet-stream');
    response.setHeader('Cache-Control', 'no-store');
    response.end(await readFile(path));
  } catch {
    response.statusCode = 404; response.end('Not found');
  }
});
server.listen(port, host, () => console.log(`Production component workbench: http://${host}:${port}`));
