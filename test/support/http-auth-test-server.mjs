import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const configPath = process.argv[2];
if (!configPath) throw new Error('A configuration path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
if (
  typeof config.username !== 'string'
  || config.username.length === 0
  || typeof config.password !== 'string'
  || config.password.length === 0
) throw new Error('Invalid Basic authentication test configuration');

const expected = Buffer.from(`Basic ${Buffer.from(`${config.username}:${config.password}`).toString('base64')}`);
const metrics = { requests: 0, challenges: 0, authorizationAttempts: 0, successes: 0 };

const server = createServer((request, response) => {
  const path = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
  if (path === '/health') {
    response.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
    response.end('ok');
    return;
  }
  if (path === '/metrics') {
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(metrics));
    return;
  }
  if (path === '/favicon.ico') {
    response.writeHead(204, { 'cache-control': 'no-store' });
    response.end();
    return;
  }
  if (path !== '/protected') {
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found');
    return;
  }

  metrics.requests += 1;
  const authorization = request.headers.authorization;
  if (typeof authorization === 'string') metrics.authorizationAttempts += 1;
  const actual = Buffer.from(authorization ?? '');
  const allowed = actual.length === expected.length && timingSafeEqual(actual, expected);
  actual.fill(0);
  if (!allowed) {
    metrics.challenges += 1;
    response.writeHead(401, {
      'www-authenticate': 'Basic realm="MiYu HTTP Auth E2E", charset="UTF-8"',
      'content-type': 'text/plain',
      'cache-control': 'no-store',
    });
    response.end('authentication required');
    return;
  }

  metrics.successes += 1;
  response.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end('<!doctype html><html><body><main data-authenticated="true">HTTP authentication succeeded</main></body></html>');
});

server.listen(18083, '127.0.0.1', () => {
  process.stdout.write('ready\n');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
