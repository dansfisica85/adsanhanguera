import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { createGateway } from '../gateway.mjs';
import { loadConfig, workspaceOrigin } from '../config.mjs';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  return server.address().port;
}

function request(port, host, path, { method = 'GET', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers: { host, ...headers } }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('gateway separa usuários, origens, cookies e conexões; logout revoga acesso', async t => {
  const config = loadConfig({ IDE_GATEWAY_TOKEN: 'gateway-test-key-with-more-than-32-characters',
    IDE_PUBLIC_URL: 'http://localhost:4100', PLATFORM_ORIGIN: 'http://localhost:3001', IDE_ALLOW_HTTP_LOOPBACK: 'true' });
  let time = Date.now();
  const upstreams = new Map();
  for (const userId of ['1', '2']) {
    const upstream = http.createServer((req, res) => {
      res.setHeader('set-cookie', 'untrusted=value');
      res.end(JSON.stringify({ userId, cookie: req.headers.cookie || null, auth: req.headers.authorization || null }));
    });
    upstream.on('upgrade', (req, socket) => {
      const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      socket.on('error', () => {});
    });
    upstreams.set(userId, { server: upstream, target: { hostname: '127.0.0.1', port: await listen(upstream) } });
  }
  const stopped = [];
  let waitProvision;
  const runtime = {
    health: async () => true,
    ensure: async id => { if (waitProvision) await waitProvision; return upstreams.get(id).target; },
    stop: async id => { stopped.push(id); }, touch() {},
  };
  const { server, revokeAll } = createGateway({ config, runtime, now: () => time });
  const port = await listen(server);
  config.publicUrl = `http://localhost:${port}`;
  const baseHost = `localhost:${port}`;
  const admin = { authorization: `Bearer ${config.token}`, 'content-type': 'application/json' };
  t.after(async () => {
    revokeAll();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    for (const { server: upstream } of upstreams.values()) { upstream.closeAllConnections(); upstream.close(); }
  });
  const issue = async userId => {
    const res = await request(port, baseHost, '/api/sessions', { method: 'POST', headers: admin, body: JSON.stringify({ userId }) });
    assert.equal(res.status, 201);
    return JSON.parse(res.text);
  };
  const launch = async (ticket, origin = config.platformOrigin) => request(port, baseHost, '/launch', {
    method: 'POST', headers: { origin, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ ticket }).toString(),
  });
  const enter = async userId => {
    const issued = await issue(userId);
    assert.equal((await launch(issued.ticket, 'https://attacker.test')).status, 403);
    const transfer = await launch(issued.ticket);
    assert.equal(transfer.status, 200);
    assert.equal(transfer.headers['referrer-policy'], 'strict-origin');
    assert.equal((await launch(issued.ticket)).status, 401);
    const ticket = /name="ticket" value="([\w-]+)"/.exec(transfer.text)[1];
    const origin = workspaceOrigin(config, userId);
    assert.ok(transfer.text.includes(`${origin}/redeem`));
    const host = new URL(origin).host;
    const redeem = () => request(port, host, '/redeem', { method: 'POST', headers: {
      origin: config.publicUrl, 'content-type': 'application/x-www-form-urlencoded',
    }, body: new URLSearchParams({ ticket }).toString() });
    const accepted = await redeem();
    assert.equal(accepted.status, 303);
    assert.equal((await redeem()).status, 401);
    assert.match(accepted.headers['set-cookie'][0], /HttpOnly/);
    assert.match(accepted.headers['set-cookie'][0], /Secure; Partitioned/);
    assert.doesNotMatch(accepted.headers['set-cookie'][0], /Domain=/i);
    return { host, origin, cookie: accepted.headers['set-cookie'][0].split(';')[0] };
  };

  assert.equal((await request(port, baseHost, '/api/sessions', { method: 'POST' })).status, 401);
  assert.equal((await request(port, baseHost, '/api/sessions', { method: 'POST', headers: admin, body: '{"userId":"../1"}' })).status, 400);
  const a = await enter('1');
  const b = await enter('2');
  assert.notEqual(a.origin, b.origin);
  for (const [session, userId] of [[a, '1'], [b, '2']]) {
    const res = await request(port, session.host, '/', { headers: { cookie: session.cookie, authorization: 'Bearer must-not-reach-workspace' } });
    assert.deepEqual(JSON.parse(res.text), { userId, cookie: null, auth: null });
    assert.equal(res.headers['set-cookie'], undefined);
    assert.match(res.headers['content-security-policy'], /frame-ancestors/);
  }
  assert.equal((await request(port, b.host, '/', { headers: { cookie: a.cookie } })).status, 401);
  assert.equal((await request(port, a.host, '/', { method: 'POST', headers: { cookie: a.cookie, origin: b.origin } })).status, 403);

  const socket = await new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: '/websocket', headers: {
      host: a.host, cookie: a.cookie, origin: a.origin, connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==', 'sec-websocket-version': '13',
    } });
    req.on('upgrade', (res, connected) => resolve(connected));
    req.on('error', reject);
    req.end();
  });
  const closed = new Promise(resolve => socket.once('close', resolve));
  socket.resume();
  assert.equal((await request(port, baseHost, '/api/sessions/1', { method: 'DELETE', headers: admin })).status, 204);
  await closed;
  assert.deepEqual(stopped, ['1']);
  assert.equal((await request(port, a.host, '/', { headers: { cookie: a.cookie } })).status, 401);
  assert.equal((await request(port, b.host, '/', { headers: { cookie: b.cookie } })).status, 200);

  const old = await issue('1');
  time += 60001;
  assert.equal((await launch(old.ticket)).status, 401);
  time += config.sessionTtlMs;
  assert.equal((await request(port, b.host, '/', { headers: { cookie: b.cookie } })).status, 401);

  let finish;
  waitProvision = new Promise(resolve => { finish = resolve; });
  const pending = request(port, baseHost, '/api/sessions', { method: 'POST', headers: admin, body: '{"userId":"1"}' });
  await new Promise(resolve => setTimeout(resolve, 20));
  await request(port, baseHost, '/api/sessions/1', { method: 'DELETE', headers: admin });
  finish();
  assert.equal((await pending).status, 409);
});

test('configuração exige TLS em produção e origem distinta por usuário', () => {
  const env = { IDE_GATEWAY_TOKEN: 'test-token-with-at-least-32-characters', IDE_PUBLIC_URL: 'https://ide.example.test', PLATFORM_ORIGIN: 'https://app.example.test' };
  assert.equal(workspaceOrigin(loadConfig(env), '42'), 'https://u42.ide.example.test');
  assert.throws(() => loadConfig({ ...env, IDE_PUBLIC_URL: 'http://ide.example.test' }), /HTTPS/);
  assert.throws(() => loadConfig({ ...env, IDE_PUBLIC_URL: env.PLATFORM_ORIGIN }), /separate origin/);
  assert.throws(() => workspaceOrigin(loadConfig(env), '1/../../2'));
});
