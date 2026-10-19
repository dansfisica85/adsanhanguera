const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createIdeRouter, getIdeConfig } = require('../src/ide');
const { configurarCarregadorUsuario, gerarToken, middlewareAuth } = require('../src/auth');

process.env.JWT_SECRET = 'ide-route-test-secret-at-least-32-characters';
const env = { IDE_GATEWAY_URL: 'https://ide.example.test', IDE_GATEWAY_TOKEN: 'test-gateway-token-with-at-least-32-characters' };
const users = ['admin', 'coordenador', 'aluno', 'especial'].map((role, i) => ({
  id: i + 1, nome: `Teste ${role}`, email: `${role}@example.test`, role, token_version: 0,
}));
configurarCarregadorUsuario(async id => users.find(user => user.id === Number(id)));

test('configuração da IDE aceita HTTPS e desenvolvimento local, recusando destinos ambíguos', () => {
  assert.equal(getIdeConfig(env).origin, env.IDE_GATEWAY_URL);
  assert.equal(getIdeConfig({ ...env, IDE_GATEWAY_URL: 'http://127.0.0.1:4100/' }).origin, 'http://127.0.0.1:4100');
  for (const value of ['http://ide.example.test', 'https://ide.example.test/path', 'https://user:pass@ide.example.test',
    'https://ide.example.test/?secret=1', 'javascript:alert(1)', 'https://ide.example.test/#x']) {
    assert.equal(getIdeConfig({ ...env, IDE_GATEWAY_URL: value }), null);
  }
  assert.equal(getIdeConfig({ ...env, IDE_GATEWAY_TOKEN: '' }), null);
});

test('rotas da IDE usam a identidade autenticada dos quatro perfis sem gravar dados acadêmicos', async t => {
  const calls = [];
  let response = () => Response.json({
    launchUrl: `${env.IDE_GATEWAY_URL}/launch`, ticket: 'a'.repeat(43), expiresAt: new Date(Date.now() + 60000).toISOString(),
  });
  const config = { ...env };
  const app = express();
  app.use(express.json());
  app.use('/api/ide', middlewareAuth, createIdeRouter({ env: config, fetchImpl: async (url, init) => {
    calls.push({ url, init });
    return response();
  } }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/ide`;
  const headers = user => ({ Authorization: `Bearer ${gerarToken(user)}`, 'Content-Type': 'application/json' });

  for (const path of ['/status', '/session']) {
    const res = await fetch(base + path, { method: path === '/session' ? 'POST' : 'GET' });
    assert.equal(res.status, 401);
  }
  assert.equal(calls.length, 0);
  for (const user of users) {
    const res = await fetch(`${base}/session`, {
      method: 'POST', headers: headers(user), body: JSON.stringify({ userId: '999', role: 'admin', projectId: 44 }),
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.launchUrl, `${env.IDE_GATEWAY_URL}/launch`);
    assert.equal(JSON.stringify(data).includes(env.IDE_GATEWAY_TOKEN), false);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const call = calls.at(-1);
    assert.deepEqual(JSON.parse(call.init.body), { userId: String(user.id) });
    assert.equal(call.init.headers.Authorization, `Bearer ${env.IDE_GATEWAY_TOKEN}`);
    assert.equal(call.init.redirect, 'error');
  }

  const status = await fetch(`${base}/status`, { headers: headers(users[2]) });
  assert.deepEqual(await status.json(), { configured: true });
  const count = calls.length;
  config.IDE_GATEWAY_TOKEN = '';
  assert.deepEqual(await (await fetch(`${base}/status`, { headers: headers(users[2]) })).json(), { configured: false });
  assert.equal((await fetch(`${base}/session`, { method: 'POST', headers: headers(users[2]) })).status, 503);
  assert.equal(calls.length, count);
  config.IDE_GATEWAY_TOKEN = env.IDE_GATEWAY_TOKEN;

  for (const launchUrl of ['https://evil.example/launch', `${env.IDE_GATEWAY_URL}/launch?token=x`,
    `${env.IDE_GATEWAY_URL}/other`, `https://user:password@ide.example.test/launch`]) {
    response = () => Response.json({ launchUrl, ticket: 'b'.repeat(43), expiresAt: new Date(Date.now() + 60000).toISOString() });
    const res = await fetch(`${base}/session`, { method: 'POST', headers: headers(users[2]) });
    assert.equal(res.status, 503);
    assert.equal((await res.text()).includes('evil.example'), false);
  }
  for (const data of [
    { launchUrl: `${env.IDE_GATEWAY_URL}/launch`, ticket: 'bad', expiresAt: new Date(Date.now() + 60000).toISOString() },
    { launchUrl: `${env.IDE_GATEWAY_URL}/launch`, ticket: 'b'.repeat(43), expiresAt: '2000-01-01T00:00:00Z' },
  ]) {
    response = () => Response.json(data);
    assert.equal((await fetch(`${base}/session`, { method: 'POST', headers: headers(users[2]) })).status, 503);
  }
  response = () => { throw new Error('upstream failure with private diagnostics'); };
  const failed = await fetch(`${base}/session`, { method: 'POST', headers: headers(users[2]) });
  assert.equal(failed.status, 503);
  assert.equal((await failed.text()).includes('private diagnostics'), false);

  response = () => new Response(null, { status: 204 });
  const revoked = await fetch(`${base}/session`, { method: 'DELETE', headers: headers(users[2]) });
  assert.equal(revoked.status, 204);
  assert.equal(calls.at(-1).url, `${env.IDE_GATEWAY_URL}/api/sessions/3`);
  assert.equal(calls.at(-1).init.method, 'DELETE');

  const staleHeaders = headers(users[2]);
  users[2].token_version++;
  assert.equal((await fetch(`${base}/session`, { method: 'POST', headers: staleHeaders })).status, 401);
  users[2].role = 'desconhecido';
  assert.equal((await fetch(`${base}/session`, { method: 'POST', headers: headers(users[2]) })).status, 403);
});
