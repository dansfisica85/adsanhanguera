import http from 'node:http';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { validUserId, workspaceOrigin } from './config.mjs';

const opaque = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest();
const json = (res, status, value) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
const reserved = path => path === '/launch' || path === '/redeem' || path === '/health' || path === '/api' || path.startsWith('/api/');

async function readBody(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 8192) { const error = new Error('Body too large'); error.status = 413; throw error; }
  }
  return body;
}

function cookies(req) {
  const result = new Map();
  for (const part of (req.headers.cookie || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0) result.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
  }
  return result;
}

export function createGateway({ config, runtime, now = Date.now, onError = () => {} }) {
  const tickets = new Map();
  const transfers = new Map();
  const sessions = new Map();
  const generations = new Map();
  const cookieName = config.secureCookies ? '__Host-ads_ide' : 'ads_ide_dev';
  const tokenDigest = digest(config.token);

  function headers(res) {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('content-security-policy', `frame-ancestors ${config.platformOrigin}`);
  }

  function revoke(id) {
    const session = sessions.get(id);
    if (!session) return;
    sessions.delete(id);
    clearTimeout(session.timer);
    for (const close of session.connections) close();
  }

  function prune() {
    for (const [id, ticket] of tickets) if (ticket.expiresAt <= now()) tickets.delete(id);
    for (const [id, ticket] of transfers) if (ticket.expiresAt <= now()) transfers.delete(id);
    for (const [id, session] of sessions) if (session.expiresAt <= now()) revoke(id);
  }

  function authenticate(req) {
    const id = cookies(req).get(cookieName);
    const session = sessions.get(id);
    if (!session) return null;
    if (req.headers.host !== new URL(session.origin).host) return null;
    if (session.expiresAt <= now()) { revoke(id); return null; }
    runtime.touch?.(session.userId);
    return session;
  }

  function admin(req) {
    const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || '');
    return Boolean(match && timingSafeEqual(tokenDigest, digest(match[1])));
  }

  function proxyHeaders(req, session, websocket = false) {
    const result = { ...req.headers };
    // Credentials belong to this gateway, never to user-controlled workspace processes.
    delete result.cookie;
    delete result.authorization;
    delete result['proxy-authorization'];
    delete result['x-forwarded-for'];
    delete result['x-forwarded-host'];
    delete result['x-forwarded-proto'];
    delete result.forwarded;
    delete result['x-real-ip'];
    result.host = new URL(session.origin).host;
    result['x-forwarded-host'] = result.host;
    result['x-forwarded-proto'] = new URL(session.origin).protocol.slice(0, -1);
    if (!websocket) { delete result.upgrade; result.connection = 'close'; }
    return result;
  }

  function proxyHttp(req, res, session) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers.origin !== session.origin) return json(res, 403, { error: 'Origem não autorizada.' });
    const upstream = http.request({ ...session.target, path: req.url, method: req.method, headers: proxyHeaders(req, session) }, response => {
      const outgoing = { ...response.headers };
      delete outgoing['x-frame-options'];
      delete outgoing['content-security-policy-report-only'];
      delete outgoing['set-cookie'];
      const csp = String(outgoing['content-security-policy'] || '').split(';').filter(part => !part.trim().startsWith('frame-ancestors')).filter(Boolean);
      outgoing['content-security-policy'] = [...csp, `frame-ancestors 'self' ${config.platformOrigin}`].join('; ');
      outgoing['cache-control'] = 'no-store';
      outgoing['referrer-policy'] = 'no-referrer';
      res.writeHead(response.statusCode, outgoing);
      response.pipe(res);
    });
    const close = () => { upstream.destroy(); res.destroy(); };
    session.connections.add(close);
    res.on('close', () => { session.connections.delete(close); upstream.destroy(); });
    upstream.on('error', () => { if (!res.headersSent) json(res, 502, { error: 'IDE indisponível. Abra a IDE novamente pela plataforma.' }); else res.destroy(); });
    req.on('aborted', () => upstream.destroy());
    req.pipe(upstream);
  }

  async function handler(req, res) {
    headers(res);
    let path;
    try { path = new URL(req.url, config.publicUrl).pathname; } catch { return json(res, 400, { error: 'Requisição inválida.' }); }
    try {
      const baseHost = req.headers.host === new URL(config.publicUrl).host;
      if (reserved(path) && path !== '/redeem' && !baseHost) return json(res, 404, { error: 'Endpoint inexistente.' });
      if (path === '/health' && req.method === 'GET') {
        try { await runtime.health(); return json(res, 200, { status: 'ready' }); }
        catch { return json(res, 503, { status: 'unavailable' }); }
      }
      if (path === '/api' || path.startsWith('/api/')) {
        if (!admin(req)) return json(res, 401, { error: 'Não autorizado.' });
        if (req.method === 'POST' && path === '/api/sessions') {
          if (!(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'Use application/json.' });
          let body;
          try { body = JSON.parse(await readBody(req)); } catch (error) { return json(res, error.status || 400, { error: 'Requisição inválida.' }); }
          if (!validUserId(body?.userId)) return json(res, 400, { error: 'Identificador inválido.' });
          prune();
          if (tickets.size + transfers.size >= 1000 || sessions.size >= 1000) return json(res, 503, { error: 'Limite de sessões atingido.' });
          const generation = generations.get(body.userId) || 0;
          const target = await runtime.ensure(body.userId);
          if ((generations.get(body.userId) || 0) !== generation) return json(res, 409, { error: 'Sessão revogada. Entre novamente.' });
          const ticket = opaque();
          const expiresAt = now() + config.ticketTtlMs;
          tickets.set(ticket, { userId: body.userId, target, expiresAt });
          return json(res, 201, { launchUrl: `${config.publicUrl}/launch`, ticket, expiresAt: new Date(expiresAt).toISOString() });
        }
        const match = /^\/api\/sessions\/([1-9][0-9]{0,18})$/.exec(path);
        if (req.method === 'DELETE' && match) {
          const userId = match[1];
          generations.set(userId, (generations.get(userId) || 0) + 1);
          for (const [id, ticket] of tickets) if (ticket.userId === userId) tickets.delete(id);
          for (const [id, ticket] of transfers) if (ticket.userId === userId) transfers.delete(id);
          for (const [id, session] of sessions) if (session.userId === userId) revoke(id);
          await runtime.stop(userId);
          res.writeHead(204); return res.end();
        }
        return json(res, 404, { error: 'Endpoint inexistente.' });
      }
      if (path === '/launch') {
        if (req.method !== 'POST') return json(res, 405, { error: 'Abra a IDE pela plataforma.' });
        if (req.headers.origin !== config.platformOrigin) return json(res, 403, { error: 'Origem não autorizada.' });
        if (!(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) return json(res, 415, { error: 'Formato inválido.' });
        const values = new URLSearchParams(await readBody(req));
        const id = values.get('ticket');
        const ticket = tickets.get(id);
        if (!ticket || ticket.expiresAt <= now() || values.getAll('ticket').length !== 1) { if (id) tickets.delete(id); return json(res, 401, { error: 'Acesso expirado. Reabra a IDE pela plataforma.' }); }
        // Delete synchronously before creating a session; concurrent redemption cannot succeed twice.
        tickets.delete(id);
        const transferId = opaque();
        const origin = workspaceOrigin(config, ticket.userId);
        transfers.set(transferId, { ...ticket, origin });
        const nonce = opaque();
        // Keep the Origin header on the cross-origin POST to the user's host.
        res.setHeader('referrer-policy', 'strict-origin');
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.setHeader('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; form-action ${origin}; frame-ancestors ${config.platformOrigin}; base-uri 'none'`);
        res.end(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Abrindo VS Code</title><form method="post" action="${origin}/redeem"><input type="hidden" name="ticket" value="${transferId}"><button type="submit">Continuar para o VS Code</button></form><script nonce="${nonce}">document.forms[0].submit()</script></html>`);
        return;
      }
      if (path === '/redeem') {
        if (req.method !== 'POST' || req.headers.origin !== config.publicUrl) return json(res, 403, { error: 'Origem não autorizada.' });
        if (!(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) return json(res, 415, { error: 'Formato inválido.' });
        const values = new URLSearchParams(await readBody(req));
        const id = values.get('ticket');
        const ticket = transfers.get(id);
        if (!ticket || ticket.expiresAt <= now() || values.getAll('ticket').length !== 1 || req.headers.host !== new URL(ticket.origin).host) return json(res, 401, { error: 'Acesso expirado. Reabra a IDE pela plataforma.' });
        transfers.delete(id);
        const previous = cookies(req).get(cookieName);
        if (previous) revoke(previous);
        const sessionId = opaque();
        const expiresAt = now() + config.sessionTtlMs;
        const session = { ...ticket, expiresAt, connections: new Set(), timer: setTimeout(() => revoke(sessionId), config.sessionTtlMs) };
        session.timer.unref();
        sessions.set(sessionId, session);
        res.setHeader('set-cookie', `${cookieName}=${sessionId}; Path=/; HttpOnly; Max-Age=${Math.floor(config.sessionTtlMs / 1000)}; SameSite=${config.secureCookies ? 'None; Secure; Partitioned' : 'Lax'}`);
        res.writeHead(303, { location: '/' }); return res.end();
      }
      const session = authenticate(req);
      if (!session) return json(res, 401, { error: 'Abra a IDE pela plataforma para iniciar uma sessão.' });
      return proxyHttp(req, res, session);
    } catch (error) {
      onError(error);
      if (!res.headersSent) json(res, error.status || 503, { error: 'Não foi possível iniciar a IDE. Tente novamente.' });
      else res.destroy();
    }
  }

  const server = http.createServer({ maxHeaderSize: 16_384 }, handler);
  server.requestTimeout = 60_000;
  server.headersTimeout = 15_000;
  server.on('upgrade', (req, socket, head) => {
    const reject = status => socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    let path;
    try { path = new URL(req.url, config.publicUrl).pathname; } catch { return reject('400 Bad Request'); }
    if (reserved(path)) return reject('404 Not Found');
    const session = authenticate(req);
    if (!session) return reject('401 Unauthorized');
    if (req.headers.origin !== session.origin || req.headers.upgrade?.toLowerCase() !== 'websocket') return reject('403 Forbidden');
    const upstream = http.request({ ...session.target, path: req.url, method: 'GET', headers: proxyHeaders(req, session, true) });
    let upstreamSocket;
    const close = () => { upstream.destroy(); upstreamSocket?.destroy(); socket.destroy(); };
    session.connections.add(close);
    socket.on('error', close);
    socket.on('close', () => { session.connections.delete(close); upstream.destroy(); upstreamSocket?.destroy(); });
    upstream.on('upgrade', (response, connected, upstreamHead) => {
      upstreamSocket = connected;
      const responseHeaders = Object.entries(response.headers).filter(([key]) => !['set-cookie', 'x-frame-options'].includes(key)).map(([key, value]) => `${key}: ${value}`).join('\r\n');
      socket.write(`HTTP/1.1 101 Switching Protocols\r\n${responseHeaders}\r\n\r\n`);
      if (upstreamHead.length) socket.write(upstreamHead);
      if (head.length) connected.write(head);
      socket.pipe(connected); connected.pipe(socket);
      socket.on('data', () => runtime.touch?.(session.userId));
      connected.on('data', () => runtime.touch?.(session.userId));
      connected.on('error', close);
      connected.on('close', close);
    });
    upstream.on('response', response => { response.resume(); reject('502 Bad Gateway'); });
    upstream.on('error', close);
    upstream.end();
  });
  const cleanup = setInterval(prune, 30_000);
  cleanup.unref();
  server.on('close', () => { clearInterval(cleanup); for (const id of sessions.keys()) revoke(id); });
  return { server, revokeAll: () => { tickets.clear(); transfers.clear(); for (const id of sessions.keys()) revoke(id); } };
}
