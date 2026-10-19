const express = require('express');

const IDE_ROLES = new Set(['admin', 'coordenador', 'aluno', 'especial']);
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function getIdeConfig(env) {
  const token = env.IDE_GATEWAY_TOKEN;
  if (!env.IDE_GATEWAY_URL || !token || token.length < 32) return null;
  try {
    const url = new URL(env.IDE_GATEWAY_URL);
    const secure = url.protocol === 'https:';
    const local = url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname);
    if ((!secure && !local) || url.username || url.password || url.search || url.hash
      || (url.pathname !== '/' && url.pathname !== '')) return null;
    return { origin: url.origin, token };
  } catch {
    return null;
  }
}

// This router never writes academic data. Identity comes only from middlewareAuth.
function createIdeRouter({ env = process.env, fetchImpl = (...args) => fetch(...args) } = {}) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!req.user || !IDE_ROLES.has(req.user.role)
      || !Number.isSafeInteger(Number(req.user.id)) || Number(req.user.id) < 1) {
      return res.status(403).json({ error: 'Acesso à IDE não autorizado.' });
    }
    next();
  });

  router.get('/status', (req, res) => {
    res.json({ configured: Boolean(getIdeConfig(env)) });
  });

  router.post('/session', async (req, res) => {
    const config = getIdeConfig(env);
    if (!config) {
      return res.status(503).json({ error: 'O VS Code ainda não está disponível. Use o editor de projetos enquanto isso.' });
    }
    try {
      const upstream = await fetchImpl(`${config.origin}/api/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.token}` },
        body: JSON.stringify({ userId: String(req.user.id) }),
        redirect: 'error',
        signal: AbortSignal.timeout(25000),
      });
      if (!upstream.ok) throw new Error('gateway_unavailable');
      const data = await upstream.json();
      const launchUrl = new URL(data.launchUrl);
      const expiresAt = Date.parse(data.expiresAt);
      if (launchUrl.href !== `${config.origin}/launch`
        || typeof data.ticket !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(data.ticket)
        || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 120000) {
        throw new Error('invalid_gateway_response');
      }
      return res.json({ launchUrl: launchUrl.href, ticket: data.ticket, expiresAt: new Date(expiresAt).toISOString() });
    } catch {
      // Never expose gateway credentials, provider response bodies, or workspace paths.
      return res.status(503).json({ error: 'Não foi possível iniciar o VS Code. Tente novamente em instantes.' });
    }
  });

  router.delete('/session', async (req, res) => {
    const config = getIdeConfig(env);
    if (!config) return res.sendStatus(204);
    try {
      const upstream = await fetchImpl(`${config.origin}/api/sessions/${encodeURIComponent(String(req.user.id))}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${config.token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (!upstream.ok) throw new Error('gateway_unavailable');
      return res.sendStatus(204);
    } catch {
      return res.status(503).json({ error: 'Não foi possível encerrar a sessão da IDE. Ela será encerrada automaticamente ao expirar.' });
    }
  });

  return router;
}

module.exports = { createIdeRouter, getIdeConfig };
