export const CODE_SERVER_IMAGE = 'codercom/code-server:4.141.0@sha256:72ab24b5680ee597dd647b30d82625752f40109b5f61bef90ffbf1ea1f02dbb8';

function origin(value, name) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`${name} must be an absolute origin`); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`${name} must contain only scheme, hostname and optional port`);
  }
  return url;
}

function number(env, key, fallback, min, max) {
  const value = Number(env[key] || fallback);
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`Invalid ${key}`);
  return value;
}

export function loadConfig(env = process.env) {
  if (!env.IDE_GATEWAY_TOKEN || env.IDE_GATEWAY_TOKEN.length < 32) throw new Error('IDE_GATEWAY_TOKEN requires at least 32 characters');
  const publicUrl = origin(env.IDE_PUBLIC_URL, 'IDE_PUBLIC_URL');
  const platform = origin(env.PLATFORM_ORIGIN, 'PLATFORM_ORIGIN');
  const loopback = url => ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || url.hostname.endsWith('.localhost');
  const development = env.IDE_ALLOW_HTTP_LOOPBACK === 'true' && loopback(publicUrl) && loopback(platform);
  if (!development && (publicUrl.protocol !== 'https:' || platform.protocol !== 'https:')) throw new Error('HTTPS is required (HTTP is allowed only for explicit loopback development)');
  if (publicUrl.origin === platform.origin) throw new Error('IDE_PUBLIC_URL must use a separate origin from the platform');
  if (loopback(publicUrl) && publicUrl.hostname !== 'localhost') throw new Error('Use localhost for development; user workspaces use u<ID>.localhost');
  if (!loopback(publicUrl) && /^\d+(\.\d+){3}$/.test(publicUrl.hostname)) throw new Error('IDE_PUBLIC_URL requires a hostname with wildcard DNS');
  const networkMode = env.IDE_NETWORK_MODE || 'isolated';
  if (!['isolated', 'internet'].includes(networkMode)) throw new Error('Invalid IDE_NETWORK_MODE');
  const prefix = env.IDE_RESOURCE_PREFIX || 'ads-ide';
  if (!/^[a-z][a-z0-9-]{0,30}$/.test(prefix)) throw new Error('Invalid IDE_RESOURCE_PREFIX');
  return {
    token: env.IDE_GATEWAY_TOKEN,
    publicUrl: publicUrl.origin,
    platformOrigin: platform.origin,
    // Chromium treats localhost as trustworthy; SameSite=None is needed even
    // there because each user's .localhost host is embedded by the platform.
    secureCookies: true,
    bindAddress: env.IDE_BIND_ADDRESS || '127.0.0.1',
    port: number(env, 'IDE_PORT', 3100, 1, 65535),
    ticketTtlMs: 60_000,
    sessionTtlMs: number(env, 'IDE_SESSION_MINUTES', 30, 1, 30) * 60_000,
    idleMs: number(env, 'IDE_IDLE_MINUTES', 30, 1, 1440) * 60_000,
    maxUsers: number(env, 'IDE_MAX_RUNNING_USERS', 10, 1, 100),
    memoryMb: number(env, 'IDE_MEMORY_MB', 1024, 512, 65536),
    cpus: number(env, 'IDE_CPUS', 1, 1, 32),
    pids: number(env, 'IDE_PIDS_LIMIT', 256, 64, 4096),
    networkMode,
    prefix,
    image: env.IDE_WORKSPACE_IMAGE || 'ads-ide-workspace:4.141.0',
  };
}

export function workspaceOrigin(config, userId) {
  if (!validUserId(userId)) throw new Error('Invalid user ID');
  const url = new URL(config.publicUrl);
  // Keep dev workspaces on the same site as app.ide.localhost. Browsers can
  // block IndexedDB/localStorage in an otherwise cross-site VS Code iframe.
  url.hostname = url.hostname === 'localhost' ? `u${userId}.ide.localhost` : `u${userId}.${url.hostname}`;
  return url.origin;
}

export function validUserId(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value);
}
