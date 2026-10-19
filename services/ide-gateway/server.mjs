import { loadConfig } from './config.mjs';
import { DockerRuntime } from './runtime.mjs';
import { createGateway } from './gateway.mjs';

try {
  const config = loadConfig();
  const runtime = new DockerRuntime(config);
  await runtime.health();
  const { server, revokeAll } = createGateway({ config, runtime, onError: () => console.error('IDE operation failed; inspect Docker state locally without logging credentials.') });
  server.listen(config.port, config.bindAddress, () => console.log(`IDE gateway listening on ${config.bindAddress}:${config.port}`));
  const maintenance = setInterval(() => runtime.reap().catch(() => console.error('IDE idle maintenance failed')), 60_000);
  maintenance.unref();
  let closing = false;
  const stop = () => {
    if (closing) return;
    closing = true;
    clearInterval(maintenance);
    revokeAll();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
} catch (error) {
  // Configuration errors are safe; Docker command errors may include operational detail.
  console.error(error.stderr ? 'Docker is unavailable or the workspace image is missing. Follow README.md.' : error.message);
  process.exitCode = 1;
}
