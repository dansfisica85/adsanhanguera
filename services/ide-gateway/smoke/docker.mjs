import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DockerRuntime } from '../runtime.mjs';
import { loadConfig } from '../config.mjs';

const config = loadConfig({ ...process.env,
  IDE_GATEWAY_TOKEN: randomBytes(32).toString('hex'), IDE_PUBLIC_URL: 'http://localhost:4100',
  PLATFORM_ORIGIN: 'http://localhost:3001', IDE_ALLOW_HTTP_LOOPBACK: 'true',
  IDE_RESOURCE_PREFIX: `ads-smoke-${randomBytes(5).toString('hex')}`, IDE_NETWORK_MODE: 'isolated',
});
const runtime = new DockerRuntime(config);
try {
  await runtime.health();
  const first = await runtime.ensure('1');
  const second = await runtime.ensure('2');
  assert.notDeepEqual(first, second);
  for (const target of [first, second]) {
    const res = await fetch(`http://${target.hostname}:${target.port}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /code-server|workbench/i);
  }
  const name = runtime.name('1');
  const execute = args => runtime.docker(['exec', name, ...args]);
  assert.equal(await execute(['id', '-u']), '1000');
  assert.equal(await execute(['node', '-e', 'console.log(6*7)']), '42');
  assert.equal(await execute(['python3', '-c', 'print(6*7)']), '42');
  const cSource = '#include <stdio.h>\nint main(void){puts("42");}\n';
  await execute(['node', '-e', `require("fs").writeFileSync("/home/coder/smoke.c", ${JSON.stringify(cSource)})`]);
  await execute(['cc', '/home/coder/smoke.c', '-o', '/home/coder/smoke-c']);
  assert.equal(await execute(['/home/coder/smoke-c']), '42');
  await execute(['node', '-e', 'require("fs").writeFileSync("/home/coder/Smoke.java", "class Smoke { public static void main(String[] a) { System.out.println(42); } }")']);
  await execute(['javac', '/home/coder/Smoke.java']);
  assert.equal(await execute(['java', '-cp', '/home/coder', 'Smoke']), '42');
  assert.equal(await runtime.docker(['exec', runtime.name('2'), 'sh', '-c', 'test ! -e /home/coder/Smoke.java && echo isolated']), 'isolated');
  assert.equal(await execute(['node', '-e', `fetch(${JSON.stringify(`http://${second.hostname}:${second.port}/`)}, {signal: AbortSignal.timeout(1500)}).then(() => process.exit(1), () => console.log('network isolated'))`]), 'network isolated');
  await runtime.stop('1');
  await runtime.ensure('1');
  assert.equal(await execute(['java', '-cp', '/home/coder', 'Smoke']), '42');
  for (const id of ['1', '2']) {
    const info = await runtime.inspect(runtime.name(id));
    assert.equal(info.HostConfig.ReadonlyRootfs, true);
    assert.ok(info.HostConfig.CapDrop.includes('ALL'));
    assert.equal(info.Config.User, '1000:1000');
    assert.equal(info.Mounts.filter(mount => mount.Type === 'bind').length, 0);
    assert.equal(Object.keys(info.HostConfig.PortBindings || {}).length, 0);
  }
  console.log('PASS: two real code-server environments; Node/Python/C/Java execution; private files; restart persistence; container restrictions.');
} finally {
  // These names use this run's random prefix; never touch real users' resources.
  for (const id of ['1', '2']) {
    const name = runtime.name(id);
    await runtime.docker(['rm', '-f', name]).catch(() => {});
    await runtime.docker(['volume', 'rm', `${name}-home`]).catch(() => {});
    await runtime.docker(['network', 'rm', `${name}-net`]).catch(() => {});
  }
}
