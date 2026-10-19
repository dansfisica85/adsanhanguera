import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import http from 'node:http';
import { validUserId } from './config.mjs';

const execFileAsync = promisify(execFile);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

export class DockerRuntime {
  constructor(config) {
    this.config = config;
    this.activity = new Map();
    this.queue = Promise.resolve();
  }

  async docker(args) {
    const { stdout } = await execFileAsync('docker', args, { timeout: 90_000, maxBuffer: 1024 * 1024 });
    return stdout.trim();
  }

  serialize(fn) {
    const operation = this.queue.then(fn);
    this.queue = operation.catch(() => {});
    return operation;
  }

  name(userId) {
    if (!validUserId(userId)) throw new Error('Invalid user ID');
    return `${this.config.prefix}-u${userId}`;
  }

  async inspect(name) {
    try { return JSON.parse(await this.docker(['container', 'inspect', name]))[0]; }
    catch (error) {
      if (error.stderr?.includes('No such container') || error.stderr?.includes('No such object')) return null;
      throw error;
    }
  }

  async health() {
    const version = await this.docker(['version', '--format', '{{.Server.Version}}']);
    if (Number(version.split('.')[0]) < 28) throw new Error('Docker 28 or later is required');
    await this.docker(['image', 'inspect', this.config.image, '--format', '{{.Id}}']);
    return true;
  }

  touch(userId) { this.activity.set(userId, Date.now()); }

  ensure(userId) {
    return this.serialize(async () => {
      const name = this.name(userId);
      let container = await this.inspect(name);
      if (container && (container.Config.Labels?.['ads.ide.owner'] !== userId || container.Config.Labels?.['ads.ide.gateway'] !== this.config.prefix)) {
        throw new Error('Resource ownership mismatch');
      }
      if (container) {
        const networkName = `${name}-net`;
        const network = JSON.parse(await this.docker(['network', 'inspect', networkName]))[0];
        if (network.Internal !== (this.config.networkMode === 'isolated')
          || network.Labels?.['ads.ide.owner'] !== userId
          || network.Labels?.['ads.ide.gateway'] !== this.config.prefix
          || Object.keys(container.NetworkSettings.Networks).length !== 1
          || !container.NetworkSettings.Networks[networkName]) throw new Error('Existing workspace network policy mismatch');
      }
      if (!container?.State.Running) {
        const running = (await this.docker(['ps', '-q', '--filter', `label=ads.ide.gateway=${this.config.prefix}`])).split('\n').filter(Boolean);
        if (running.length >= this.config.maxUsers) throw new Error('IDE capacity reached');
      }
      if (!container) {
        // A private network for each user prevents one IDE reaching another unauthenticated code-server.
        const networkName = `${name}-net`;
        let network;
        try { network = JSON.parse(await this.docker(['network', 'inspect', networkName]))[0]; }
        catch (error) { if (!error.stderr?.includes('not found') && !error.stderr?.includes('No such network')) throw error; }
        if (network) {
          if (network.Labels?.['ads.ide.gateway'] !== this.config.prefix || network.Labels?.['ads.ide.owner'] !== userId || network.Internal !== (this.config.networkMode === 'isolated')) throw new Error('Network ownership or policy mismatch');
        } else {
          await this.docker(['network', 'create', '--driver', 'bridge', ...(this.config.networkMode === 'isolated' ? ['--internal'] : []), '--label', `ads.ide.gateway=${this.config.prefix}`, '--label', `ads.ide.owner=${userId}`, networkName]);
        }
        const volume = `${name}-home`;
        let volumeInfo;
        try { volumeInfo = JSON.parse(await this.docker(['volume', 'inspect', volume]))[0]; }
        catch (error) { if (!error.stderr?.includes('no such volume')) throw error; }
        if (volumeInfo && (volumeInfo.Labels?.['ads.ide.gateway'] !== this.config.prefix || volumeInfo.Labels?.['ads.ide.owner'] !== userId)) throw new Error('Volume ownership mismatch');
        if (!volumeInfo) await this.docker(['volume', 'create', '--label', `ads.ide.gateway=${this.config.prefix}`, '--label', `ads.ide.owner=${userId}`, volume]);
        await this.docker([
          'create', '--name', name, '--label', `ads.ide.gateway=${this.config.prefix}`, '--label', `ads.ide.owner=${userId}`,
          '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
          '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '--shm-size', '64m',
          '--memory', `${this.config.memoryMb}m`, '--memory-swap', `${this.config.memoryMb}m`, '--cpus', String(this.config.cpus), '--pids-limit', String(this.config.pids),
          '--network', networkName,
          ...(this.config.networkMode === 'isolated' ? [] : ['--publish', '127.0.0.1::8080']),
          '--mount', `type=volume,src=${volume},dst=/home/coder`,
          '--env', 'HOME=/home/coder', '--env', 'DOCKER_USER=coder',
          '--log-driver', 'local', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=2',
          '--entrypoint', '/usr/bin/dumb-init', this.config.image, '--', '/usr/bin/code-server',
          '--bind-addr', '0.0.0.0:8080', '--auth', 'none', '--disable-telemetry', '--disable-update-check',
          '--disable-getting-started-override', '/home/coder',
        ]);
      }
      if (!container?.State.Running) await this.docker(['start', name]);
      container = await this.inspect(name);
      let target;
      if (this.config.networkMode === 'isolated') {
        const address = container.NetworkSettings.Networks[`${name}-net`]?.IPAddress;
        if (!address || !/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) throw new Error('Missing private workspace address');
        target = { hostname: address, port: 8080 };
      } else {
        const binding = container.NetworkSettings.Ports['8080/tcp']?.find(value => value.HostIp === '127.0.0.1');
        if (!binding || !/^\d+$/.test(binding.HostPort)) throw new Error('Missing loopback port binding');
        target = { hostname: '127.0.0.1', port: Number(binding.HostPort) };
      }
      await this.waitReady(target);
      this.touch(userId);
      return target;
    });
  }

  async waitReady(target) {
    for (let attempt = 0; attempt < 60; attempt++) {
      const ready = await new Promise(resolve => {
        const request = http.get({ ...target, path: '/healthz', timeout: 800 }, response => {
          response.resume();
          resolve(response.statusCode === 200);
        });
        request.on('error', () => resolve(false));
        request.on('timeout', () => { request.destroy(); resolve(false); });
      });
      if (ready) return;
      await delay(500);
    }
    throw new Error('code-server did not become ready');
  }

  stop(userId) {
    return this.serialize(async () => {
      const name = this.name(userId);
      const container = await this.inspect(name);
      if (container?.Config.Labels?.['ads.ide.gateway'] === this.config.prefix && container.Config.Labels['ads.ide.owner'] === userId && container.State.Running) await this.docker(['stop', '--time', '10', name]);
      this.activity.delete(userId);
    });
  }

  async reap() {
    const names = (await this.docker(['ps', '--format', '{{.Names}}', '--filter', `label=ads.ide.gateway=${this.config.prefix}`])).split('\n').filter(Boolean);
    for (const name of names) {
      if (!name.startsWith(`${this.config.prefix}-u`)) continue;
      const userId = name.slice(this.config.prefix.length + 2);
      if (!validUserId(userId)) continue;
      if (!this.activity.has(userId)) this.touch(userId);
      else if (Date.now() - this.activity.get(userId) > this.config.idleMs) await this.stop(userId);
    }
  }
}
