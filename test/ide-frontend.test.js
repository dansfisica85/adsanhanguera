const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const appSource = fs.readFileSync(path.join(root, 'public/app.js'), 'utf8');
const ideSource = fs.readFileSync(path.join(root, 'public/vscode-ide.js'), 'utf8');
const indexSource = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8');
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const session = (overrides = {}) => ({
  launchUrl: 'https://ide.example.com/launch',
  ticket: 'one-use-ticket',
  expiresAt: new Date(Date.now() + 60000).toISOString(),
  ...overrides,
});

function harness(implementation = async url => response(url.endsWith('/status') ? { configured: true } : session())) {
  const calls = [];
  const submissions = [];
  const frames = [];
  const popups = [];
  const timers = new Map();
  let timerId = 0;

  function createElement(tag = 'div') {
    const classes = new Set();
    const node = {
      tagName: tag, children: [], hidden: false, disabled: false, textContent: '', value: '',
      attributes: {}, removed: false,
      classList: { add: name => classes.add(name), remove: name => classes.delete(name), toggle(name, state) { if (state) classes.add(name); else classes.delete(name); } },
      appendChild(child) { this.children.push(child); child.parentNode = this; },
      remove() { this.removed = true; if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this); },
      setAttribute(name, value) { this.attributes[name] = value; },
      submit() { submissions.push({ method: this.method, action: this.action, target: this.target, inputs: this.children.map(input => ({ name: input.name, value: input.value })) }); },
      requestFullscreen: async () => {},
      contentWindow: { location: { href: 'about:blank' } },
    };
    if (tag === 'iframe') frames.push(node);
    return node;
  }

  const elements = Object.fromEntries([
    'vscodeShell', 'vscodeStatus', 'vscodeMessage', 'vscodeFrameHost',
    'vscodeOpenButton', 'vscodeNewTabButton', 'vscodeFullscreenButton',
    'vscodeRetryButton', 'vscodeEditorButton', 'tab-vscode',
  ].map(id => [id, createElement()]));
  const document = {
    body: createElement('body'),
    addEventListener() {},
    getElementById: id => elements[id] || null,
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement,
  };
  const context = {
    URL, AbortController, console,
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    document,
    window: {
      addEventListener() {},
      open() {
        const popup = { document: { createElement, body: createElement('body') }, opener: {}, closed: false, close() { this.closed = true; } };
        popups.push(popup);
        return popup;
      },
    },
    localStorage: { getItem() { return null; }, removeItem() {}, setItem() {} },
    fetch(url, options) { calls.push({ url, options }); return implementation(url, options); },
  };
  vm.createContext(context);
  vm.runInContext(appSource, context);
  vm.runInContext(ideSource, context);
  vm.runInContext("authToken = 'platform-jwt'; currentUser = { id: 3, role: 'aluno' };", context);
  return {
    calls, elements, submissions, frames, popups, context,
    run: code => vm.runInContext(code, context),
    runTimer(delay) { const match = [...timers.entries()].find(([, timer]) => timer.delay === delay); assert.ok(match); timers.delete(match[0]); match[1].callback(); },
  };
}

test('aba VS Code independe do Monaco e fica disponível para todos os perfis autenticados', async () => {
  assert.match(indexSource, /data-tab="vscode"[^>]*onclick="switchTab\('vscode'\)"/);
  for (const role of ['admin', 'aluno', 'especial', 'coordenador']) {
    const h = harness();
    h.run(`currentUser.role = '${role}'; loadCodeEditor = () => { throw new Error('Monaco não deve ser usado'); }; switchTab('vscode');`);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls[0].url, '/api/ide/status');
    assert.equal(h.calls[0].options.headers.Authorization, 'Bearer platform-jwt');
    assert.equal(h.elements.vscodeOpenButton.hidden, false);
  }
});

test('IDE desativada oferece o editor existente sem solicitar configurações ao aluno', async () => {
  const h = harness(async () => response({ configured: false }));
  await h.run('window.vscodeIDE.show()');
  assert.equal(h.elements.vscodeMessage.textContent, 'VS Code ainda não está disponível. Você pode continuar usando o editor de projetos.');
  assert.equal(h.elements.vscodeEditorButton.hidden, false);
  assert.equal(h.elements.vscodeOpenButton.hidden, true);
  await h.run('window.vscodeIDE.launch()');
  assert.equal(h.calls.length, 1);
});

test('sessão usa autenticação somente na API e envia ticket por formulário POST sem persistência', async () => {
  const h = harness();
  await h.run('window.vscodeIDE.show()');
  await h.run('window.vscodeIDE.launch()');
  assert.equal(h.calls[1].url, '/api/ide/session');
  assert.equal(h.calls[1].options.method, 'POST');
  assert.equal(h.calls[1].options.headers.Authorization, 'Bearer platform-jwt');
  assert.equal(h.calls[1].options.body, '{}');
  assert.deepEqual(h.submissions, [{ method: 'POST', action: 'https://ide.example.com/launch', target: 'vscode-workspace', inputs: [{ name: 'ticket', value: 'one-use-ticket' }] }]);
  assert.equal(h.context.document.body.children.length, 0);
  assert.equal(h.frames.length, 1);
  assert.equal(h.elements.vscodeFrameHost.hidden, false);
  assert.equal(h.frames[0].src, undefined);
  assert.doesNotMatch(ideSource, /localStorage|sessionStorage|console\./);
});

test('logout remove a IDE imediatamente e revoga com os cabeçalhos anteriores ao clearAuth', async () => {
  const h = harness();
  await h.run('window.vscodeIDE.show()');
  await h.run('window.vscodeIDE.launch()');
  h.run('clearAuth()');
  assert.equal(h.frames[0].removed, true);
  assert.equal(h.elements.vscodeFrameHost.hidden, true);
  assert.equal(h.run('authToken'), null);
  assert.equal(h.calls.at(-1).options.method, 'DELETE');
  assert.equal(h.calls.at(-1).options.headers.Authorization, 'Bearer platform-jwt');
  assert.equal(h.calls.at(-1).options.keepalive, true);
});

test('resposta atrasada após logout não recria iframe nem envia ticket', async () => {
  let resolveSession;
  const h = harness(async (url, options) => {
    if (options.method === 'POST') return new Promise(resolve => { resolveSession = resolve; });
    return response({ configured: true });
  });
  await h.run('window.vscodeIDE.show()');
  const pending = h.run('window.vscodeIDE.launch()');
  const requestSignal = h.calls.at(-1).options.signal;
  h.run('clearAuth()');
  assert.equal(requestSignal.aborted, true);
  h.run("authToken = 'other-user-jwt'; currentUser = { id: 7, role: 'admin' };");
  resolveSession(response(session()));
  await pending;
  assert.equal(h.frames.length, 0);
  assert.equal(h.submissions.length, 0);
  assert.equal(h.elements.vscodeOpenButton.hidden, true);
});

test('falhas de autenticação e respostas técnicas não expõem conteúdo do servidor', async () => {
  for (const status of [401, 502]) {
    const h = harness(async () => response({ error: 'secret internal configuration' }, status));
    await h.run('window.vscodeIDE.show()');
    assert.doesNotMatch(h.elements.vscodeMessage.textContent, /secret internal/);
    assert.equal(h.elements.vscodeRetryButton.hidden, false);
    if (status === 401) assert.match(h.elements.vscodeMessage.textContent, /sessão expirou/);
  }
});

test('destinos inseguros, credenciais na URL e tickets expirados nunca são enviados', async () => {
  const invalidSessions = [
    { launchUrl: 'javascript:alert(1)' },
    { launchUrl: 'http://ide.example.com/launch' },
    { launchUrl: 'https://user:password@ide.example.com/launch' },
    { launchUrl: 'https://ide.example.com/launch?ticket=leaked' },
    { launchUrl: 'https://ide.example.com/launch#ticket' },
    { expiresAt: '2000-01-01T00:00:00.000Z' },
  ];
  for (const invalid of invalidSessions) {
    const h = harness(async url => response(url.endsWith('/status') ? { configured: true } : session(invalid)));
    await h.run('window.vscodeIDE.show()');
    await h.run('window.vscodeIDE.launch()');
    assert.equal(h.submissions.length, 0);
    assert.equal(h.frames.length, 0);
    assert.match(h.elements.vscodeMessage.textContent, /Não foi possível abrir/);
  }
});

test('HTTP é permitido somente para desenvolvimento em loopback', async () => {
  const h = harness(async url => response(url.endsWith('/status') ? { configured: true } : session({ launchUrl: 'http://127.0.0.1:9090/launch' })));
  await h.run('window.vscodeIDE.show()');
  await h.run('window.vscodeIDE.launch()');
  assert.equal(h.submissions[0].action, 'http://127.0.0.1:9090/launch');
});

test('nova aba usa POST próprio, remove opener e fecha ao sair da plataforma', async () => {
  const h = harness();
  await h.run('window.vscodeIDE.show()');
  await h.run("window.vscodeIDE.launch('tab')");
  assert.equal(h.popups[0].opener, null);
  assert.equal(h.submissions[0].target, '_self');
  assert.equal(h.popups[0].document.body.children.length, 0);
  assert.equal(h.frames.length, 0);
  h.run('clearAuth()');
  assert.equal(h.popups[0].closed, true);
});

test('cancelamento por timeout libera tentativa e cliques repetidos não duplicam sessão', async () => {
  const h = harness(async (url, options) => {
    if (options.method !== 'POST') return response({ configured: true });
    return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => {
      const error = new Error('Request aborted');
      error.name = 'AbortError';
      reject(error);
    }));
  });
  await h.run('window.vscodeIDE.show()');
  const pending = h.run('window.vscodeIDE.launch()');
  await h.run('window.vscodeIDE.launch()');
  assert.equal(h.calls.filter(call => call.options.method === 'POST').length, 1);
  h.runTimer(30000);
  await pending;
  assert.match(h.elements.vscodeMessage.textContent, /demorou/);
  assert.equal(h.elements.vscodeOpenButton.disabled, false);
});
