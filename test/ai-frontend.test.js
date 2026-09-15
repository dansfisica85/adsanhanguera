const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const appSource = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');

function jsonResponse(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => 'application/json; charset=utf-8' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function textResponse(status, body, contentType = 'text/html; charset=utf-8') {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => contentType },
    json: async () => { throw new SyntaxError('Resposta nao JSON'); },
    text: async () => body,
  };
}

function createScheduler() {
  let nextId = 1;
  const tasks = new Map();
  return {
    setTimeout(callback, delay) {
      const id = nextId++;
      tasks.set(id, { callback, delay });
      return id;
    },
    clearTimeout(id) {
      tasks.delete(id);
    },
    runDelay(delay) {
      const match = [...tasks.entries()].find(([, task]) => task.delay === delay);
      assert.ok(match, `Timer de ${delay}ms nao foi criado`);
      const [id, task] = match;
      tasks.delete(id);
      task.callback();
    },
    hasDelay(delay) {
      return [...tasks.values()].some(task => task.delay === delay);
    },
  };
}

function createHarness(fetchImplementation) {
  const calls = [];
  const rendered = [];
  const scheduler = createScheduler();
  const elements = {
    aiChatInput: { value: 'Pergunta digitada', focus() {} },
    aiSendBtn: { disabled: false },
    aiChatMessages: { innerHTML: '', appendChild() {}, scrollTop: 0, scrollHeight: 0 },
    aiChatPanel: { classList: { toggle() {} } },
  };

  const context = {
    AbortController,
    console: { log() {}, warn() {}, error() {} },
    setTimeout: scheduler.setTimeout,
    clearTimeout: scheduler.clearTimeout,
    window: { addEventListener() {}, innerWidth: 1280 },
    location: { href: '', reload() {} },
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    document: {
      addEventListener() {},
      getElementById(id) { return elements[id] || null; },
      querySelector(selector) {
        return selector === '.code-lang-tab.active' ? { dataset: { lang: 'html' } } : null;
      },
      querySelectorAll() { return []; },
      createElement() { return { className: '', id: '', innerHTML: '', remove() {} }; },
    },
    fetch(url, options) {
      calls.push({ url, options });
      return fetchImplementation(url, options, calls.length);
    },
    __rendered: rendered,
  };

  vm.createContext(context);
  vm.runInContext(appSource, context);
  vm.runInContext(`
    authToken = 'jwt-de-teste';
    currentUser = { nome: 'Aluno Teste' };
    aiChatIsOpen = true;
    appendAIMsg = (role, text) => __rendered.push({ role, text });
    appendAITyping = () => 'typing-test';
    removeAITyping = () => {};
    getEditorValue = () => '<h1>Contexto</h1>';
  `, context);

  return {
    calls,
    rendered,
    scheduler,
    elements,
    run(code) { return vm.runInContext(code, context); },
  };
}

test('chat envia contrato autenticado e aceita somente uma requisicao por vez', async () => {
  let resolveRequest;
  const harness = createHarness(() => new Promise(resolve => { resolveRequest = resolve; }));

  const firstRequest = harness.run(`sendAIMessage('Primeira pergunta', true)`);
  await harness.run(`sendAIMessage('Segunda pergunta', false)`);
  harness.run(`aiHandleKey({ key: 'Enter', shiftKey: false, preventDefault() {} })`);
  harness.run(`aiQuickAsk('Atalho rapido')`);

  assert.equal(harness.calls.length, 1);
  assert.equal(harness.elements.aiSendBtn.disabled, true);
  assert.equal(harness.calls[0].url, '/api/ai/chat');
  assert.equal(harness.calls[0].options.method, 'POST');
  assert.equal(harness.calls[0].options.headers.Authorization, 'Bearer jwt-de-teste');
  assert.ok(harness.calls[0].options.signal);
  assert.deepEqual(JSON.parse(harness.calls[0].options.body), {
    messages: [{ role: 'user', content: 'Primeira pergunta' }],
    includeCode: true,
    codigoContexto: '<h1>Contexto</h1>',
  });

  resolveRequest(jsonResponse(200, { reply: 'Resposta valida' }));
  await firstRequest;

  assert.equal(harness.elements.aiSendBtn.disabled, false);
  assert.equal(harness.rendered.at(-1).role, 'assistant');
  assert.equal(harness.rendered.at(-1).text, 'Resposta valida');
});

test('chat nao repete POST em erro 503 e remove a pergunta falha do historico', async () => {
  const harness = createHarness(async () => jsonResponse(503, { error: 'IA temporariamente indisponivel.' }));

  await harness.run(`sendAIMessage('Teste 503', false)`);

  assert.equal(harness.calls.length, 1);
  assert.match(harness.rendered.at(-1).text, /IA temporariamente indisponivel/);
  assert.equal(harness.run('aiChatHistory.length'), 0);
});

test('chat converte erro nao JSON em mensagem amigavel', async () => {
  const harness = createHarness(async () => textResponse(502, '<html>Bad Gateway</html>'));

  await harness.run(`sendAIMessage('Teste HTML', false)`);

  const message = harness.rendered.at(-1).text;
  assert.match(message, /Serviço de IA indisponível no momento \(erro 502\)/);
  assert.doesNotMatch(message, /Unexpected token|Resposta nao JSON/);
});

test('chat apresenta orientacao amigavel quando a sessao expira', async () => {
  const harness = createHarness(async () => jsonResponse(401, { error: 'Token invalido.' }));

  await harness.run(`sendAIMessage('Teste 401', false)`);

  assert.match(harness.rendered.at(-1).text, /sessão expirou.*Saia e entre novamente/i);
  assert.equal(harness.calls.length, 1);
});

test('chat normaliza corpo JSON nulo sem confundir com falha de rede', async () => {
  const harness = createHarness(async () => jsonResponse(502, null));

  await harness.run(`sendAIMessage('Teste JSON nulo', false)`);

  const message = harness.rendered.at(-1).text;
  assert.match(message, /Serviço de IA indisponível no momento \(erro 502\)/);
  assert.doesNotMatch(message, /internet|conectar/i);
});

test('chat rejeita resposta 200 vazia', async () => {
  const harness = createHarness(async () => jsonResponse(200, { reply: '   ' }));

  await harness.run(`sendAIMessage('Teste vazio', false)`);

  assert.match(harness.rendered.at(-1).text, /resposta vazia/i);
  assert.equal(harness.run('aiChatHistory.length'), 0);
});

test('chat cancela depois de 35 segundos e sempre libera o envio', async () => {
  const harness = createHarness((url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => {
      const error = new Error('Abortado');
      error.name = 'AbortError';
      reject(error);
    });
  }));

  const pending = harness.run(`sendAIMessage('Teste timeout', false)`);
  assert.equal(harness.scheduler.hasDelay(35000), true);
  harness.scheduler.runDelay(35000);
  await pending;

  assert.match(harness.rendered.at(-1).text, /mais de 35 segundos/i);
  assert.equal(harness.elements.aiSendBtn.disabled, false);
  assert.equal(harness.run('aiRequestInFlight'), false);
});

test('limpar conversa durante requisicao impede resposta antiga de reaparecer', async () => {
  let resolveRequest;
  const harness = createHarness(() => new Promise(resolve => { resolveRequest = resolve; }));

  const pending = harness.run(`sendAIMessage('Pergunta antiga', false)`);
  const renderedBeforeClear = harness.rendered.length;
  harness.run('clearAIChat()');
  resolveRequest(jsonResponse(200, { reply: 'Resposta antiga' }));
  await pending;

  assert.equal(harness.rendered.length, renderedBeforeClear);
  assert.equal(harness.rendered.some(item => item.text === 'Resposta antiga'), false);
  assert.equal(harness.run('aiChatHistory.length'), 0);
  assert.match(harness.elements.aiChatMessages.innerHTML, /Conversa reiniciada/);
});
