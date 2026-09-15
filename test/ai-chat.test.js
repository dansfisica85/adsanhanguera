const test = require('node:test');
const assert = require('node:assert/strict');

process.env.JWT_SECRET = 'test-only-secret-with-at-least-32-characters';

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const user = {
  id: 42,
  nome: 'Aluno de Teste',
  email: 'aluno-ia@example.com',
  role: 'aluno',
  token_version: 0,
};

async function fakeDbExecute(sqlOrObject, positionalArgs) {
  const statement = typeof sqlOrObject === 'string'
    ? { sql: sqlOrObject, args: positionalArgs || [] }
    : sqlOrObject;
  const sql = statement.sql.replace(/\s+/g, ' ').trim();
  const args = statement.args || [];

  if (/^SELECT id, nome, email, role, token_version FROM usuarios WHERE id = \?/i.test(sql)) {
    return { rows: Number(args[0]) === user.id ? [{ ...user }] : [] };
  }

  throw new Error(`SQL não simulada no teste da IA: ${sql}`);
}

const databasePath = require.resolve('../src/database');
require.cache[databasePath] = {
  id: databasePath,
  filename: databasePath,
  loaded: true,
  exports: {
    dbExecute: fakeDbExecute,
    dbBatch: async () => [],
    initDB: async () => undefined,
  },
};

const nativeFetch = global.fetch.bind(globalThis);
const nativeAbortTimeout = AbortSignal.timeout;
const originalGroqApiKey = process.env.GROQ_API_KEY;
const originalGroqModel = process.env.GROQ_MODEL;

let groqHandler;
let groqCalls = [];
let abortTimeoutCalls = [];

global.fetch = async (input, init = {}) => {
  const url = typeof input === 'string'
    ? input
    : input instanceof URL
      ? input.href
      : input.url;

  if (url !== GROQ_URL) return nativeFetch(input, init);

  const parsedBody = init.body ? JSON.parse(init.body) : undefined;
  groqCalls.push({ url, init, body: parsedBody });
  return groqHandler({ url, init, body: parsedBody });
};

AbortSignal.timeout = (milliseconds) => {
  abortTimeoutCalls.push(milliseconds);
  return nativeAbortTimeout(milliseconds);
};

const app = require('../server');
const { gerarToken } = require('../src/auth');

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${gerarToken(user)}`,
  };
}

test('POST /api/ai/chat integra o backend Groq com validação e erros seguros', async (t) => {
  await new Promise(resolve => setImmediate(resolve));

  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    global.fetch = nativeFetch;
    AbortSignal.timeout = nativeAbortTimeout;
    restoreEnv('GROQ_API_KEY', originalGroqApiKey);
    restoreEnv('GROQ_MODEL', originalGroqModel);
    await new Promise(resolve => server.close(resolve));
  });

  function resetGroq(handler = () => jsonResponse({
    choices: [{ message: { content: 'Resposta didática da IA.' } }],
  })) {
    groqCalls = [];
    abortTimeoutCalls = [];
    groqHandler = handler;
  }

  async function post(body, headers = authHeaders()) {
    return nativeFetch(`${baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  }

  await t.test('usa GPT-OSS 120B por padrão, limita o histórico e inclui contexto truncado', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    delete process.env.GROQ_MODEL;
    resetGroq();

    const messages = Array.from({ length: 24 }, (_, index) => ({
      role: index % 2 === 0 ? 'user' : 'assistant',
      content: `mensagem-${index}`,
      extra: 'não deve chegar ao provedor',
    }));
    const codigoContexto = 'x'.repeat(8500);

    const response = await post({ messages, includeCode: true, codigoContexto });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { reply: 'Resposta didática da IA.' });
    assert.equal(groqCalls.length, 1);

    const call = groqCalls[0];
    assert.equal(call.url, GROQ_URL);
    assert.equal(call.init.method, 'POST');
    assert.equal(call.init.headers['Content-Type'], 'application/json');
    assert.equal(call.init.headers.Authorization, 'Bearer test-groq-key');
    assert.ok(call.init.signal instanceof AbortSignal);
    assert.deepEqual(abortTimeoutCalls, [25000]);

    assert.equal(call.body.model, 'openai/gpt-oss-120b');
    assert.equal(call.body.temperature, 0.7);
    assert.equal(call.body.max_completion_tokens, 4096);
    assert.equal(call.body.stream, false);
    assert.equal(call.body.reasoning_effort, 'low');
    assert.equal(call.body.include_reasoning, false);
    assert.equal('max_tokens' in call.body, false);
    assert.equal('reasoning_format' in call.body, false);

    assert.equal(call.body.messages.length, 22);
    assert.equal(call.body.messages[0].role, 'system');
    assert.match(call.body.messages[0].content, /ADS-AI/);
    assert.equal(call.body.messages[1].role, 'system');
    assert.ok(call.body.messages[1].content.includes('x'.repeat(8000)));
    assert.equal(call.body.messages[1].content.includes('x'.repeat(8001)), false);
    assert.deepEqual(call.body.messages[2], { role: 'user', content: 'mensagem-4' });
    assert.deepEqual(call.body.messages.at(-1), { role: 'assistant', content: 'mensagem-23' });
  });

  await t.test('respeita GROQ_MODEL e só envia parâmetros de raciocínio para GPT-OSS', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    process.env.GROQ_MODEL = '  qwen/qwen3.6-27b  ';
    resetGroq();

    const response = await post({ messages: [{ role: 'user', content: 'Explique filas.' }] });
    assert.equal(response.status, 200);
    assert.equal(groqCalls.length, 1);
    assert.equal(groqCalls[0].body.model, 'qwen/qwen3.6-27b');
    assert.equal('reasoning_effort' in groqCalls[0].body, false);
    assert.equal('include_reasoning' in groqCalls[0].body, false);
  });

  await t.test('recusa acesso sem sessão válida antes de chamar a Groq', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    resetGroq();

    const missingToken = await post(
      { messages: [{ role: 'user', content: 'Olá' }] },
      { 'Content-Type': 'application/json' }
    );
    assert.equal(missingToken.status, 401);
    assert.deepEqual(await missingToken.json(), { error: 'Token não fornecido.' });

    const invalidToken = await post(
      { messages: [{ role: 'user', content: 'Olá' }] },
      { 'Content-Type': 'application/json', Authorization: 'Bearer token-invalido' }
    );
    assert.equal(invalidToken.status, 401);
    assert.deepEqual(await invalidToken.json(), { error: 'Token inválido ou expirado.' });
    assert.equal(groqCalls.length, 0);
  });

  await t.test('retorna 503 quando GROQ_API_KEY está ausente ou vazia', async () => {
    process.env.GROQ_API_KEY = '   ';
    delete process.env.GROQ_MODEL;
    resetGroq();

    const response = await post({ messages: [{ role: 'user', content: 'Olá' }] });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: 'Serviço de IA não configurado. Defina GROQ_API_KEY nas variáveis de ambiente.',
    });
    assert.equal(groqCalls.length, 0);
  });

  await t.test('valida a coleção, os papéis e o conteúdo das mensagens', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    resetGroq();

    const requiredCases = [{}, { messages: [] }, { messages: 'não é lista' }];
    for (const body of requiredCases) {
      const response = await post(body);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: 'messages é obrigatório.' });
    }

    const invalidCases = [
      { messages: [null] },
      { messages: [{ role: 'system', content: 'Não permitido' }] },
      { messages: [{ role: 'user', content: '   ' }] },
      { messages: [{ role: 'assistant', content: 123 }] },
    ];
    for (const body of invalidCases) {
      const response = await post(body);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: 'Envie mensagens de texto válidas.' });
    }
    assert.equal(groqCalls.length, 0);
  });

  await t.test('mapeia limite, credencial, modelo indisponível e erro genérico da Groq', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    delete process.env.GROQ_MODEL;

    const cases = [
      {
        upstreamStatus: 404,
        upstreamBody: { error: { code: 'model_not_found' } },
        expectedStatus: 503,
        expectedError: 'O modelo de IA está indisponível para esta conta. O administrador precisa conferir a configuração do serviço.',
      },
      {
        upstreamStatus: 429,
        upstreamBody: { error: { code: 'rate_limit_exceeded' } },
        expectedStatus: 429,
        expectedError: 'O limite de uso da IA foi atingido. Aguarde um pouco e tente novamente.',
      },
      {
        upstreamStatus: 401,
        upstreamBody: { error: { code: 'invalid_api_key' } },
        expectedStatus: 503,
        expectedError: 'A credencial do serviço de IA não foi aceita. O administrador precisa conferir a configuração do serviço.',
      },
      {
        upstreamStatus: 400,
        upstreamBody: { error: { code: 'model_decommissioned' } },
        expectedStatus: 503,
        expectedError: 'O modelo de IA está indisponível para esta conta. O administrador precisa conferir a configuração do serviço.',
      },
      {
        upstreamStatus: 403,
        upstreamBody: { error: { code: 'model_permission_blocked_project' } },
        expectedStatus: 503,
        expectedError: 'O modelo de IA está indisponível para esta conta. O administrador precisa conferir a configuração do serviço.',
      },
      {
        upstreamStatus: 500,
        upstreamBody: { error: { code: 'internal_error' } },
        expectedStatus: 502,
        expectedError: 'Erro ao contatar IA. Tente novamente em instantes.',
      },
    ];

    for (const current of cases) {
      resetGroq(() => jsonResponse(current.upstreamBody, current.upstreamStatus));
      const response = await post({ messages: [{ role: 'user', content: 'Teste de erro' }] });
      assert.equal(response.status, current.expectedStatus);
      assert.deepEqual(await response.json(), { error: current.expectedError });
      assert.equal(groqCalls.length, 1);
    }
  });

  await t.test('rejeita uma conclusão bem-sucedida sem texto', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    resetGroq(() => jsonResponse({ choices: [{ message: { content: '   ' } }] }));

    const response = await post({ messages: [{ role: 'user', content: 'Responda' }] });
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), {
      error: 'A IA não retornou uma resposta. Tente novamente com uma pergunta mais curta.',
    });
  });

  await t.test('mapeia timeout do provedor para 504', async () => {
    process.env.GROQ_API_KEY = 'test-groq-key';
    resetGroq(() => {
      const error = new Error('simulação de timeout');
      error.name = 'TimeoutError';
      throw error;
    });

    const response = await post({ messages: [{ role: 'user', content: 'Demora?' }] });
    assert.equal(response.status, 504);
    assert.deepEqual(await response.json(), {
      error: 'A IA demorou para responder. Tente novamente em instantes.',
    });
    assert.deepEqual(abortTimeoutCalls, [25000]);
  });
});
