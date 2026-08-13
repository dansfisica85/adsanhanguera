const test = require('node:test');
const assert = require('node:assert/strict');

process.env.JWT_SECRET = 'test-only-secret-with-at-least-32-characters';

const projects = [
  { id: 10, aluno_id: 3, nome: 'Projeto de outro aluno', html: '<h1>Original</h1>', css: '', js: '', py: '', assets: '{}', visto: 0 },
  { id: 11, aluno_id: 4, nome: 'Projeto da Isabelly', html: '<h1>Isabelly</h1>', css: '', js: '', py: '', assets: '{}', visto: 0 },
];
const responses = [
  { id: 30, aluno_id: 3, unidade: 1, etapa: 1, exercicio: 1, resposta: 'Resposta original' },
];
const users = [
  { id: 1, nome: 'Davi', email: 'professordavi85@gmail.com', role: 'admin' },
  { id: 3, nome: 'Outro Aluno', email: 'aluno@example.com', role: 'aluno' },
  { id: 4, nome: 'Isabelly Benetelli Geron', email: 'IsabellyBenetelliGeron', role: 'especial' },
  { id: 5, nome: 'Outro Administrador', email: 'outro-admin@example.com', role: 'admin' },
];
let nextProjectId = 100;
let nextUserId = 200;

function rows(items) {
  return { rows: items };
}

async function fakeDbExecute(sqlOrObject, positionalArgs) {
  const statement = typeof sqlOrObject === 'string'
    ? { sql: sqlOrObject, args: positionalArgs || [] }
    : sqlOrObject;
  const sql = statement.sql.replace(/\s+/g, ' ').trim();
  const args = statement.args || [];

  if (/^SELECT p\.\*, u\.nome as autor_nome FROM projetos_codigo p JOIN usuarios u ON p\.aluno_id = u\.id WHERE p\.id = \?/i.test(sql)) {
    const project = projects.find(item => item.id === Number(args[0]));
    if (!project) return rows([]);
    const author = users.find(user => user.id === Number(project.aluno_id));
    return rows([{ ...project, autor_nome: author ? author.nome : '' }]);
  }

  if (/^SELECT p\.\*, u\.nome as autor_nome FROM projetos_codigo p JOIN usuarios u ON p\.aluno_id = u\.id ORDER BY/i.test(sql)) {
    return rows(projects.map(project => ({
      ...project,
      autor_nome: (users.find(user => user.id === Number(project.aluno_id)) || {}).nome || '',
    })));
  }

  if (/^SELECT p\.\*, u\.nome as autor_nome FROM projetos_codigo p JOIN usuarios u ON p\.aluno_id = u\.id WHERE p\.aluno_id = \?/i.test(sql)) {
    return rows(projects
      .filter(project => Number(project.aluno_id) === Number(args[0]))
      .map(project => ({
        ...project,
        autor_nome: (users.find(user => user.id === Number(project.aluno_id)) || {}).nome || '',
      })));
  }

  if (/^SELECT \* FROM projetos_codigo WHERE id = \?/i.test(sql)) {
    const project = projects.find(item => item.id === Number(args[0]));
    return rows(project ? [{ ...project }] : []);
  }

  if (/^INSERT INTO projetos_codigo/i.test(sql)) {
    const project = {
      id: nextProjectId++,
      aluno_id: Number(args[0]),
      nome: args[1],
      html: args[2],
      css: args[3],
      js: args[4],
      py: args[5],
      assets: args[6],
      visto: 0,
    };
    projects.push(project);
    return { rows: [], lastInsertRowid: project.id };
  }

  if (/^UPDATE projetos_codigo SET nome = \?/i.test(sql)) {
    const project = projects.find(item => item.id === Number(args[6]));
    Object.assign(project, { nome: args[0], html: args[1], css: args[2], js: args[3], py: args[4], assets: args[5] });
    return rows([]);
  }

  if (/^DELETE FROM projetos_codigo WHERE id = \?/i.test(sql)) {
    const index = projects.findIndex(item => item.id === Number(args[0]));
    if (index >= 0) projects.splice(index, 1);
    return rows([]);
  }

  if (/^SELECT \* FROM respostas WHERE id = \?/i.test(sql)) {
    const response = responses.find(item => item.id === Number(args[0]));
    return rows(response ? [{ ...response }] : []);
  }

  if (/^SELECT id FROM usuarios WHERE lower\(email\) = lower\(\?\)/i.test(sql)) {
    const user = users.find(item => item.email.toLowerCase() === String(args[0]).toLowerCase());
    return rows(user ? [{ id: user.id }] : []);
  }

  if (/^INSERT INTO usuarios \(nome, email, senha_hash, role\) VALUES/i.test(sql)) {
    const user = { id: nextUserId++, nome: args[0], email: args[1], senha_hash: args[2], role: args[3] };
    users.push(user);
    return { rows: [], lastInsertRowid: user.id };
  }

  if (/^SELECT id, email, role FROM usuarios WHERE id = \?/i.test(sql)) {
    const user = users.find(item => item.id === Number(args[0]));
    return rows(user ? [{ id: user.id, email: user.email, role: user.role }] : []);
  }

  if (/^SELECT u\.id, u\.nome, u\.role, COUNT\(p\.id\) as total_projetos/i.test(sql)) {
    return rows(users
      .filter(user => ['aluno', 'especial'].includes(user.role) && Number(user.id) !== Number(args[0]))
      .map(user => ({
        id: user.id,
        nome: user.nome,
        role: user.role,
        total_projetos: projects.filter(project => Number(project.aluno_id) === Number(user.id)).length,
      })));
  }

  throw new Error(`SQL não simulada no teste: ${sql}`);
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

const app = require('../server');
const { gerarToken } = require('../src/auth');

function authHeaders(user) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${gerarToken(user)}`,
  };
}

test('rotas aplicam as permissões da Aluna Especial sem confiar na interface', async (t) => {
  await new Promise(resolve => setImmediate(resolve));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const especial = users.find(user => user.role === 'especial');
  const specialHeaders = authHeaders(especial);

  const allProjects = await fetch(`${baseUrl}/api/projetos`, { headers: specialHeaders });
  assert.equal(allProjects.status, 200);
  assert.equal((await allProjects.json()).projetos.length, 2);

  const students = await fetch(`${baseUrl}/api/projetos-alunos`, { headers: specialHeaders });
  assert.equal(students.status, 200);
  const studentList = (await students.json()).alunos;
  assert.equal(studentList.some(user => user.id === especial.id), false);
  assert.equal(studentList.some(user => user.id === 3), true);

  const admin = users.find(user => user.role === 'admin');
  const adminStudents = await fetch(`${baseUrl}/api/projetos-alunos`, { headers: authHeaders(admin) });
  assert.equal(adminStudents.status, 200);
  assert.equal((await adminStudents.json()).alunos.some(user => user.id === especial.id), true);

  const specialProjectsForAdmin = await fetch(`${baseUrl}/api/projetos-aluno/${especial.id}`, { headers: authHeaders(admin) });
  assert.equal(specialProjectsForAdmin.status, 200);
  assert.equal((await specialProjectsForAdmin.json()).projetos.some(project => project.id === 11), true);

  const foreignBefore = projects.find(project => project.id === 10).html;
  const forbiddenUpdate = await fetch(`${baseUrl}/api/projetos/10`, {
    method: 'PUT',
    headers: specialHeaders,
    body: JSON.stringify({ nome: 'Tentativa indevida', html: '<h1>Alterado</h1>' }),
  });
  assert.equal(forbiddenUpdate.status, 403);
  assert.equal(projects.find(project => project.id === 10).html, foreignBefore);

  const forbiddenDelete = await fetch(`${baseUrl}/api/projetos/10`, { method: 'DELETE', headers: specialHeaders });
  assert.equal(forbiddenDelete.status, 403);
  assert.ok(projects.some(project => project.id === 10));

  const forbiddenResponseCreate = await fetch(`${baseUrl}/api/respostas`, {
    method: 'POST',
    headers: specialHeaders,
    body: JSON.stringify({ unidade: 1, etapa: 1, exercicio: 1, resposta: 'Tentativa' }),
  });
  assert.equal(forbiddenResponseCreate.status, 403);

  const forbiddenResponseUpdate = await fetch(`${baseUrl}/api/respostas/30`, {
    method: 'PUT',
    headers: specialHeaders,
    body: JSON.stringify({ resposta: 'Tentativa indevida' }),
  });
  assert.equal(forbiddenResponseUpdate.status, 403);
  assert.equal(responses[0].resposta, 'Resposta original');

  const forbiddenResponseDelete = await fetch(`${baseUrl}/api/respostas/30`, {
    method: 'DELETE',
    headers: specialHeaders,
  });
  assert.equal(forbiddenResponseDelete.status, 403);
  assert.equal(responses[0].resposta, 'Resposta original');

  const forbiddenAdmin = await fetch(`${baseUrl}/api/admin/estatisticas`, { headers: specialHeaders });
  assert.equal(forbiddenAdmin.status, 403);

  const forbiddenUserDelete = await fetch(`${baseUrl}/api/admin/alunos/3`, { method: 'DELETE', headers: specialHeaders });
  assert.equal(forbiddenUserDelete.status, 403);

  const forbiddenSeen = await fetch(`${baseUrl}/api/projetos/10/visto`, { method: 'PUT', headers: specialHeaders });
  assert.equal(forbiddenSeen.status, 403);

  const created = await fetch(`${baseUrl}/api/projetos`, {
    method: 'POST',
    headers: specialHeaders,
    body: JSON.stringify({ aluno_id: 3, nome: 'Projeto próprio', html: '<h1>Isabelly</h1>' }),
  });
  assert.equal(created.status, 200);
  const createdId = (await created.json()).id;
  assert.equal(projects.find(project => project.id === createdId).aluno_id, especial.id);

  const ownUpdate = await fetch(`${baseUrl}/api/projetos/${createdId}`, {
    method: 'PUT',
    headers: specialHeaders,
    body: JSON.stringify({ nome: 'Projeto próprio editado', html: '<h1>Editado</h1>' }),
  });
  assert.equal(ownUpdate.status, 200);
  assert.equal(projects.find(project => project.id === createdId).nome, 'Projeto próprio editado');

  const ownDelete = await fetch(`${baseUrl}/api/projetos/${createdId}`, { method: 'DELETE', headers: specialHeaders });
  assert.equal(ownDelete.status, 200);
  assert.equal(projects.some(project => project.id === createdId), false);

  const unknown = { id: 99, nome: 'Desconhecido', email: 'unknown@example.com', role: 'desconhecido' };
  const unknownCreate = await fetch(`${baseUrl}/api/projetos`, {
    method: 'POST',
    headers: authHeaders(unknown),
    body: JSON.stringify({ nome: 'Não deve criar' }),
  });
  assert.equal(unknownCreate.status, 403);

  const createdByOwner = await fetch(`${baseUrl}/api/admin/usuarios`, {
    method: 'POST',
    headers: authHeaders(admin),
    body: JSON.stringify({
      nome: 'Conta Especial de Teste',
      email: 'conta-especial-teste',
      senha: 'senha-teste-segura',
      role: 'especial',
    }),
  });
  assert.equal(createdByOwner.status, 201);
  const createdUser = (await createdByOwner.json()).user;
  assert.equal(createdUser.role, 'especial');
  assert.equal('senha_hash' in createdUser, false);

  const otherAdmin = users.find(user => user.id === 5);
  const specialCreationByOtherAdmin = await fetch(`${baseUrl}/api/admin/usuarios`, {
    method: 'POST',
    headers: authHeaders(otherAdmin),
    body: JSON.stringify({
      nome: 'Outra Conta Especial',
      email: 'outra-conta-especial',
      senha: 'senha-teste-segura',
      role: 'especial',
    }),
  });
  assert.equal(specialCreationByOtherAdmin.status, 403);

  const protectedOwnerDelete = await fetch(`${baseUrl}/api/admin/alunos/${admin.id}`, {
    method: 'DELETE',
    headers: authHeaders(otherAdmin),
  });
  assert.equal(protectedOwnerDelete.status, 403);
  assert.ok(users.some(user => user.id === admin.id));
});
