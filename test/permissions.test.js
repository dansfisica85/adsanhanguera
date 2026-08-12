const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canViewAllProjects,
  canViewProject,
  canCreateProject,
  canUpdateProject,
  canDeleteProject,
  canCreateResponse,
  canMutateResponse,
  isPlatformOwner,
} = require('../src/permissions');

const users = {
  admin: { id: 1, email: 'professordavi85@gmail.com', role: 'admin' },
  coordenador: { id: 2, role: 'coordenador' },
  aluno: { id: 3, role: 'aluno' },
  especial: { id: 4, role: 'especial' },
  desconhecido: { id: 5, role: 'desconhecido' },
};

test('aluna especial visualiza todos os projetos e gerencia apenas os proprios', () => {
  assert.equal(canViewAllProjects(users.especial), true);
  assert.equal(canViewProject(users.especial, users.aluno.id), true);
  assert.equal(canCreateProject(users.especial), true);
  assert.equal(canUpdateProject(users.especial, users.especial.id), true);
  assert.equal(canDeleteProject(users.especial, users.especial.id), true);
  assert.equal(canUpdateProject(users.especial, users.aluno.id), false);
  assert.equal(canDeleteProject(users.especial, users.aluno.id), false);
});

test('aluna especial nao cria, corrige nem exclui respostas', () => {
  assert.equal(canCreateResponse(users.especial), false);
  assert.equal(canMutateResponse(users.especial, users.especial.id), false);
  assert.equal(canMutateResponse(users.especial, users.aluno.id), false);
});

test('administrador preserva acesso maximo', () => {
  assert.equal(isPlatformOwner(users.admin), true);
  assert.equal(canViewAllProjects(users.admin), true);
  assert.equal(canUpdateProject(users.admin, users.aluno.id), true);
  assert.equal(canDeleteProject(users.admin, users.aluno.id), true);
  assert.equal(canCreateResponse(users.admin), true);
  assert.equal(canMutateResponse(users.admin, users.aluno.id), true);
});

test('outro administrador nao e confundido com o criador da plataforma', () => {
  assert.equal(isPlatformOwner({ id: 9, email: 'outro-admin@example.com', role: 'admin' }), false);
});

test('coordenador permanece somente leitura', () => {
  assert.equal(canViewAllProjects(users.coordenador), true);
  assert.equal(canCreateProject(users.coordenador), false);
  assert.equal(canUpdateProject(users.coordenador, users.aluno.id), false);
  assert.equal(canDeleteProject(users.coordenador, users.aluno.id), false);
  assert.equal(canCreateResponse(users.coordenador), false);
  assert.equal(canMutateResponse(users.coordenador, users.aluno.id), false);
});

test('aluno gerencia apenas os proprios dados', () => {
  assert.equal(canViewAllProjects(users.aluno), false);
  assert.equal(canViewProject(users.aluno, users.aluno.id), true);
  assert.equal(canViewProject(users.aluno, users.especial.id), false);
  assert.equal(canUpdateProject(users.aluno, users.aluno.id), true);
  assert.equal(canUpdateProject(users.aluno, users.especial.id), false);
  assert.equal(canMutateResponse(users.aluno, users.aluno.id), true);
  assert.equal(canMutateResponse(users.aluno, users.especial.id), false);
});

test('papel desconhecido falha fechado em todas as mutacoes', () => {
  assert.equal(canViewAllProjects(users.desconhecido), false);
  assert.equal(canViewProject(users.desconhecido, users.desconhecido.id), false);
  assert.equal(canCreateProject(users.desconhecido), false);
  assert.equal(canUpdateProject(users.desconhecido, users.desconhecido.id), false);
  assert.equal(canDeleteProject(users.desconhecido, users.desconhecido.id), false);
  assert.equal(canCreateResponse(users.desconhecido), false);
  assert.equal(canMutateResponse(users.desconhecido, users.desconhecido.id), false);
});
