const { createClient } = require('@libsql/client');
const { hashSenha } = require('./auth');
require('dotenv').config();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const USUARIOS_SEED = [
  { nome: 'Davi Antonino Nunes da Silva', email: 'professordavi85@gmail.com', senha: 'Ads@Admin#', role: 'admin' },
  { nome: 'Coordenadora Priscila', email: 'p.cunha@kroton.com.br', senha: 'Coord@Priscila#', role: 'coordenador' },
  { nome: 'Allan Casanova', email: 'allancasanova724@gmail.com', senha: 'allancasanova724@Ads2026', role: 'aluno' },
  { nome: 'Vitor Muniz', email: 'vitorlgmuniz@gmail.com', senha: 'vitorlgmuniz@Ads2026', role: 'aluno' },
  { nome: 'Eduardo Jordão', email: 'eduardosarnejordao@gmail.com', senha: 'eduardosarnejordao@Ads2026', role: 'aluno' },
  { nome: 'Daniel Gomes', email: 'danielgom0928@outlook.com', senha: 'danielgom0928@Ads2026', role: 'aluno' },
  { nome: 'Adrian Japa', email: 'Adrian.japa90@icloud.com', senha: 'Adrian.japa90@Ads2026', role: 'aluno' },
  { nome: 'Renan Lourenço Pedrosa', email: 'renanlourencopedrosa@gmail.com', senha: 'renanlourencopedrosa@Ads2026', role: 'aluno' },
];

async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'aluno',
      criado_em TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS respostas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      aluno_id INTEGER NOT NULL,
      unidade INTEGER NOT NULL,
      etapa INTEGER NOT NULL,
      exercicio INTEGER NOT NULL,
      resposta TEXT NOT NULL,
      nota REAL DEFAULT 0,
      feedback TEXT DEFAULT '',
      tentativa INTEGER DEFAULT 1,
      enviado_em TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (aluno_id) REFERENCES usuarios(id)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_respostas_aluno ON respostas(aluno_id)`,
    `CREATE INDEX IF NOT EXISTS idx_respostas_unidade ON respostas(unidade, etapa, exercicio)`,
  ]);

  // Seed users
  for (const u of USUARIOS_SEED) {
    const exists = await db.execute({ sql: 'SELECT id FROM usuarios WHERE email = ?', args: [u.email] });
    if (exists.rows.length === 0) {
      const hash = await hashSenha(u.senha);
      await db.execute({
        sql: 'INSERT INTO usuarios (nome, email, senha_hash, role) VALUES (?, ?, ?, ?)',
        args: [u.nome, u.email, hash, u.role],
      });
      console.log(`  ✅ Usuário criado: ${u.email} (${u.role})`);
    }
  }

  console.log('✅ Banco de dados inicializado com sucesso!');
}

module.exports = { db, initDB };
