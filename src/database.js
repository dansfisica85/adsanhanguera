const { createClient } = require('@libsql/client/http');
const { hashSenha } = require('./auth');
require('dotenv').config();

let db = null;

function criarClienteTurso() {
  if (!process.env.TURSO_DATABASE_URL) {
    console.error('⚠️ TURSO_DATABASE_URL não definida! Verifique as variáveis de ambiente.');
    return null;
  }
  try {
    return createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN,
    });
  } catch (err) {
    console.error('⚠️ Erro ao criar cliente Turso:', err.message);
    return null;
  }
}

db = criarClienteTurso();

// Utilitário de delay para retry
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Executa uma operação no DB com retry automático em caso de erro transitório
async function dbExecute(sqlOrObj, args) {
  if (!db) {
    db = criarClienteTurso();
    if (!db) throw new Error('Cliente de banco de dados não inicializado. Verifique TURSO_DATABASE_URL e TURSO_AUTH_TOKEN.');
  }

  const maxRetries = 3;
  const baseDelay = 1000; // 1 segundo

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      if (typeof sqlOrObj === 'string') {
        return await db.execute(args ? { sql: sqlOrObj, args } : sqlOrObj);
      }
      return await db.execute(sqlOrObj);
    } catch (err) {
      const isTransient = /ECONNRESET|ETIMEDOUT|ENOTFOUND|ECONNREFUSED|fetch failed|network|socket hang up|503|502/i.test(err.message);
      if (isTransient && attempt < maxRetries) {
        const waitMs = baseDelay * Math.pow(2, attempt - 1); // backoff exponencial
        console.warn(`⚠️ Tentativa ${attempt}/${maxRetries} falhou (${err.message}). Retentando em ${waitMs}ms...`);
        // Recria o cliente para limpar conexão quebrada
        db = criarClienteTurso();
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
}

// Executa batch com retry automático
async function dbBatch(statements) {
  if (!db) {
    db = criarClienteTurso();
    if (!db) throw new Error('Cliente de banco de dados não inicializado. Verifique TURSO_DATABASE_URL e TURSO_AUTH_TOKEN.');
  }

  const maxRetries = 3;
  const baseDelay = 1000;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await db.batch(statements);
    } catch (err) {
      const isTransient = /ECONNRESET|ETIMEDOUT|ENOTFOUND|ECONNREFUSED|fetch failed|network|socket hang up|503|502/i.test(err.message);
      if (isTransient && attempt < maxRetries) {
        const waitMs = baseDelay * Math.pow(2, attempt - 1);
        console.warn(`⚠️ Batch tentativa ${attempt}/${maxRetries} falhou (${err.message}). Retentando em ${waitMs}ms...`);
        db = criarClienteTurso();
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
}

const USUARIOS_SEED = [
  { nome: 'Davi Antonino Nunes da Silva', email: 'professordavi85@gmail.com', senha: 'Ads@Admin#', role: 'admin' },
  { nome: 'Coordenadora Priscila', email: 'p.cunha@kroton.com.br', senha: 'Coord@Priscila#', role: 'coordenador' },
  { nome: 'Allan Casanova', email: 'allancasanova724@gmail.com', senha: 'allancasanova724@Ads2026', role: 'aluno' },
  { nome: 'Vitor Muniz', email: 'vitorlgmuniz@gmail.com', senha: 'vitorlgmuniz@Ads2026', role: 'aluno' },
  { nome: 'Eduardo Jordão', email: 'eduardosarnejordao@gmail.com', senha: 'eduardosarnejordao@Ads2026', role: 'aluno' },
  { nome: 'Daniel Gomes', email: 'danielgom0928@outlook.com', senha: 'danielgom0928@Ads2026', role: 'aluno' },
  { nome: 'Adrian Japa', email: 'Adrian.japa90@icloud.com', senha: 'Adrian.japa90@Ads2026', role: 'aluno' },
  { nome: 'Renan Lourenço Pedrosa', email: 'renanlourencopedrosa@gmail.com', senha: 'renanlourencopedrosa@Ads2026', role: 'aluno' },
  { nome: 'Pedro Henrique', email: 'pedrohenrique0477@gmail.com', senha: 'pedrohenrique0477@Ads2026', role: 'aluno' },
];

async function initDB() {
  if (!db) {
    db = criarClienteTurso();
    if (!db) throw new Error('Cliente de banco de dados não inicializado. Verifique TURSO_DATABASE_URL e TURSO_AUTH_TOKEN.');
  }

  await dbBatch([
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
    const exists = await dbExecute({ sql: 'SELECT id FROM usuarios WHERE email = ?', args: [u.email] });
    if (exists.rows.length === 0) {
      const hash = await hashSenha(u.senha);
      await dbExecute({
        sql: 'INSERT INTO usuarios (nome, email, senha_hash, role) VALUES (?, ?, ?, ?)',
        args: [u.nome, u.email, hash, u.role],
      });
      console.log(`  ✅ Usuário criado: ${u.email} (${u.role})`);
    }
  }

  // Migration: adicionar coluna tentativa se não existir
  try {
    await dbExecute(`ALTER TABLE respostas ADD COLUMN tentativa INTEGER DEFAULT 1`);
    console.log('  ✅ Coluna tentativa adicionada.');
  } catch (e) {
    // Coluna já existe, ignorar
  }

  console.log('✅ Banco de dados inicializado com sucesso!');
}

// initDB com retry em caso de falha transitória na inicialização
async function initDBWithRetry(maxRetries = 5) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await initDB();
      return; // sucesso
    } catch (err) {
      const isTransient = /ECONNRESET|ETIMEDOUT|ENOTFOUND|ECONNREFUSED|fetch failed|network|socket hang up|503|502/i.test(err.message);
      if (isTransient && attempt < maxRetries) {
        const waitMs = 2000 * Math.pow(2, attempt - 1); // 2s, 4s, 8s, 16s, 32s
        console.warn(`⚠️ initDB tentativa ${attempt}/${maxRetries} falhou (${err.message}). Retentando em ${waitMs / 1000}s...`);
        db = criarClienteTurso();
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
}

module.exports = { dbExecute, dbBatch, initDB: initDBWithRetry };
