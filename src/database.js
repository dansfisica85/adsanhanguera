const { createClient } = require("@libsql/client");
require("dotenv").config();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS alunos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
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
      enviado_em TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (aluno_id) REFERENCES alunos(id)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_respostas_aluno ON respostas(aluno_id)`,
    `CREATE INDEX IF NOT EXISTS idx_respostas_unidade ON respostas(unidade, etapa, exercicio)`,
  ]);
  console.log("✅ Banco de dados inicializado com sucesso!");
}

module.exports = { db, initDB };
