const express = require("express");
const path = require("path");
require("dotenv").config();

const { db, initDB } = require("./src/database");
const gabaritos = require("./src/gabaritos");
const { avaliarResposta } = require("./src/avaliador");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ===== API Routes =====

// Registrar aluno
app.post("/api/alunos", async (req, res) => {
  try {
    const { nome, email } = req.body;
    if (!nome || !email)
      return res.status(400).json({ error: "Nome e email são obrigatórios." });

    // Check if email exists
    const existing = await db.execute({
      sql: "SELECT id, nome, email FROM alunos WHERE email = ?",
      args: [email],
    });

    if (existing.rows.length > 0) {
      return res.json({ aluno: existing.rows[0], message: "Bem-vindo de volta!" });
    }

    const result = await db.execute({
      sql: "INSERT INTO alunos (nome, email) VALUES (?, ?)",
      args: [nome, email],
    });

    const aluno = { id: Number(result.lastInsertRowid), nome, email };
    res.json({ aluno, message: "Cadastro realizado com sucesso!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao registrar aluno." });
  }
});

// Enviar resposta de exercício
app.post("/api/respostas", async (req, res) => {
  try {
    const { aluno_id, unidade, etapa, exercicio, resposta } = req.body;
    if (!aluno_id || !unidade || !etapa || !exercicio || !resposta)
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });

    // Avaliar a resposta
    const avaliacao = avaliarResposta(unidade, etapa, exercicio, resposta);

    // Salvar no banco
    await db.execute({
      sql: `INSERT INTO respostas (aluno_id, unidade, etapa, exercicio, resposta, nota, feedback)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        aluno_id,
        unidade,
        etapa,
        exercicio,
        resposta,
        avaliacao.nota,
        JSON.stringify(avaliacao),
      ],
    });

    res.json({ avaliacao });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao salvar resposta." });
  }
});

// Buscar respostas do aluno
app.get("/api/respostas/:aluno_id", async (req, res) => {
  try {
    const { aluno_id } = req.params;
    const { unidade } = req.query;

    let sql = "SELECT * FROM respostas WHERE aluno_id = ?";
    const args = [aluno_id];

    if (unidade) {
      sql += " AND unidade = ?";
      args.push(unidade);
    }

    sql += " ORDER BY enviado_em DESC";

    const result = await db.execute({ sql, args });
    res.json({ respostas: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar respostas." });
  }
});

// Buscar gabarito/exercícios
app.get("/api/exercicios/:unidade", (req, res) => {
  const unidade = parseInt(req.params.unidade);
  const gab = gabaritos[unidade];
  if (!gab) return res.status(404).json({ error: "Unidade não encontrada." });

  // Retornar sem o gabarito completo (apenas perguntas e conceitos)
  const exercicios = {};
  for (const [etapaKey, etapa] of Object.entries(gab.etapas)) {
    exercicios[etapaKey] = {
      titulo: etapa.titulo,
      exercicios: {},
    };
    for (const [exKey, ex] of Object.entries(etapa.exercicios)) {
      exercicios[etapaKey].exercicios[exKey] = {
        pergunta: ex.pergunta,
        conceitos: ex.conceitos,
      };
    }
  }

  res.json({ titulo: gab.titulo, etapas: exercicios });
});

// Estatísticas gerais
app.get("/api/estatisticas", async (req, res) => {
  try {
    const totalAlunos = await db.execute("SELECT COUNT(*) as total FROM alunos");
    const totalRespostas = await db.execute(
      "SELECT COUNT(*) as total FROM respostas"
    );
    const mediaNotas = await db.execute(
      "SELECT AVG(nota) as media FROM respostas"
    );
    const porUnidade = await db.execute(
      "SELECT unidade, COUNT(*) as total, AVG(nota) as media FROM respostas GROUP BY unidade ORDER BY unidade"
    );

    res.json({
      totalAlunos: totalAlunos.rows[0].total,
      totalRespostas: totalRespostas.rows[0].total,
      mediaGeral: Math.round((mediaNotas.rows[0].media || 0) * 10) / 10,
      porUnidade: porUnidade.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar estatísticas." });
  }
});

// Ranking dos alunos
app.get("/api/ranking", async (req, res) => {
  try {
    const result = await db.execute(
      `SELECT a.nome, a.email, AVG(r.nota) as media, COUNT(r.id) as total_respostas 
       FROM alunos a JOIN respostas r ON a.id = r.aluno_id 
       GROUP BY a.id ORDER BY media DESC LIMIT 20`
    );
    res.json({ ranking: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar ranking." });
  }
});

// SPA fallback
app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
async function start() {
  await initDB();
  app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
  });
}

start();
