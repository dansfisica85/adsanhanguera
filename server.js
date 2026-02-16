const express = require('express');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { db, initDB } = require('./src/database');
const gabaritos = require('./src/gabaritos');
const { avaliarResposta } = require('./src/avaliador');
const { verificarSenha, gerarToken, middlewareAuth, middlewareRole } = require('./src/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Inicialização do banco (precisa estar antes do middleware que usa dbInit)
let dbReady = false;
let dbInitError = null;

const dbInit = initDB()
  .then(() => {
    dbReady = true;
    console.log('✅ DB pronto para receber requests.');
  })
  .catch(err => {
    dbInitError = err;
    console.error('❌ Erro fatal na inicialização do DB:', err.message || err);
  });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health check — registrado ANTES do middleware de DB para funcionar mesmo sem banco
app.get('/api/health', (req, res) => {
  res.json({
    status: dbReady ? 'ok' : 'db_unavailable',
    dbReady,
    dbError: dbInitError ? dbInitError.message : null,
    timestamp: new Date().toISOString(),
  });
});

// Middleware para garantir que o DB está pronto antes de processar requests de API
app.use('/api', async (req, res, next) => {
  try {
    if (!dbReady) {
      await dbInit;
    }
    if (!dbReady) {
      return res.status(503).json({
        error: dbInitError
          ? `Banco de dados indisponível: ${dbInitError.message}`
          : 'Banco de dados ainda não está pronto. Tente novamente em instantes.'
      });
    }
    next();
  } catch (err) {
    console.error('Erro no middleware de DB:', err);
    res.status(503).json({ error: 'Banco de dados indisponível.' });
  }
});

// ===== AUTH ROUTES =====

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

    const result = await db.execute({ sql: 'SELECT * FROM usuarios WHERE email = ?', args: [email] });
    if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const user = result.rows[0];
    const senhaOk = await verificarSenha(senha, user.senha_hash);
    if (!senhaOk) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const token = gerarToken({ id: user.id, email: user.email, role: user.role, nome: user.nome });
    res.json({
      token,
      user: { id: user.id, nome: user.nome, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// Verificar token
app.get('/api/auth/me', middlewareAuth, async (req, res) => {
  try {
    const result = await db.execute({ sql: 'SELECT id, nome, email, role FROM usuarios WHERE id = ?', args: [req.user.id] });
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ===== EXERCÍCIOS =====

// Buscar exercícios (sem gabarito)
app.get('/api/exercicios/:unidade', (req, res) => {
  const unidade = parseInt(req.params.unidade);
  const gab = gabaritos[unidade];
  if (!gab) return res.status(404).json({ error: 'Unidade não encontrada.' });

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

// ===== RESPOSTAS (CRUD) =====

// Criar resposta
app.post('/api/respostas', middlewareAuth, async (req, res) => {
  try {
    const { unidade, etapa, exercicio, resposta } = req.body;
    if (!unidade || !etapa || !exercicio || !resposta)
      return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });

    const aluno_id = req.user.id;

    // Calcular tentativa
    const tentResult = await db.execute({
      sql: 'SELECT COUNT(*) as cnt FROM respostas WHERE aluno_id = ? AND unidade = ? AND etapa = ? AND exercicio = ?',
      args: [aluno_id, unidade, etapa, exercicio],
    });
    const tentativa = Number(tentResult.rows[0].cnt) + 1;

    // Avaliar a resposta
    const avaliacao = avaliarResposta(unidade, etapa, exercicio, resposta);

    await db.execute({
      sql: `INSERT INTO respostas (aluno_id, unidade, etapa, exercicio, resposta, nota, feedback, tentativa)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [aluno_id, unidade, etapa, exercicio, resposta, avaliacao.nota, JSON.stringify(avaliacao), tentativa],
    });

    res.json({ avaliacao, tentativa });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar resposta.' });
  }
});

// Listar respostas do usuário autenticado
app.get('/api/respostas', middlewareAuth, async (req, res) => {
  try {
    const { unidade } = req.query;
    let sql = 'SELECT * FROM respostas WHERE aluno_id = ?';
    const args = [req.user.id];

    if (unidade) {
      sql += ' AND unidade = ?';
      args.push(unidade);
    }
    sql += ' ORDER BY enviado_em DESC';

    const result = await db.execute({ sql, args });
    res.json({ respostas: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar respostas.' });
  }
});

// Atualizar resposta (só aluno dono, admin pode tudo)
app.put('/api/respostas/:id', middlewareAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { resposta } = req.body;
    if (!resposta) return res.status(400).json({ error: 'Resposta é obrigatória.' });

    // Verificar propriedade
    const existing = await db.execute({ sql: 'SELECT * FROM respostas WHERE id = ?', args: [id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Resposta não encontrada.' });

    const row = existing.rows[0];
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem editar respostas.' });
    if (req.user.role === 'aluno' && Number(row.aluno_id) !== req.user.id) return res.status(403).json({ error: 'Sem permissão.' });

    // Reavaliar
    const avaliacao = avaliarResposta(Number(row.unidade), Number(row.etapa), Number(row.exercicio), resposta);

    await db.execute({
      sql: 'UPDATE respostas SET resposta = ?, nota = ?, feedback = ?, enviado_em = datetime(\'now\') WHERE id = ?',
      args: [resposta, avaliacao.nota, JSON.stringify(avaliacao), id],
    });

    res.json({ avaliacao, message: 'Resposta atualizada.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar resposta.' });
  }
});

// Deletar resposta
app.delete('/api/respostas/:id', middlewareAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.execute({ sql: 'SELECT * FROM respostas WHERE id = ?', args: [id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Resposta não encontrada.' });

    const row = existing.rows[0];
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem deletar respostas.' });
    if (req.user.role === 'aluno' && Number(row.aluno_id) !== req.user.id) return res.status(403).json({ error: 'Sem permissão.' });

    await db.execute({ sql: 'DELETE FROM respostas WHERE id = ?', args: [id] });
    res.json({ message: 'Resposta removida.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar resposta.' });
  }
});

// ===== GABARITO (protegido) =====
app.get('/api/gabarito/:unidade/:etapa/:exercicio', middlewareAuth, async (req, res) => {
  try {
    const { unidade, etapa, exercicio } = req.params;
    const u = parseInt(unidade), e = parseInt(etapa), ex = parseInt(exercicio);

    const gab = gabaritos[u];
    if (!gab || !gab.etapas[e] || !gab.etapas[e].exercicios[ex]) {
      return res.status(404).json({ error: 'Exercício não encontrado.' });
    }

    const gabData = gab.etapas[e].exercicios[ex];

    // Admin e coordenador sempre veem
    if (req.user.role === 'admin' || req.user.role === 'coordenador') {
      return res.json({ gabarito: gabData.resposta, palavrasChave: gabData.palavrasChave });
    }

    // Aluno: precisa de 3+ tentativas todas com nota < 10
    const tentativas = await db.execute({
      sql: 'SELECT nota FROM respostas WHERE aluno_id = ? AND unidade = ? AND etapa = ? AND exercicio = ? ORDER BY tentativa ASC',
      args: [req.user.id, u, e, ex],
    });

    if (tentativas.rows.length < 3) {
      return res.status(403).json({ error: `Você precisa de pelo menos 3 tentativas para ver o gabarito. Tentativas: ${tentativas.rows.length}/3` });
    }

    const todasAbaixo = tentativas.rows.every(r => Number(r.nota) < 10);
    if (!todasAbaixo) {
      return res.status(403).json({ error: 'Você já obteve nota 10 em alguma tentativa.' });
    }

    return res.json({ gabarito: gabData.resposta, palavrasChave: gabData.palavrasChave });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar gabarito.' });
  }
});

// ===== ADMIN / COORDENADOR ROUTES =====

// Listar todos alunos
app.get('/api/admin/alunos', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const result = await db.execute(
      `SELECT u.id, u.nome, u.email, u.role, u.criado_em,
        COUNT(r.id) as total_respostas,
        COALESCE(AVG(r.nota), 0) as media_nota
       FROM usuarios u
       LEFT JOIN respostas r ON u.id = r.aluno_id
       WHERE u.role = 'aluno'
       GROUP BY u.id
       ORDER BY u.nome`
    );
    res.json({ alunos: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar alunos.' });
  }
});

// Evolução de um aluno
app.get('/api/admin/alunos/:id/evolucao', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.execute({
      sql: `SELECT unidade, etapa, exercicio, nota, tentativa, enviado_em
            FROM respostas WHERE aluno_id = ? ORDER BY unidade, etapa, exercicio, tentativa`,
      args: [id],
    });

    // Agrupar por unidade
    const porUnidade = {};
    for (const r of result.rows) {
      const u = Number(r.unidade);
      if (!porUnidade[u]) porUnidade[u] = { respostas: [], somaNotas: 0, count: 0 };
      porUnidade[u].respostas.push(r);
      porUnidade[u].somaNotas += Number(r.nota);
      porUnidade[u].count++;
    }

    const evolucao = Object.entries(porUnidade).map(([u, data]) => ({
      unidade: Number(u),
      mediaNotas: Math.round((data.somaNotas / data.count) * 10) / 10,
      totalRespostas: data.count,
      respostas: data.respostas,
    }));

    res.json({ evolucao });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar evolução.' });
  }
});

// Estatísticas gerais
app.get('/api/admin/estatisticas', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const totalAlunos = await db.execute("SELECT COUNT(*) as total FROM usuarios WHERE role = 'aluno'");
    const totalRespostas = await db.execute('SELECT COUNT(*) as total FROM respostas');
    const mediaNotas = await db.execute('SELECT AVG(nota) as media FROM respostas');
    const porUnidade = await db.execute(
      'SELECT unidade, COUNT(*) as total, AVG(nota) as media FROM respostas GROUP BY unidade ORDER BY unidade'
    );

    res.json({
      totalAlunos: totalAlunos.rows[0].total,
      totalRespostas: totalRespostas.rows[0].total,
      mediaGeral: Math.round((Number(mediaNotas.rows[0].media) || 0) * 10) / 10,
      porUnidade: porUnidade.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
  }
});

// ===== DOCUMENTOS =====
app.get('/api/documentos', (req, res) => {
  const docsDir = path.join(__dirname, 'public', 'docs');
  const documentos = [];

  const categorias = [
    { pasta: 'geral', label: 'Material Geral' },
    { pasta: 'u1', label: 'Unidade 1' },
    { pasta: 'u2', label: 'Unidade 2' },
    { pasta: 'u3', label: 'Unidade 3' },
    { pasta: 'u4', label: 'Unidade 4' },
  ];

  for (const cat of categorias) {
    const catDir = path.join(docsDir, cat.pasta);
    if (fs.existsSync(catDir)) {
      const files = fs.readdirSync(catDir).filter(f => /\.(pdf|png|jpg)$/i.test(f));
      for (const f of files) {
        documentos.push({
          nome: f.replace(/\.[^.]+$/, '').replace(/_/g, ' '),
          arquivo: `/docs/${cat.pasta}/${f}`,
          categoria: cat.label,
          tipo: f.split('.').pop().toLowerCase(),
          isGabarito: /gabarito/i.test(f),
        });
      }
    }
  }

  res.json({ documentos });
});

// ===== README =====
app.get('/api/readme', (req, res) => {
  const readmePath = path.join(__dirname, 'README.md');
  if (fs.existsSync(readmePath)) {
    const content = fs.readFileSync(readmePath, 'utf-8');
    res.json({ content });
  } else {
    res.json({ content: '# ADS Anhanguera\nREADME não encontrado.' });
  }
});

// SPA fallback
app.get('/{*splat}', (req, res) => {
  try {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } catch (err) {
    res.status(404).json({ error: 'Página não encontrada.' });
  }
});

// Global error handler — garante que TODA resposta de erro seja JSON, não HTML
app.use((err, req, res, next) => {
  console.error('❌ Erro não tratado:', err.message || err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Erro interno do servidor.' });
});

// Start server (apenas quando executado diretamente, não na Vercel)
if (require.main === module) {
  dbInit.then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
    });
  });
}

// Export para Vercel serverless
module.exports = app;
