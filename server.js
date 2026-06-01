const express = require('express');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { dbExecute, initDB } = require('./src/database');
const gabaritos = require('./src/gabaritos');
const { avaliarResposta } = require('./src/avaliador');
const { verificarSenha, gerarToken, middlewareAuth, middlewareRole } = require('./src/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Inicialização do banco com retry
let dbReady = false;
let dbInitError = null;
let dbInitPromise = null;

function startDBInit() {
  dbInitPromise = initDB()
    .then(() => {
      dbReady = true;
      dbInitError = null;
      console.log('✅ DB pronto para receber requests.');
    })
    .catch(err => {
      dbInitError = err;
      dbReady = false;
      console.error('❌ Erro na inicialização do DB:', err.message || err);
    });
  return dbInitPromise;
}

startDBInit();

app.use(express.json({ limit: '25mb' }));
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
      // Se houve erro anterior, tenta re-inicializar
      if (dbInitError) {
        console.log('🔄 Retentando inicialização do DB...');
        await startDBInit();
      } else {
        await dbInitPromise;
      }
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
    res.status(503).json({ error: 'Banco de dados indisponível. Tente novamente em instantes.' });
  }
});

// ===== AUTH ROUTES =====

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'Email e senha são obrigatórios.' });

    const result = await dbExecute({ sql: 'SELECT * FROM usuarios WHERE email = ?', args: [email] });
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
    const result = await dbExecute({ sql: 'SELECT id, nome, email, role FROM usuarios WHERE id = ?', args: [req.user.id] });
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
    const tentResult = await dbExecute({
      sql: 'SELECT COUNT(*) as cnt FROM respostas WHERE aluno_id = ? AND unidade = ? AND etapa = ? AND exercicio = ?',
      args: [aluno_id, unidade, etapa, exercicio],
    });
    const tentativa = Number(tentResult.rows[0].cnt) + 1;

    // Avaliar a resposta
    const avaliacao = avaliarResposta(unidade, etapa, exercicio, resposta);

    await dbExecute({
      sql: `INSERT INTO respostas (aluno_id, unidade, etapa, exercicio, resposta, nota, feedback, tentativa)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [aluno_id, unidade, etapa, exercicio, resposta, avaliacao.nota, JSON.stringify(avaliacao), tentativa],
    });

    res.json({ avaliacao, tentativa });
  } catch (err) {
    console.error('Erro ao salvar resposta:', err.message || err);
    res.status(500).json({ error: 'Erro ao salvar resposta: ' + (err.message || 'erro desconhecido') });
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

    const result = await dbExecute({ sql, args });
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
    const existing = await dbExecute({ sql: 'SELECT * FROM respostas WHERE id = ?', args: [id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Resposta não encontrada.' });

    const row = existing.rows[0];
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem editar respostas.' });
    if (req.user.role === 'aluno' && Number(row.aluno_id) !== req.user.id) return res.status(403).json({ error: 'Sem permissão.' });

    // Reavaliar
    const avaliacao = avaliarResposta(Number(row.unidade), Number(row.etapa), Number(row.exercicio), resposta);

    await dbExecute({
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
    const existing = await dbExecute({ sql: 'SELECT * FROM respostas WHERE id = ?', args: [id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Resposta não encontrada.' });

    const row = existing.rows[0];
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem deletar respostas.' });
    if (req.user.role === 'aluno' && Number(row.aluno_id) !== req.user.id) return res.status(403).json({ error: 'Sem permissão.' });

    await dbExecute({ sql: 'DELETE FROM respostas WHERE id = ?', args: [id] });
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

    // Admin e coordenador sempre veem tudo
    if (req.user.role === 'admin' || req.user.role === 'coordenador') {
      return res.json({
        gabarito: gabData.gabarito,
        respostaModelo: gabData.respostaModelo,
        palavrasChave: gabData.palavrasChave,
      });
    }

    // Aluno: precisa de 3+ tentativas OU ter obtido nota 10
    const tentativas = await dbExecute({
      sql: 'SELECT nota FROM respostas WHERE aluno_id = ? AND unidade = ? AND etapa = ? AND exercicio = ? ORDER BY tentativa ASC',
      args: [req.user.id, u, e, ex],
    });

    const temNota10 = tentativas.rows.some(r => Number(r.nota) >= 10);
    const tem3Tentativas = tentativas.rows.length >= 3;

    if (!temNota10 && !tem3Tentativas) {
      return res.status(403).json({ error: `Você precisa de pelo menos 3 tentativas ou nota 10 para ver o gabarito. Tentativas: ${tentativas.rows.length}/3` });
    }

    return res.json({
      gabarito: gabData.gabarito,
      respostaModelo: gabData.respostaModelo,
      palavrasChave: gabData.palavrasChave,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar gabarito.' });
  }
});

// ===== ADMIN / COORDENADOR ROUTES =====

// Recalcular todas as notas existentes com os novos gabaritos
app.post('/api/admin/recalcular', middlewareAuth, middlewareRole('admin'), async (req, res) => {
  try {
    const result = await dbExecute('SELECT id, unidade, etapa, exercicio, resposta FROM respostas ORDER BY id');
    const rows = result.rows;
    let atualizadas = 0;
    const detalhes = [];

    for (const row of rows) {
      const avaliacao = avaliarResposta(Number(row.unidade), Number(row.etapa), Number(row.exercicio), row.resposta);
      await dbExecute({
        sql: 'UPDATE respostas SET nota = ?, feedback = ? WHERE id = ?',
        args: [avaliacao.nota, JSON.stringify(avaliacao), row.id],
      });
      detalhes.push({
        id: row.id,
        unidade: row.unidade,
        etapa: row.etapa,
        exercicio: row.exercicio,
        novaNota: avaliacao.nota,
        percentualAcerto: avaliacao.percentualAcerto,
      });
      atualizadas++;
    }

    res.json({
      message: `${atualizadas} respostas recalculadas com sucesso.`,
      total: atualizadas,
      detalhes,
    });
  } catch (err) {
    console.error('Erro ao recalcular notas:', err);
    res.status(500).json({ error: 'Erro ao recalcular notas: ' + (err.message || 'erro desconhecido') });
  }
});

// Listar todos alunos
app.get('/api/admin/alunos', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const result = await dbExecute(
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
    const result = await dbExecute({
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
    const totalAlunos = await dbExecute("SELECT COUNT(*) as total FROM usuarios WHERE role = 'aluno'");
    const totalRespostas = await dbExecute('SELECT COUNT(*) as total FROM respostas');
    const mediaNotas = await dbExecute('SELECT AVG(nota) as media FROM respostas');
    const porUnidade = await dbExecute(
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

// ===== PROJETOS DE CÓDIGO =====

// Listar todos os projetos (admin/coord vê todos, aluno vê só o seu)
app.get('/api/projetos', middlewareAuth, async (req, res) => {
  try {
    let result;
    if (req.user.role === 'admin' || req.user.role === 'coordenador') {
      result = await dbExecute(
        `SELECT p.*, u.nome as autor_nome FROM projetos_codigo p
         JOIN usuarios u ON p.aluno_id = u.id
         ORDER BY p.atualizado_em DESC`
      );
    } else {
      result = await dbExecute({
        sql: `SELECT p.*, u.nome as autor_nome FROM projetos_codigo p
              JOIN usuarios u ON p.aluno_id = u.id
              WHERE p.aluno_id = ?
              ORDER BY p.atualizado_em DESC`,
        args: [req.user.id],
      });
    }
    res.json({ projetos: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar projetos.' });
  }
});

// Buscar projeto específico
app.get('/api/projetos/:id', middlewareAuth, async (req, res) => {
  try {
    const result = await dbExecute({
      sql: 'SELECT p.*, u.nome as autor_nome FROM projetos_codigo p JOIN usuarios u ON p.aluno_id = u.id WHERE p.id = ?',
      args: [req.params.id],
    });
    if (result.rows.length === 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const projeto = result.rows[0];
    if (req.user.role === 'aluno' && Number(projeto.aluno_id) !== req.user.id) {
      return res.status(403).json({ error: 'Sem permissão.' });
    }
    res.json({ projeto });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar projeto.' });
  }
});

// Criar novo projeto
app.post('/api/projetos', middlewareAuth, async (req, res) => {
  try {
    const { nome, html, css, js, py, assets } = req.body;
    const assetsStr = typeof assets === 'string' ? assets : JSON.stringify(assets || {});
    const result = await dbExecute({
      sql: `INSERT INTO projetos_codigo (aluno_id, nome, html, css, js, py, assets) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [req.user.id, nome || 'Meu Projeto', html || '', css || '', js || '', py || '', assetsStr],
    });
    res.json({ id: Number(result.lastInsertRowid), message: 'Projeto criado.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar projeto.' });
  }
});

// Atualizar projeto
app.put('/api/projetos/:id', middlewareAuth, async (req, res) => {
  try {
    const existing = await dbExecute({ sql: 'SELECT * FROM projetos_codigo WHERE id = ?', args: [req.params.id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const projeto = existing.rows[0];
    if (req.user.role === 'aluno' && Number(projeto.aluno_id) !== req.user.id) {
      return res.status(403).json({ error: 'Sem permissão.' });
    }
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem editar projetos.' });

    const { nome, html, css, js, py, assets } = req.body;
    const assetsStr = assets === undefined ? projeto.assets : (typeof assets === 'string' ? assets : JSON.stringify(assets || {}));
    await dbExecute({
      sql: `UPDATE projetos_codigo SET nome = ?, html = ?, css = ?, js = ?, py = ?, assets = ?, atualizado_em = datetime('now') WHERE id = ?`,
      args: [nome || projeto.nome, html ?? projeto.html, css ?? projeto.css, js ?? projeto.js, py ?? projeto.py, assetsStr, req.params.id],
    });
    res.json({ message: 'Projeto atualizado.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar projeto.' });
  }
});

// Deletar projeto
app.delete('/api/projetos/:id', middlewareAuth, async (req, res) => {
  try {
    const existing = await dbExecute({ sql: 'SELECT * FROM projetos_codigo WHERE id = ?', args: [req.params.id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const projeto = existing.rows[0];
    if (req.user.role === 'coordenador') return res.status(403).json({ error: 'Coordenadores não podem deletar projetos.' });
    if (req.user.role === 'aluno' && Number(projeto.aluno_id) !== req.user.id) {
      return res.status(403).json({ error: 'Sem permissão.' });
    }
    await dbExecute({ sql: 'DELETE FROM projetos_codigo WHERE id = ?', args: [req.params.id] });
    res.json({ message: 'Projeto removido.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar projeto.' });
  }
});

// Listar todos os alunos (para admin/coord verem sub-abas)
app.get('/api/projetos-alunos', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const result = await dbExecute(
      `SELECT u.id, u.nome, COUNT(p.id) as total_projetos
       FROM usuarios u
       LEFT JOIN projetos_codigo p ON u.id = p.aluno_id
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

// Buscar projetos de um aluno específico (admin/coord)
app.get('/api/projetos-aluno/:id', middlewareAuth, middlewareRole('admin', 'coordenador'), async (req, res) => {
  try {
    const result = await dbExecute({
      sql: `SELECT p.*, u.nome as autor_nome FROM projetos_codigo p
            JOIN usuarios u ON p.aluno_id = u.id
            WHERE p.aluno_id = ?
            ORDER BY p.atualizado_em DESC`,
      args: [req.params.id],
    });
    res.json({ projetos: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar projetos do aluno.' });
  }
});

// Buscar projetos do admin (visíveis para todos os usuários autenticados, read-only)
app.get('/api/projetos-admin', middlewareAuth, async (req, res) => {
  try {
    const result = await dbExecute(
      `SELECT p.*, u.nome as autor_nome FROM projetos_codigo p
       JOIN usuarios u ON p.aluno_id = u.id
       WHERE u.role = 'admin'
       ORDER BY p.atualizado_em DESC`
    );
    res.json({ projetos: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar projetos do professor.' });
  }
});

// Toggle visto de um projeto (apenas admin)
app.put('/api/projetos/:id/visto', middlewareAuth, middlewareRole('admin'), async (req, res) => {
  try {
    const existing = await dbExecute({ sql: 'SELECT visto FROM projetos_codigo WHERE id = ?', args: [req.params.id] });
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const novoVisto = existing.rows[0].visto ? 0 : 1;
    await dbExecute({ sql: 'UPDATE projetos_codigo SET visto = ? WHERE id = ?', args: [novoVisto, req.params.id] });
    res.json({ visto: novoVisto });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar visto.' });
  }
});

// Ranking de alunos (linhas, palavras, projetos) — exclui admin e coordenador
app.get('/api/ranking', middlewareAuth, async (req, res) => {
  try {
    const alunos = await dbExecute(
      `SELECT u.id, u.nome FROM usuarios u WHERE u.role = 'aluno' ORDER BY u.nome`
    );
    const ranking = [];
    for (const aluno of alunos.rows) {
      const projetos = await dbExecute({
        sql: 'SELECT html, css, js, py FROM projetos_codigo WHERE aluno_id = ?',
        args: [aluno.id],
      });
      let totalLinhas = 0;
      let totalPalavras = 0;
      const totalProjetos = projetos.rows.length;
      for (const p of projetos.rows) {
        const code = (p.html || '') + '\n' + (p.css || '') + '\n' + (p.js || '') + '\n' + (p.py || '');
        totalLinhas += code.split('\n').filter(l => l.trim().length > 0).length;
        totalPalavras += code.split(/\s+/).filter(w => w.length > 0).length;
      }
      ranking.push({
        id: aluno.id,
        nome: aluno.nome,
        totalProjetos,
        totalLinhas,
        totalPalavras,
      });
    }
    // Ordenar por projetos DESC, depois linhas DESC
    ranking.sort((a, b) => b.totalProjetos - a.totalProjetos || b.totalLinhas - a.totalLinhas);
    res.json({ ranking });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao calcular ranking.' });
  }
});

// ===== DOCUMENTOS =====
app.get('/api/documentos', (req, res) => {
  const docsDir = path.join(__dirname, 'public', 'docs');

  const categorias = [
    { pasta: 'ads1-projeto-software', label: 'Projeto de Software', cor: 'green' },
    { pasta: 'ads2', label: 'ADS 2', cor: 'blue' },
    { pasta: 'ads3', label: 'ADS 3', cor: 'purple' },
    { pasta: 'ads4', label: 'ADS 4', cor: 'orange' },
  ];

  const pastas = categorias.map(cat => {
    const catDir = path.join(docsDir, cat.pasta);
    const arquivos = [];
    if (fs.existsSync(catDir)) {
      const files = fs.readdirSync(catDir).filter(f => /\.(pdf|png|jpg)$/i.test(f));
      for (const f of files) {
        arquivos.push({
          nome: f.replace(/\.[^.]+$/, '').replace(/_/g, ' '),
          arquivo: `/docs/${cat.pasta}/${encodeURIComponent(f)}`,
          tipo: f.split('.').pop().toLowerCase(),
          isGabarito: /gabarito/i.test(f),
        });
      }
    }
    return { label: cat.label, cor: cat.cor, arquivos };
  });

  res.json({ pastas });
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

// ===== EXPLORER (file browser) =====
const EXPLORER_ROOT = __dirname;
const EXPLORER_IGNORE = new Set(['node_modules', '.git', '.env', '.env.local', '.env.production']);

function listDirRecursive(dirPath, basePath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const items = [];
  for (const entry of entries) {
    if (EXPLORER_IGNORE.has(entry.name)) continue;
    const rel = path.join(basePath, entry.name);
    if (entry.isDirectory()) {
      items.push({ name: entry.name, path: rel, type: 'folder', children: listDirRecursive(path.join(dirPath, entry.name), rel) });
    } else {
      items.push({ name: entry.name, path: rel, type: 'file' });
    }
  }
  items.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  return items;
}

app.get('/api/explorer/tree', (req, res) => {
  try {
    const tree = listDirRecursive(EXPLORER_ROOT, '');
    res.json({ tree });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao listar diretório.' });
  }
});

app.get('/api/explorer/file', (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'Parâmetro path é obrigatório.' });

  const resolved = path.resolve(EXPLORER_ROOT, filePath);
  if (!resolved.startsWith(EXPLORER_ROOT)) return res.status(403).json({ error: 'Acesso negado.' });

  // Block sensitive files
  const parts = filePath.split(path.sep);
  if (parts.some(p => EXPLORER_IGNORE.has(p))) return res.status(403).json({ error: 'Acesso negado.' });
  if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) return res.status(404).json({ error: 'Arquivo não encontrado.' });

  const ext = path.extname(resolved).toLowerCase();
  const textExtensions = new Set(['.js', '.ts', '.json', '.html', '.css', '.md', '.txt', '.yaml', '.yml', '.xml', '.env.example', '.sh', '.sql', '.py']);
  const imageExtensions = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico']);

  if (ext === '.pdf') {
    res.sendFile(resolved);
  } else if (imageExtensions.has(ext)) {
    res.sendFile(resolved);
  } else if (textExtensions.has(ext) || ext === '') {
    const content = fs.readFileSync(resolved, 'utf-8');
    res.json({ content, ext, filename: path.basename(resolved) });
  } else {
    res.sendFile(resolved);
  }
});

// Explorer page
app.get('/explorer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'explorer.html'));
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
  dbInitPromise.then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
    });
  });
}

// Export para Vercel serverless
module.exports = app;
