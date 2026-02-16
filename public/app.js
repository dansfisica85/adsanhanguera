// ===== Estado da Aplicação =====
let authToken = null;
let currentUser = null;
let currentTab = 'u1';
let exerciciosCache = {};
let respostasCache = {};
let coordView = false; // false = visao aluno, true = visao admin
let chartEvolucao = null;
let chartUnidades = null;

// ===== Helpers =====
function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`,
  };
}

function isAdmin() {
  return currentUser && currentUser.role === 'admin';
}

function isCoord() {
  return currentUser && currentUser.role === 'coordenador';
}

function isAluno() {
  return currentUser && currentUser.role === 'aluno';
}

function canSeeAdmin() {
  return isAdmin() || (isCoord() && coordView);
}

function canMutate() {
  return isAdmin() || isAluno();
}

// ===== Inicialização =====
document.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('adsToken');
  const savedUser = localStorage.getItem('adsUser');
  if (saved && savedUser) {
    try {
      authToken = saved;
      currentUser = JSON.parse(savedUser);
      verifyAndShow();
    } catch {
      clearAuth();
    }
  }

  document.getElementById('loginForm').addEventListener('submit', handleLogin);
});

async function verifyAndShow() {
  try {
    const res = await fetch('/api/auth/me', { headers: authHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();
    currentUser = data.user;
    localStorage.setItem('adsUser', JSON.stringify(currentUser));
    showApp();
  } catch {
    clearAuth();
  }
}

function clearAuth() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem('adsToken');
  localStorage.removeItem('adsUser');
}

// ===== Login =====
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value.trim();
  const senha = document.getElementById('loginSenha').value;
  if (!email || !senha) return;

  const btn = e.target.querySelector('button[type="submit"]');
  const errorEl = document.getElementById('loginError');
  btn.disabled = true;
  btn.textContent = 'Entrando...';
  errorEl.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, senha }),
    });

    // Proteger contra resposta não-JSON (ex: Vercel retornando HTML de erro)
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      const text = await res.text();
      console.error('Resposta não-JSON do servidor:', text.substring(0, 200));
      throw new Error('Erro de servidor. Tente novamente em instantes.');
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erro ao logar.');

    authToken = data.token;
    currentUser = data.user;
    localStorage.setItem('adsToken', authToken);
    localStorage.setItem('adsUser', JSON.stringify(currentUser));
    showApp();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Entrar';
  }
}

function showApp() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  // User info
  document.getElementById('userNameDisplay').textContent = currentUser.nome;

  // Role badge
  const badge = document.getElementById('roleBadge');
  badge.textContent = currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1);
  badge.className = 'role-badge ' + currentUser.role;

  // Coord toggle
  if (isCoord()) {
    document.getElementById('coordToggle').classList.remove('hidden');
  }

  // Admin tab visibility
  if (isAdmin()) {
    document.getElementById('tabAdmin').style.display = '';
  } else if (isCoord()) {
    document.getElementById('tabAdmin').style.display = coordView ? '' : 'none';
  }

  // Load data
  loadExercicios(1);
  loadRespostasAluno();
  loadProfileData();

  if (canSeeAdmin()) {
    loadAdminData();
  }
}

function logout() {
  clearAuth();
  exerciciosCache = {};
  respostasCache = {};
  coordView = false;
  document.getElementById('app').classList.add('hidden');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('loginForm').reset();
  document.getElementById('loginError').classList.add('hidden');

  if (chartEvolucao) { chartEvolucao.destroy(); chartEvolucao = null; }
  if (chartUnidades) { chartUnidades.destroy(); chartUnidades = null; }
}

// ===== Coord Toggle =====
function toggleCoordView() {
  coordView = document.getElementById('coordSwitch').checked;
  document.getElementById('coordLabel').textContent = coordView ? 'Visão Admin' : 'Visão Aluno';
  document.getElementById('tabAdmin').style.display = coordView ? '' : 'none';

  if (coordView && !document.getElementById('adminTotalAlunos').textContent) {
    loadAdminData();
  }
}

// ===== Tabs =====
function switchTab(tabId) {
  currentTab = tabId;

  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const tabBtn = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (tabBtn) tabBtn.classList.add('active');

  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const tabContent = document.getElementById(`tab-${tabId}`);
  if (tabContent) tabContent.classList.add('active');

  // Load unit exercises
  const unitMatch = tabId.match(/^u(\d)$/);
  if (unitMatch) {
    loadExercicios(parseInt(unitMatch[1]));
  }

  if (tabId === 'docs') loadDocumentos();
  if (tabId === 'perfil') loadProfileData();
  if (tabId === 'admin') loadAdminData();
}

// ===== Conceitos Toggle =====
function toggleConcept(header) {
  header.closest('.concept-card').classList.toggle('open');
}

// ===== Flash Card Modal =====
function openFlashCard(card) {
  const modal = document.getElementById('flashCardModal');
  const icon = card.querySelector('.flashcard-icon').textContent;
  const title = card.querySelector('.flashcard-title').textContent;
  const badge = card.querySelector('.flashcard-badge').textContent;
  const content = card.querySelector('.flashcard-full-content').innerHTML;
  const color = card.getAttribute('data-color');

  document.getElementById('flashModalIcon').textContent = icon;
  document.getElementById('flashModalTitle').textContent = title;
  document.getElementById('flashModalBadge').textContent = badge;
  document.getElementById('flashModalBody').innerHTML = content;

  // Set color theme on badge
  const badgeEl = document.getElementById('flashModalBadge');
  const colorMap = {
    orange: 'linear-gradient(135deg, #F37021, #D45A0A)',
    blue: 'linear-gradient(135deg, #2563EB, #1D4ED8)',
    green: 'linear-gradient(135deg, #16A34A, #15803D)',
    purple: 'linear-gradient(135deg, #7C3AED, #6D28D9)',
    red: 'linear-gradient(135deg, #DC2626, #B91C1C)',
  };
  badgeEl.style.background = colorMap[color] || colorMap.orange;

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeFlashCard(e) {
  if (e && e.target !== e.currentTarget) return;
  const modal = document.getElementById('flashCardModal');
  modal.classList.remove('active');
  document.body.style.overflow = '';
}

// Close flash card on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const flashModal = document.getElementById('flashCardModal');
    if (flashModal && flashModal.classList.contains('active')) {
      closeFlashCard();
    }
  }
});

// ===== Carregar Exercícios =====
async function loadExercicios(unidade) {
  const container = document.getElementById(`exercises-${unidade}`);
  if (!container) return;

  if (exerciciosCache[unidade]) {
    renderExercicios(container, unidade, exerciciosCache[unidade]);
    return;
  }

  container.innerHTML = '<div class="loading">Carregando exercícios</div>';

  try {
    const res = await fetch(`/api/exercicios/${unidade}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    exerciciosCache[unidade] = data;
    renderExercicios(container, unidade, data);
  } catch (err) {
    container.innerHTML = `<p style="color: var(--accent-red);">Erro: ${err.message}</p>`;
  }
}

function renderExercicios(container, unidade, data) {
  let html = '';

  for (const [etapaKey, etapa] of Object.entries(data.etapas)) {
    for (const [exKey, ex] of Object.entries(etapa.exercicios)) {
      const respKey = `${unidade}-${etapaKey}-${exKey}`;
      const resposta = respostasCache[respKey];

      html += `<div class="exercise-card" id="ex-${respKey}">`;
      html += `<div class="etapa-titulo">${etapa.titulo}</div>`;
      html += `<span class="exercise-num">Exercício ${exKey}</span>`;
      html += `<p class="pergunta">${ex.pergunta}</p>`;

      if (ex.conceitos && ex.conceitos.length > 0) {
        html += '<div class="conceitos">';
        ex.conceitos.forEach(c => {
          html += `<span class="conceito-tag">${c}</span>`;
        });
        html += '</div>';
      }

      if (resposta) {
        html += renderFeedback(resposta, respKey);
        html += `<div class="exercise-actions">`;
        html += `<button class="btn btn-sm btn-outline" onclick="reDoExercise('${respKey}', ${unidade}, ${etapaKey}, ${exKey})">Refazer</button>`;
        // Gabarito button
        html += `<button class="btn btn-sm btn-outline" onclick="verGabarito(${unidade}, ${etapaKey}, ${exKey})">Ver Gabarito</button>`;
        if (canMutate() && resposta.id) {
          html += `<button class="btn btn-sm btn-danger" onclick="deleteResposta(${resposta.id}, '${respKey}', ${unidade})">Excluir</button>`;
        }
        html += `</div>`;
      } else {
        html += renderExerciseForm(unidade, etapaKey, exKey);
      }

      html += '</div>';
    }
  }

  container.innerHTML = html || '<p style="color:var(--text-muted);">Nenhum exercício disponível.</p>';
}

function renderExerciseForm(unidade, etapa, exercicio) {
  return `
    <form class="exercise-form" onsubmit="submitResposta(event, ${unidade}, ${etapa}, ${exercicio})">
      <div class="form-group">
        <label>Sua Resposta</label>
        <textarea id="resp-${unidade}-${etapa}-${exercicio}" placeholder="Escreva sua resposta... (mínimo 15 palavras)" required></textarea>
      </div>
      <button type="submit" class="btn btn-primary">Enviar Resposta</button>
    </form>
  `;
}

function renderFeedback(resp, respKey) {
  const nota = Number(resp.nota);
  let classe, corClasse;
  if (nota >= 8) { classe = 'nota-alta'; corClasse = 'alta'; }
  else if (nota >= 5) { classe = 'nota-media'; corClasse = 'media'; }
  else { classe = 'nota-baixa'; corClasse = 'baixa'; }

  let feedbackData;
  if (typeof resp.feedback === 'string') {
    try { feedbackData = JSON.parse(resp.feedback); } catch { feedbackData = null; }
  } else {
    feedbackData = resp;
  }

  let html = `<div class="feedback-box ${classe}">`;
  html += `<div class="feedback-header">`;
  html += `<span class="feedback-nota ${corClasse}">Nota: ${nota}/10</span>`;
  if (resp.tentativa) html += `<span class="feedback-percentual">Tentativa ${resp.tentativa}</span>`;
  else if (feedbackData && feedbackData.percentualAcerto !== undefined)
    html += `<span class="feedback-percentual">${feedbackData.percentualAcerto}% de acerto</span>`;
  html += `</div>`;

  if (feedbackData && feedbackData.feedback) {
    html += `<p class="feedback-text">${feedbackData.feedback}</p>`;
  } else if (typeof resp.feedback === 'string') {
    html += `<p class="feedback-text">${resp.feedback}</p>`;
  }

  if (feedbackData && feedbackData.acertos && feedbackData.acertos.length > 0) {
    html += '<ul class="feedback-list">';
    feedbackData.acertos.forEach(a => { html += `<li>${a}</li>`; });
    html += '</ul>';
  }

  if (feedbackData && feedbackData.sugestoes && feedbackData.sugestoes.length > 0) {
    html += '<ul class="feedback-list" style="margin-top:8px;">';
    feedbackData.sugestoes.forEach(s => { html += `<li>${s}</li>`; });
    html += '</ul>';
  }

  if (feedbackData && feedbackData.gabaritoResumo) {
    html += `<details class="feedback-gabarito"><summary>Ver gabarito resumido</summary><p>${feedbackData.gabaritoResumo}</p></details>`;
  }

  html += '</div>';
  return html;
}

// ===== Enviar Resposta =====
async function submitResposta(e, unidade, etapa, exercicio) {
  e.preventDefault();
  const textarea = document.getElementById(`resp-${unidade}-${etapa}-${exercicio}`);
  const resposta = textarea.value.trim();
  if (!resposta) return;

  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'Avaliando...';

  try {
    const res = await fetch('/api/respostas', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ unidade, etapa, exercicio, resposta }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    const respKey = `${unidade}-${etapa}-${exercicio}`;
    respostasCache[respKey] = { ...data.avaliacao, tentativa: data.tentativa };

    renderExercicios(
      document.getElementById(`exercises-${unidade}`),
      unidade,
      exerciciosCache[unidade]
    );

    const exCard = document.getElementById(`ex-${respKey}`);
    if (exCard) exCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (err) {
    alert('Erro: ' + err.message);
    btn.disabled = false;
    btn.textContent = 'Enviar Resposta';
  }
}

// ===== Refazer =====
function reDoExercise(respKey, unidade, etapa, exercicio) {
  delete respostasCache[respKey];
  renderExercicios(
    document.getElementById(`exercises-${unidade}`),
    unidade,
    exerciciosCache[unidade]
  );
}

// ===== Delete Resposta =====
async function deleteResposta(id, respKey, unidade) {
  if (!confirm('Tem certeza que deseja excluir esta resposta?')) return;

  try {
    const res = await fetch(`/api/respostas/${id}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error);
    }

    delete respostasCache[respKey];
    renderExercicios(
      document.getElementById(`exercises-${unidade}`),
      unidade,
      exerciciosCache[unidade]
    );
  } catch (err) {
    alert('Erro: ' + err.message);
  }
}

// ===== Ver Gabarito =====
async function verGabarito(unidade, etapa, exercicio) {
  try {
    const res = await fetch(`/api/gabarito/${unidade}/${etapa}/${exercicio}`, {
      headers: authHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.error);
      return;
    }

    const modal = document.getElementById('readmeModal');
    const content = document.getElementById('readmeContent');
    document.querySelector('#readmeModal .modal-box-header h3').textContent = `Gabarito - U${unidade} E${etapa} Ex${exercicio}`;

    let html = `<h3>Resposta Esperada</h3><p>${data.gabarito}</p>`;
    if (data.palavrasChave && data.palavrasChave.length > 0) {
      html += `<h3>Palavras-Chave</h3><div style="display:flex;flex-wrap:wrap;gap:6px;">`;
      data.palavrasChave.forEach(p => {
        html += `<span style="background:var(--primary-light);color:var(--primary);padding:4px 10px;border-radius:12px;font-size:0.82rem;">${p}</span>`;
      });
      html += '</div>';
    }

    content.innerHTML = html;
    modal.classList.remove('hidden');
  } catch (err) {
    alert('Erro ao buscar gabarito: ' + err.message);
  }
}

// ===== Carregar Respostas Anteriores =====
async function loadRespostasAluno() {
  if (!authToken) return;

  try {
    const res = await fetch('/api/respostas', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) return;

    if (data.respostas && data.respostas.length > 0) {
      const byExercise = {};
      for (const r of data.respostas) {
        const key = `${r.unidade}-${r.etapa}-${r.exercicio}`;
        if (!byExercise[key] || new Date(r.enviado_em) > new Date(byExercise[key].enviado_em)) {
          byExercise[key] = r;
        }
      }

      for (const [key, r] of Object.entries(byExercise)) {
        let feedbackData;
        try { feedbackData = JSON.parse(r.feedback); } catch { feedbackData = null; }

        respostasCache[key] = {
          id: r.id,
          nota: r.nota,
          tentativa: r.tentativa,
          feedback: feedbackData ? feedbackData.feedback || r.feedback : r.feedback,
          acertos: feedbackData ? feedbackData.acertos : [],
          sugestoes: feedbackData ? feedbackData.sugestoes : [],
          gabaritoResumo: feedbackData ? feedbackData.gabaritoResumo : null,
          percentualAcerto: feedbackData ? feedbackData.percentualAcerto : null,
        };
      }

      // Re-render current tab
      const unitMatch = currentTab.match(/^u(\d)$/);
      if (unitMatch && exerciciosCache[parseInt(unitMatch[1])]) {
        const u = parseInt(unitMatch[1]);
        renderExercicios(document.getElementById(`exercises-${u}`), u, exerciciosCache[u]);
      }
    }
  } catch (err) {
    console.error('Erro ao carregar respostas:', err);
  }
}

// ===== Profile =====
function loadProfileData() {
  if (!currentUser) return;

  document.getElementById('profileNome').textContent = currentUser.nome;
  document.getElementById('profileEmail').textContent = currentUser.email;

  const roleEl = document.getElementById('profileRole');
  roleEl.textContent = currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1);
  roleEl.className = 'role-badge ' + currentUser.role;

  // Calculate stats from cache
  const resKeys = Object.keys(respostasCache);
  const notas = resKeys.map(k => Number(respostasCache[k].nota)).filter(n => !isNaN(n));
  const unidades = new Set(resKeys.map(k => k.split('-')[0]));

  document.getElementById('statRespostas').textContent = resKeys.length;
  document.getElementById('statMedia').textContent = notas.length > 0
    ? (notas.reduce((a, b) => a + b, 0) / notas.length).toFixed(1)
    : '0.0';
  document.getElementById('statUnidades').textContent = `${unidades.size}/4`;
}

// ===== Admin Panel =====
async function loadAdminData() {
  if (!canSeeAdmin()) return;

  try {
    // Stats
    const statsRes = await fetch('/api/admin/estatisticas', { headers: authHeaders() });
    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('adminTotalAlunos').textContent = stats.totalAlunos;
      document.getElementById('adminTotalRespostas').textContent = stats.totalRespostas;
      document.getElementById('adminMediaGeral').textContent = stats.mediaGeral;

      // Chart
      renderChartUnidades(stats.porUnidade);
    }

    // Alunos list
    const alunosRes = await fetch('/api/admin/alunos', { headers: authHeaders() });
    if (alunosRes.ok) {
      const data = await alunosRes.json();
      renderAlunosList(data.alunos);
    }
  } catch (err) {
    console.error('Erro admin:', err);
  }
}

function renderChartUnidades(porUnidade) {
  const canvas = document.getElementById('chartUnidades');
  if (!canvas) return;

  if (chartUnidades) chartUnidades.destroy();

  const labels = (porUnidade || []).map(u => `Unidade ${u.unidade}`);
  const medias = (porUnidade || []).map(u => Math.round(Number(u.media) * 10) / 10);
  const totais = (porUnidade || []).map(u => Number(u.total));

  chartUnidades = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Média de Notas',
          data: medias,
          backgroundColor: 'rgba(243, 112, 33, 0.7)',
          borderColor: '#F37021',
          borderWidth: 2,
          borderRadius: 6,
        },
        {
          label: 'Total de Respostas',
          data: totais,
          backgroundColor: 'rgba(37, 99, 235, 0.5)',
          borderColor: '#2563EB',
          borderWidth: 2,
          borderRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true, grid: { color: '#EDE6DD' } },
        x: { grid: { display: false } },
      },
      plugins: { legend: { position: 'top' } },
    },
  });
}

function renderAlunosList(alunos) {
  const container = document.getElementById('adminAlunosList');
  if (!container) return;

  container.innerHTML = (alunos || []).map(a => `
    <div class="aluno-card" onclick="loadEvolucao(${a.id}, '${a.nome.replace(/'/g, "\\'")}')">
      <h4>${a.nome}</h4>
      <p class="aluno-email">${a.email}</p>
      <div class="aluno-stats">
        <span class="aluno-stat">Respostas: <strong>${a.total_respostas}</strong></span>
        <span class="aluno-stat">Média: <strong>${(Math.round(Number(a.media_nota) * 10) / 10).toFixed(1)}</strong></span>
      </div>
    </div>
  `).join('');
}

async function loadEvolucao(alunoId, nome) {
  const section = document.getElementById('adminEvolucao');
  section.classList.remove('hidden');
  document.getElementById('evolucaoNome').textContent = nome;

  try {
    const res = await fetch(`/api/admin/alunos/${alunoId}/evolucao`, { headers: authHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();

    renderChartEvolucao(data.evolucao);

    const detalhes = document.getElementById('evolucaoDetalhes');
    detalhes.innerHTML = (data.evolucao || []).map(e => `
      <div class="stat-card" style="margin-top:12px;">
        <span class="stat-value">${e.mediaNotas}</span>
        <span class="stat-label">Unidade ${e.unidade} (${e.totalRespostas} respostas)</span>
      </div>
    `).join('');

    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch {
    alert('Erro ao carregar evolução.');
  }
}

function renderChartEvolucao(evolucao) {
  const canvas = document.getElementById('chartEvolucao');
  if (!canvas) return;

  if (chartEvolucao) chartEvolucao.destroy();

  const labels = (evolucao || []).map(e => `Unidade ${e.unidade}`);
  const medias = (evolucao || []).map(e => e.mediaNotas);

  chartEvolucao = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Média de Notas',
        data: medias,
        borderColor: '#F37021',
        backgroundColor: 'rgba(243, 112, 33, 0.1)',
        fill: true,
        tension: 0.3,
        pointBackgroundColor: '#F37021',
        pointRadius: 6,
        pointHoverRadius: 8,
        borderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true, max: 10, grid: { color: '#EDE6DD' } },
        x: { grid: { display: false } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

// ===== Documentos =====
async function loadDocumentos() {
  const container = document.getElementById('docsContainer');
  if (!container) return;

  try {
    const res = await fetch('/api/documentos');
    const data = await res.json();
    if (!res.ok) throw new Error();

    if (!data.documentos || data.documentos.length === 0) {
      container.innerHTML = '<p style="color:var(--text-muted);">Nenhum documento encontrado.</p>';
      return;
    }

    container.innerHTML = data.documentos.map(doc => {
      const isGab = doc.isGabarito;
      const canSee = !isGab || isAdmin() || isCoord();
      const icon = doc.tipo === 'pdf' ? '📄' : '🖼️';
      const lockClass = canSee ? '' : 'doc-locked';
      const gabClass = isGab ? 'gabarito-card' : '';

      return `
        <div class="doc-card ${gabClass} ${lockClass}" onclick="${canSee ? `openDoc('${doc.arquivo}', '${doc.nome.replace(/'/g, "\\'")}')` : 'alert(\\\'Gabaritos disponíveis apenas para administradores.\\\')'}" >
          <div class="doc-icon">${icon}</div>
          <h4>${doc.nome}</h4>
          <p class="doc-cat">${doc.categoria}${isGab ? ' • Gabarito' : ''}</p>
        </div>
      `;
    }).join('');
  } catch {
    container.innerHTML = '<p style="color: var(--accent-red);">Erro ao carregar documentos.</p>';
  }
}

function openDoc(url, titulo) {
  document.getElementById('docViewerTitle').textContent = titulo;
  document.getElementById('docViewerFrame').src = url;
  document.getElementById('docViewerModal').classList.remove('hidden');
}

function closeDocViewer(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('docViewerModal').classList.add('hidden');
  document.getElementById('docViewerFrame').src = '';
}

// ===== README Modal =====
async function openReadmeModal() {
  const modal = document.getElementById('readmeModal');
  const content = document.getElementById('readmeContent');
  document.querySelector('#readmeModal .modal-box-header h3').textContent = '📖 README do Projeto';

  modal.classList.remove('hidden');
  content.innerHTML = '<div class="loading">Carregando README</div>';

  try {
    const res = await fetch('/api/readme');
    const data = await res.json();
    content.innerHTML = renderMarkdown(data.content);
  } catch {
    content.innerHTML = '<p>Erro ao carregar README.</p>';
  }
}

function closeReadmeModal(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('readmeModal').classList.add('hidden');
}

// Simple markdown renderer
function renderMarkdown(md) {
  if (!md) return '';
  return md
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(?!<[hulo])/gm, '')
    .replace(/\n/g, '<br>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}
