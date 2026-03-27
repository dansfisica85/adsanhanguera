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

// Fetch com retry automático para erros transitórios (503, network errors)
async function fetchWithRetry(url, options = {}, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (res.status === 503 && attempt < maxRetries) {
        const waitMs = 1000 * Math.pow(2, attempt - 1);
        console.warn(`⚠️ 503 em ${url}, retentando em ${waitMs}ms (${attempt}/${maxRetries})...`);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      return res;
    } catch (err) {
      if (attempt < maxRetries) {
        const waitMs = 1000 * Math.pow(2, attempt - 1);
        console.warn(`⚠️ Erro de rede em ${url}, retentando em ${waitMs}ms (${attempt}/${maxRetries})...`);
        await new Promise(r => setTimeout(r, waitMs));
      } else {
        throw err;
      }
    }
  }
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
    const res = await fetchWithRetry('/api/auth/me', { headers: authHeaders() });
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
  if (tabId === 'codigo') loadCodeEditor();
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
    const res = await fetchWithRetry(`/api/exercicios/${unidade}`);
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
    const res = await fetchWithRetry('/api/respostas', {
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
    const res = await fetchWithRetry(`/api/respostas/${id}`, {
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
    const res = await fetchWithRetry(`/api/gabarito/${unidade}/${etapa}/${exercicio}`, {
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
    const res = await fetchWithRetry('/api/respostas', { headers: authHeaders() });
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
    const statsRes = await fetchWithRetry('/api/admin/estatisticas', { headers: authHeaders() });
    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('adminTotalAlunos').textContent = stats.totalAlunos;
      document.getElementById('adminTotalRespostas').textContent = stats.totalRespostas;
      document.getElementById('adminMediaGeral').textContent = stats.mediaGeral;

      // Chart
      renderChartUnidades(stats.porUnidade);
    }

    // Alunos list
    const alunosRes = await fetchWithRetry('/api/admin/alunos', { headers: authHeaders() });
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
    const res = await fetchWithRetry(`/api/admin/alunos/${alunoId}/evolucao`, { headers: authHeaders() });
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
    const res = await fetchWithRetry('/api/documentos');
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
    const res = await fetchWithRetry('/api/readme');
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

// ===== CODE EDITOR =====
let currentCodeLang = 'html';
let currentProjectId = null;
let currentCodeUserId = null; // para admin/coord navegar entre alunos
let projetosCache = [];
let adminProjetosCache = []; // projetos do professor visíveis a todos
let viewingAdminProject = false; // se está visualizando projeto do professor

// ===== Monaco Editor =====
let monacoEditors = {};
let monacoReady = false;
let autoRunTimer = null;

function initMonaco(callback) {
  if (monacoReady) { callback(); return; }
  require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs' } });
  require(['vs/editor/editor.main'], function () {
    // Tema escuro personalizado
    monaco.editor.defineTheme('p5Dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '6A9955', fontStyle: 'italic' },
        { token: 'keyword', foreground: 'C586C0' },
        { token: 'string', foreground: 'CE9178' },
        { token: 'number', foreground: 'B5CEA8' },
        { token: 'tag', foreground: '569CD6' },
        { token: 'attribute.name', foreground: '9CDCFE' },
        { token: 'attribute.value', foreground: 'CE9178' },
      ],
      colors: {
        'editor.background': '#1E293B',
        'editor.foreground': '#E2E8F0',
        'editorCursor.foreground': '#F37021',
        'editor.lineHighlightBackground': '#253349',
        'editor.selectionBackground': '#3E5575',
        'editorLineNumber.foreground': '#64748B',
        'editorLineNumber.activeForeground': '#F37021',
      }
    });

    monacoReady = true;
    callback();
  });
}

function createMonacoEditor(containerId, language, value) {
  const container = document.getElementById(containerId);
  if (!container) return null;
  container.innerHTML = '';

  const langMap = { html: 'html', css: 'css', js: 'javascript' };
  const monacoLang = langMap[language] || language;

  const editor = monaco.editor.create(container, {
    value: value || '',
    language: monacoLang,
    theme: 'p5Dark',
    automaticLayout: true,
    fontSize: 14,
    fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
    fontLigatures: true,
    minimap: { enabled: false },
    lineNumbers: 'on',
    roundedSelection: true,
    scrollBeyondLastLine: false,
    wordWrap: 'on',
    tabSize: 2,
    insertSpaces: true,
    formatOnPaste: true,
    formatOnType: true,
    autoClosingBrackets: 'always',
    autoClosingQuotes: 'always',
    autoIndent: 'full',
    suggestOnTriggerCharacters: true,
    quickSuggestions: { other: true, comments: false, strings: true },
    parameterHints: { enabled: true },
    suggest: {
      showKeywords: true,
      showSnippets: true,
      showFunctions: true,
      showVariables: true,
      showClasses: true,
      showMethods: true,
      showProperties: true,
      insertMode: 'replace',
    },
    bracketPairColorization: { enabled: true },
    padding: { top: 12, bottom: 12 },
  });

  // Auto-run com debounce
  editor.onDidChangeModelContent(() => {
    if (document.getElementById('autoRunToggle') && document.getElementById('autoRunToggle').checked) {
      clearTimeout(autoRunTimer);
      autoRunTimer = setTimeout(() => {
        runCode();
        // Atualizar live preview se estiver aberto
        if (livePreviewWindow && !livePreviewWindow.closed) {
          openLivePreview();
        }
      }, 800);
    }
  });

  return editor;
}

function setupMonacoEditors() {
  initMonaco(() => {
    if (!monacoEditors.html) {
      monacoEditors.html = createMonacoEditor('monacoHTML', 'html', '');
      monacoEditors.css = createMonacoEditor('monacoCSS', 'css', '');
      monacoEditors.js = createMonacoEditor('monacoJS', 'js', '');

      // Registrar snippets e completions customizados para JS
      registerCustomCompletions();
    }
    // Forçar layout ao trocar aba
    setTimeout(() => {
      Object.values(monacoEditors).forEach(ed => ed && ed.layout());
    }, 100);
  });
}

function registerCustomCompletions() {
  // Snippets comuns de HTML/CSS/JS para alunos
  monaco.languages.registerCompletionItemProvider('javascript', {
    provideCompletionItems: function (model, position) {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };
      return {
        suggestions: [
          { label: 'console.log', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'console.log(${1:valor});', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Imprime no console', range },
          { label: 'document.getElementById', kind: monaco.languages.CompletionItemKind.Snippet, insertText: "document.getElementById('${1:id}')", insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Seleciona elemento por ID', range },
          { label: 'document.querySelector', kind: monaco.languages.CompletionItemKind.Snippet, insertText: "document.querySelector('${1:seletor}')", insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Seleciona elemento por seletor CSS', range },
          { label: 'addEventListener', kind: monaco.languages.CompletionItemKind.Snippet, insertText: "addEventListener('${1:click}', function(e) {\n\t${2}\n});", insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Adicionar listener de evento', range },
          { label: 'fetch', kind: monaco.languages.CompletionItemKind.Snippet, insertText: "fetch('${1:url}')\n\t.then(res => res.json())\n\t.then(data => {\n\t\t${2:console.log(data);}\n\t})\n\t.catch(err => console.error(err));", insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Requisição HTTP com fetch', range },
          { label: 'for', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'for (let ${1:i} = 0; ${1:i} < ${2:10}; ${1:i}++) {\n\t${3}\n}', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Loop for', range },
          { label: 'forEach', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '${1:array}.forEach((${2:item}) => {\n\t${3}\n});', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Iterar array com forEach', range },
          { label: 'function', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'function ${1:nome}(${2:params}) {\n\t${3}\n}', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Declaração de função', range },
          { label: 'arrow function', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'const ${1:nome} = (${2:params}) => {\n\t${3}\n};', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Arrow function', range },
          { label: 'setTimeout', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'setTimeout(() => {\n\t${1}\n}, ${2:1000});', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Executa após delay', range },
          { label: 'setInterval', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'setInterval(() => {\n\t${1}\n}, ${2:1000});', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Executa periodicamente', range },
        ]
      };
    }
  });

  monaco.languages.registerCompletionItemProvider('html', {
    provideCompletionItems: function (model, position) {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };
      return {
        suggestions: [
          { label: 'html5', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<!DOCTYPE html>\n<html lang="pt-br">\n<head>\n\t<meta charset="UTF-8">\n\t<meta name="viewport" content="width=device-width, initial-scale=1.0">\n\t<title>${1:Título}</title>\n</head>\n<body>\n\t${2}\n</body>\n</html>', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Estrutura HTML5 completa', range },
          { label: 'div', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<div class="${1:classe}">\n\t${2}\n</div>', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Div com classe', range },
          { label: 'button', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<button onclick="${1:funcao()}">${2:Texto}</button>', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Botão com onclick', range },
          { label: 'input', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<input type="${1:text}" id="${2:id}" placeholder="${3:placeholder}" />', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Campo de input', range },
          { label: 'ul>li', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<ul>\n\t<li>${1}</li>\n\t<li>${2}</li>\n</ul>', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Lista não-ordenada', range },
          { label: 'table', kind: monaco.languages.CompletionItemKind.Snippet, insertText: '<table>\n\t<thead>\n\t\t<tr>\n\t\t\t<th>${1:Coluna}</th>\n\t\t</tr>\n\t</thead>\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>${2:Dado}</td>\n\t\t</tr>\n\t</tbody>\n</table>', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, documentation: 'Tabela com thead/tbody', range },
        ]
      };
    }
  });
}

function switchCodeLang(lang) {
  currentCodeLang = lang;
  document.querySelectorAll('.code-lang-tab').forEach(t => t.classList.remove('active'));
  const btn = document.querySelector(`.code-lang-tab[data-lang="${lang}"]`);
  if (btn) btn.classList.add('active');

  document.querySelectorAll('.code-editor-pane').forEach(p => p.classList.remove('active'));
  const pane = document.getElementById(`editor${lang.toUpperCase()}`);
  if (pane) pane.classList.add('active');

  // Atualizar file tree
  document.querySelectorAll('.code-file-tree-item').forEach(i => i.classList.remove('active'));
  const treeItem = document.querySelector(`.code-file-tree-item[data-lang="${lang}"]`);
  if (treeItem) treeItem.classList.add('active');

  // For\u00e7ar layout do editor Monaco ativo
  if (monacoEditors[lang]) {
    setTimeout(() => monacoEditors[lang].layout(), 50);
  }
}

// Helpers para obter/setar valores dos editores
function getEditorValue(lang) {
  if (monacoEditors[lang]) return monacoEditors[lang].getValue();
  return '';
}

function setEditorValue(lang, value) {
  if (monacoEditors[lang]) monacoEditors[lang].setValue(value || '');
}

function setEditorsReadOnly(readOnly) {
  Object.values(monacoEditors).forEach(ed => {
    if (ed) ed.updateOptions({ readOnly });
  });
}

async function loadCodeEditor() {
  const tabArea = document.getElementById('codeUserTabs');

  // Carregar ranking para todos
  loadRanking();

  // Inicializar Monaco e aguardar estar pronto antes de carregar projetos
  await new Promise(resolve => {
    setupMonacoEditors();
    const check = () => {
      if (monacoEditors.html) { resolve(); }
      else { setTimeout(check, 100); }
    };
    if (monacoEditors.html) resolve();
    else check();
  });

  if (isAdmin() || isCoord()) {
    // Carregar lista de alunos como sub-abas
    try {
      const res = await fetchWithRetry('/api/projetos-alunos', { headers: authHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      let html = '<div class="code-user-tabs-container">';
      // Aba "Meus Projetos" para admin
      if (isAdmin()) {
        html += `<button class="code-user-tab active" data-userid="${currentUser.id}" onclick="switchCodeUser(${currentUser.id}, this)">
          <span class="code-user-icon">👤</span> Meus Projetos
        </button>`;
      }
      (data.alunos || []).forEach(a => {
        const isActive = !isAdmin() && a.id === (data.alunos[0] || {}).id ? ' active' : '';
        html += `<button class="code-user-tab${isActive}" data-userid="${a.id}" onclick="switchCodeUser(${a.id}, this)">
          <span class="code-user-icon">👤</span> ${a.nome.split(' ')[0]}
          <span class="code-user-count">${a.total_projetos}</span>
        </button>`;
      });
      html += '</div>';
      tabArea.innerHTML = html;

      // Carregar projetos do primeiro usuário
      const firstUserId = isAdmin() ? currentUser.id : (data.alunos[0] ? data.alunos[0].id : null);
      if (firstUserId) {
        currentCodeUserId = firstUserId;
        await loadUserProjects(firstUserId);
      }
    } catch (err) {
      console.error('Erro ao carregar alunos:', err);
      tabArea.innerHTML = '';
      await loadUserProjects(currentUser.id);
    }
  } else {
    // Aluno: sem sub-abas para outros, carregar direto os próprios projetos + projetos do professor
    tabArea.innerHTML = '';
    currentCodeUserId = currentUser.id;
    await loadUserProjects(currentUser.id);
  }
}

async function switchCodeUser(userId, btn) {
  currentCodeUserId = userId;
  document.querySelectorAll('.code-user-tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  await loadUserProjects(userId);
}

async function loadUserProjects(userId) {
  try {
    let res;
    if ((isAdmin() || isCoord()) && userId !== currentUser.id) {
      res = await fetchWithRetry(`/api/projetos-aluno/${userId}`, { headers: authHeaders() });
    } else {
      res = await fetchWithRetry('/api/projetos', { headers: authHeaders() });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    projetosCache = (data.projetos || []).filter(p => Number(p.aluno_id) === userId);

    // Carregar projetos do professor para alunos
    adminProjetosCache = [];
    if (isAluno()) {
      try {
        const adminRes = await fetchWithRetry('/api/projetos-admin', { headers: authHeaders() });
        const adminData = await adminRes.json();
        if (adminRes.ok) {
          adminProjetosCache = adminData.projetos || [];
        }
      } catch (e) {
        console.error('Erro ao carregar projetos do professor:', e);
      }
    }

    const select = document.getElementById('codeProjectSelect');
    select.innerHTML = '';

    // Grupo "Meus Projetos"
    const myGroup = document.createElement('optgroup');
    myGroup.label = '📁 Meus Projetos';
    const newOpt = document.createElement('option');
    newOpt.value = 'new';
    newOpt.textContent = '+ Novo Projeto';
    myGroup.appendChild(newOpt);
    projetosCache.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.nome + (p.visto ? ' ✅' : '');
      myGroup.appendChild(opt);
    });
    select.appendChild(myGroup);

    // Grupo "Projetos do Professor" (para alunos)
    if (adminProjetosCache.length > 0) {
      const profGroup = document.createElement('optgroup');
      profGroup.label = '👨‍🏫 Projetos do Professor';
      adminProjetosCache.forEach(p => {
        const opt = document.createElement('option');
        opt.value = 'admin_' + p.id;
        opt.textContent = p.nome;
        profGroup.appendChild(opt);
      });
      select.appendChild(profGroup);
    }

    // Renderizar badges de visto na file tree
    renderVistoFileTree();

    // Se há projetos, selecionar o primeiro
    if (projetosCache.length > 0) {
      select.value = projetosCache[0].id;
      viewingAdminProject = false;
      loadProjectIntoEditor(projetosCache[0]);
    } else if (adminProjetosCache.length > 0 && isAluno()) {
      select.value = 'admin_' + adminProjetosCache[0].id;
      viewingAdminProject = true;
      loadProjectIntoEditor(adminProjetosCache[0]);
    } else {
      select.value = 'new';
      viewingAdminProject = false;
      clearEditor();
    }

    updateEditorPermissions();
  } catch (err) {
    console.error('Erro ao carregar projetos:', err);
  }
}

function loadProjectIntoEditor(projeto) {
  currentProjectId = projeto.id;
  document.getElementById('codeProjectName').value = projeto.nome;
  setEditorValue('html', projeto.html);
  setEditorValue('css', projeto.css);
  setEditorValue('js', projeto.js);

  // Renderizar botão de visto
  renderVistoButton(projeto);

  const canDel = canMutate() && !viewingAdminProject;
  document.getElementById('btnDeleteProjeto').style.display = canDel ? '' : 'none';

  // Atualizar nome no file tree
  const treeProjectName = document.getElementById('fileTreeProjectName');
  if (treeProjectName) {
    treeProjectName.querySelector('.file-tree-folder').textContent = '📂 ' + projeto.nome;
  }

  updateEditorPermissions();
  runCode();
}

function clearEditor() {
  currentProjectId = null;
  document.getElementById('codeProjectName').value = 'Meu Projeto';
  setEditorValue('html', '');
  setEditorValue('css', '');
  setEditorValue('js', '');
  document.getElementById('btnDeleteProjeto').style.display = 'none';
  const iframe = document.getElementById('codePreview');
  if (iframe) iframe.srcdoc = '';
  clearConsole();

  // Atualizar nome no file tree
  const treeProjectName = document.getElementById('fileTreeProjectName');
  if (treeProjectName) {
    treeProjectName.querySelector('.file-tree-folder').textContent = '📂 Meu Projeto';
  }
}

function updateEditorPermissions() {
  const isOwner = currentCodeUserId === currentUser.id;
  const canEdit = !viewingAdminProject && (isAdmin() || (isAluno() && isOwner));
  setEditorsReadOnly(!canEdit);
  document.getElementById('codeProjectName').readOnly = !canEdit;

  // Esconder botões de ação se não pode editar
  const saveBtn = document.querySelector('.code-project-actions .btn-primary');
  if (saveBtn) saveBtn.style.display = canEdit ? '' : 'none';
  document.getElementById('btnDeleteProjeto').style.display = canEdit && currentProjectId ? '' : 'none';

  // Mostrar label quando em modo read-only de projeto do professor
  let readOnlyLabel = document.getElementById('readOnlyLabel');
  if (viewingAdminProject) {
    if (!readOnlyLabel) {
      readOnlyLabel = document.createElement('span');
      readOnlyLabel.id = 'readOnlyLabel';
      readOnlyLabel.className = 'read-only-label';
      readOnlyLabel.textContent = '👁 Modo Visualização (Projeto do Professor)';
      const projectInfo = document.querySelector('.code-project-info');
      if (projectInfo) projectInfo.appendChild(readOnlyLabel);
    }
    readOnlyLabel.style.display = '';
  } else if (readOnlyLabel) {
    readOnlyLabel.style.display = 'none';
  }
}

// Evento ao trocar de projeto no select
document.addEventListener('DOMContentLoaded', () => {
  const select = document.getElementById('codeProjectSelect');
  if (select) {
    select.addEventListener('change', function () {
      if (this.value === 'new') {
        viewingAdminProject = false;
        clearEditor();
        updateEditorPermissions();
      } else if (this.value.startsWith('admin_')) {
        const adminId = parseInt(this.value.replace('admin_', ''));
        const projeto = adminProjetosCache.find(p => p.id === adminId);
        if (projeto) {
          viewingAdminProject = true;
          loadProjectIntoEditor(projeto);
        }
      } else {
        viewingAdminProject = false;
        const projeto = projetosCache.find(p => String(p.id) === this.value);
        if (projeto) loadProjectIntoEditor(projeto);
      }
    });
  }

  // Sincronizar nome do projeto com file tree
  const nameInput = document.getElementById('codeProjectName');
  if (nameInput) {
    nameInput.addEventListener('input', function () {
      const treeProjectName = document.getElementById('fileTreeProjectName');
      if (treeProjectName) {
        treeProjectName.querySelector('.file-tree-folder').textContent = '📂 ' + (this.value || 'Meu Projeto');
      }
    });
  }
});

function runCode() {
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');

  clearConsole();

  // Script injetado no iframe para capturar console e erros
  const consoleCapture = `
<script>
(function(){
  var _origLog = console.log, _origWarn = console.warn,
      _origError = console.error, _origInfo = console.info;
  function send(type, args) {
    try {
      var parts = [];
      for (var i = 0; i < args.length; i++) {
        var a = args[i];
        if (typeof a === 'object') {
          try { parts.push(JSON.stringify(a, null, 2)); } catch(e) { parts.push(String(a)); }
        } else { parts.push(String(a)); }
      }
      parent.postMessage({ _consoleMsg: true, type: type, text: parts.join(' ') }, '*');
    } catch(e){}
  }
  console.log = function(){ send('log', arguments); _origLog.apply(console, arguments); };
  console.warn = function(){ send('warn', arguments); _origWarn.apply(console, arguments); };
  console.error = function(){ send('error', arguments); _origError.apply(console, arguments); };
  console.info = function(){ send('info', arguments); _origInfo.apply(console, arguments); };
  window.onerror = function(msg, url, line, col) {
    send('error', ['Erro: ' + msg + ' (linha ' + line + ')']);
  };
  window.addEventListener('unhandledrejection', function(e) {
    send('error', ['Promise rejeitada: ' + (e.reason || e)]);
  });
})();
<\\/script>`;

  const fullCode = '<!DOCTYPE html>\\n<html>\\n<head><meta charset="UTF-8"><style>'
    + css + '</style></head>\\n<body>'
    + html + consoleCapture + '<script>' + js + '<\\/script></body>\\n</html>';

  const iframe = document.getElementById('codePreview');
  iframe.srcdoc = fullCode;
}

// Listener para mensagens do console do iframe
window.addEventListener('message', function (e) {
  if (e.data && e.data._consoleMsg) {
    appendConsole(e.data.type, e.data.text);
  }
});

function appendConsole(type, text) {
  const consoleEl = document.getElementById('codeConsole');
  if (!consoleEl) return;
  const line = document.createElement('div');
  line.className = 'console-line console-' + type;

  const icon = { log: '›', warn: '⚠', error: '✕', info: 'ℹ' }[type] || '›';
  line.innerHTML = '<span class="console-icon">' + icon + '</span><span class="console-text"></span>';
  line.querySelector('.console-text').textContent = text;

  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function clearConsole() {
  const consoleEl = document.getElementById('codeConsole');
  if (consoleEl) consoleEl.innerHTML = '';
}

async function salvarProjeto() {
  const nome = document.getElementById('codeProjectName').value.trim() || 'Meu Projeto';
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');

  try {
    let res;
    if (currentProjectId) {
      res = await fetchWithRetry(`/api/projetos/${currentProjectId}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({ nome, html, css, js }),
      });
    } else {
      res = await fetchWithRetry('/api/projetos', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ nome, html, css, js }),
      });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    if (data.id) currentProjectId = data.id;

    // Recarregar lista de projetos
    await loadUserProjects(currentCodeUserId || currentUser.id);

    // Selecionar o projeto salvo
    if (currentProjectId) {
      document.getElementById('codeProjectSelect').value = currentProjectId;
    }

    showCodeNotification('Projeto salvo com sucesso!', 'success');
  } catch (err) {
    showCodeNotification('Erro ao salvar: ' + err.message, 'error');
  }
}

async function deletarProjeto() {
  if (!currentProjectId) return;
  if (!confirm('Tem certeza que deseja excluir este projeto?')) return;

  try {
    const res = await fetchWithRetry(`/api/projetos/${currentProjectId}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error);
    }
    clearEditor();
    await loadUserProjects(currentCodeUserId || currentUser.id);
    showCodeNotification('Projeto excluído.', 'success');
  } catch (err) {
    showCodeNotification('Erro ao excluir: ' + err.message, 'error');
  }
}

function downloadProjeto() {
  const nome = document.getElementById('codeProjectName').value.trim() || 'projeto';
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');

  // Criar ZIP com os 3 arquivos usando JSZip-like approach (blob separados)
  const sanitizedName = nome.replace(/[^a-zA-Z0-9_-]/g, '_');

  // Gerar index.html com links para css e js
  const fullHtml = `<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${nome}</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
${html}
  <script src="script.js"><\/script>
</body>
</html>`;

  // Baixar os 3 arquivos individualmente
  downloadBlob(fullHtml, `${sanitizedName}/index.html`, 'text/html');
  setTimeout(() => downloadBlob(css, `${sanitizedName}/style.css`, 'text/css'), 200);
  setTimeout(() => downloadBlob(js, `${sanitizedName}/script.js`, 'text/javascript'), 400);
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadSingleFile(type) {
  const nome = document.getElementById('codeProjectName').value.trim() || 'projeto';
  const sanitizedName = nome.replace(/[^a-zA-Z0-9_-]/g, '_');

  if (type === 'html') {
    const html = getEditorValue('html');
    const css = getEditorValue('css');
    const js = getEditorValue('js');
    const fullHtml = `<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${nome}</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
${html}
  <script src="script.js"><\/script>
</body>
</html>`;
    downloadBlob(fullHtml, 'index.html', 'text/html');
  } else if (type === 'css') {
    downloadBlob(getEditorValue('css'), 'style.css', 'text/css');
  } else if (type === 'js') {
    downloadBlob(getEditorValue('js'), 'script.js', 'text/javascript');
  }
}

// ===== Live Server Preview =====
let livePreviewWindow = null;

function openLivePreview() {
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');
  const nome = document.getElementById('codeProjectName').value.trim() || 'Meu Projeto';

  const fullCode = `<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${nome} — Live Server</title>
  <style>${css}</style>
</head>
<body>
${html}
  <script>${js}<\/script>
</body>
</html>`;

  // Se a janela j\u00e1 existe e est\u00e1 aberta, atualizar conte\u00fado
  if (livePreviewWindow && !livePreviewWindow.closed) {
    livePreviewWindow.document.open();
    livePreviewWindow.document.write(fullCode);
    livePreviewWindow.document.close();
    livePreviewWindow.focus();
  } else {
    // Abrir nova janela
    livePreviewWindow = window.open('', '_blank');
    if (livePreviewWindow) {
      livePreviewWindow.document.open();
      livePreviewWindow.document.write(fullCode);
      livePreviewWindow.document.close();
    }
  }

  // Executar tamb\u00e9m no iframe oculto para captura de console
  runCode();
  showCodeNotification('Live Server aberto no navegador!', 'success');
}

function showCodeNotification(msg, type) {
  const existing = document.querySelector('.code-notification');
  if (existing) existing.remove();

  const div = document.createElement('div');
  div.className = `code-notification code-notification-${type}`;
  div.textContent = msg;
  document.getElementById('codeEditorArea').prepend(div);
  setTimeout(() => div.remove(), 3000);
}

// ===== VISTO (aprovação do professor) =====

function renderVistoButton(projeto) {
  let container = document.getElementById('vistoContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'vistoContainer';
    const projectHeader = document.querySelector('.code-project-header');
    if (projectHeader) projectHeader.appendChild(container);
  }
  if (!projeto || !projeto.id) {
    container.innerHTML = '';
    return;
  }
  const isVisto = projeto.visto ? true : false;
  const canToggle = isAdmin();
  container.innerHTML = `
    <button class="btn-visto ${isVisto ? 'active' : 'pending'}" 
            ${canToggle ? `onclick="toggleVisto(${projeto.id})"` : ''} 
            ${canToggle ? '' : 'style="cursor:default;"'}
            title="${canToggle ? 'Clique para alternar o visto' : (isVisto ? 'Aprovado pelo professor' : 'Aguardando aprovação')}">
      ${isVisto ? '✓ VISTO' : '⬜ Pendente'}
    </button>
  `;
}

function renderVistoFileTree() {
  const treeFiles = document.querySelector('.code-file-tree-files');
  if (!treeFiles) return;
  // Remover badges anteriores
  treeFiles.querySelectorAll('.visto-badge-tree').forEach(el => el.remove());

  // Se há um projeto carregado e tem visto, mostrar badge no file tree
  if (currentProjectId) {
    const projeto = projetosCache.find(p => p.id === currentProjectId) || adminProjetosCache.find(p => p.id === currentProjectId);
    if (projeto && projeto.visto) {
      const badge = document.createElement('div');
      badge.className = 'visto-badge-tree';
      badge.textContent = '✓ Aprovado';
      const treeHeader = document.querySelector('.code-file-tree-header');
      if (treeHeader) treeHeader.appendChild(badge);
    }
  }
}

async function toggleVisto(projetoId) {
  if (!isAdmin()) return;
  try {
    const res = await fetchWithRetry(`/api/projetos/${projetoId}/visto`, {
      method: 'PUT',
      headers: authHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    // Atualizar no cache
    const projeto = projetosCache.find(p => p.id === projetoId);
    if (projeto) projeto.visto = data.visto;
    const adminProjeto = adminProjetosCache.find(p => p.id === projetoId);
    if (adminProjeto) adminProjeto.visto = data.visto;

    // Re-renderizar o botão de visto e o select
    const currentProjeto = projeto || adminProjeto;
    if (currentProjeto) renderVistoButton(currentProjeto);

    // Atualizar o texto no select
    const select = document.getElementById('codeProjectSelect');
    if (select) {
      const opt = select.querySelector(`option[value="${projetoId}"]`);
      if (opt) {
        const baseName = opt.textContent.replace(' ✅', '');
        opt.textContent = baseName + (data.visto ? ' ✅' : '');
      }
    }

    showCodeNotification(data.visto ? 'Visto aplicado!' : 'Visto removido.', 'success');
  } catch (err) {
    showCodeNotification('Erro ao atualizar visto: ' + err.message, 'error');
  }
}

// ===== RANKING =====

async function loadRanking() {
  const section = document.getElementById('rankingSection');
  if (!section) return;

  try {
    const res = await fetchWithRetry('/api/ranking', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    const ranking = data.ranking || [];
    if (ranking.length === 0) {
      section.style.display = 'none';
      return;
    }

    const medals = ['🥇', '🥈', '🥉'];

    let html = `
      <div class="ranking-header">
        <h3>🏆 Ranking dos Alunos</h3>
        <button class="btn btn-sm btn-outline ranking-toggle" onclick="toggleRankingView()">Minimizar</button>
      </div>
      <div id="rankingBody" class="ranking-body">
        <table class="ranking-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Aluno</th>
              <th>Projetos</th>
              <th>Linhas</th>
              <th>Palavras</th>
            </tr>
          </thead>
          <tbody>
    `;

    ranking.forEach((aluno, i) => {
      const medal = medals[i] || (i + 1);
      const medalClass = i < 3 ? `ranking-top-${i + 1}` : '';
      html += `
        <tr class="${medalClass}">
          <td class="ranking-pos">${typeof medal === 'string' ? medal : medal + 'º'}</td>
          <td class="ranking-name">${aluno.nome}</td>
          <td>${aluno.totalProjetos}</td>
          <td>${aluno.totalLinhas.toLocaleString('pt-BR')}</td>
          <td>${aluno.totalPalavras.toLocaleString('pt-BR')}</td>
        </tr>
      `;
    });

    html += '</tbody></table></div>';
    section.innerHTML = html;
    section.style.display = '';
  } catch (err) {
    console.error('Erro ao carregar ranking:', err);
    section.style.display = 'none';
  }
}

function toggleRankingView() {
  const body = document.getElementById('rankingBody');
  const btn = document.querySelector('.ranking-toggle');
  if (!body || !btn) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    btn.textContent = 'Minimizar';
  } else {
    body.style.display = 'none';
    btn.textContent = 'Expandir';
  }
}
