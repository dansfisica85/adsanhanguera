// ===== Estado da Aplicação =====
let authToken = null;
let currentUser = null;
let currentTab = 'codigo';
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

function isEspecial() {
  return currentUser && currentUser.role === 'especial';
}

function getRoleLabel(role) {
  const labels = {
    admin: 'Administrador',
    coordenador: 'Coordenador',
    aluno: 'Aluno',
    especial: 'ALUNA ESPECIAL',
  };
  return labels[role] || 'Perfil sem permissão';
}

function canSeeAdmin() {
  return isAdmin() || (isCoord() && coordView);
}

function canMutateResponses() {
  return isAdmin() || isAluno();
}

function canViewStudentProjects() {
  return isAdmin() || isCoord() || isEspecial();
}

function canCreateOwnProjects() {
  return isAdmin() || isAluno() || isEspecial();
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
  document.getElementById('registerForm').addEventListener('submit', handleRegister);

  document.getElementById('btnShowRegister').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('loginForm').classList.add('hidden');
    document.getElementById('registerForm').classList.remove('hidden');
    document.getElementById('btnShowRegister').classList.add('hidden');
    document.getElementById('btnShowLogin').classList.remove('hidden');
    document.getElementById('loginError').classList.add('hidden');
  });

  document.getElementById('btnShowLogin').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('registerForm').classList.add('hidden');
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('btnShowLogin').classList.add('hidden');
    document.getElementById('btnShowRegister').classList.remove('hidden');
    document.getElementById('registerError').classList.add('hidden');
  });
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

// ===== Registro (Criar Perfil) =====
async function handleRegister(e) {
  e.preventDefault();
  const nome = document.getElementById('registerNome').value.trim();
  const email = document.getElementById('registerEmail').value.trim();
  const senha = document.getElementById('registerSenha').value;
  const errorEl = document.getElementById('registerError');

  if (!nome || !email || !senha) {
    errorEl.textContent = 'Nome completo, e-mail e senha são obrigatórios.';
    errorEl.classList.remove('hidden');
    return;
  }

  // Validar se inseriu o nome completo (pelo menos duas palavras)
  const nomeParts = nome.split(/\s+/);
  if (nomeParts.length < 2) {
    errorEl.textContent = 'Por favor, digite seu nome completo (nome e sobrenome).';
    errorEl.classList.remove('hidden');
    return;
  }

  // Validar formato de e-mail básico
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    errorEl.textContent = 'Por favor, insira um e-mail válido.';
    errorEl.classList.remove('hidden');
    return;
  }

  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.querySelector('span').textContent = 'Criando perfil...';
  errorEl.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nome, email, senha }),
    });

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      const text = await res.text();
      console.error('Resposta não-JSON do servidor:', text.substring(0, 200));
      throw new Error('Erro de servidor. Tente novamente em instantes.');
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erro ao criar perfil.');

    authToken = data.token;
    currentUser = data.user;
    localStorage.setItem('adsToken', authToken);
    localStorage.setItem('adsUser', JSON.stringify(currentUser));
    showApp();
    
    // Limpar o formulário de registro para caso façam logout posteriormente
    document.getElementById('registerForm').reset();
    document.getElementById('registerForm').classList.add('hidden');
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('btnShowLogin').classList.add('hidden');
    document.getElementById('btnShowRegister').classList.remove('hidden');
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'Criar Perfil';
  }
}

function showApp() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  // Mostrar botão da IA nas outras páginas
  const aiBtn = document.getElementById('aiChatToggleBtn');
  if (aiBtn) aiBtn.classList.remove('hidden');

  // User info
  document.getElementById('userNameDisplay').textContent = currentUser.nome;

  // Role badge
  const badge = document.getElementById('roleBadge');
  badge.textContent = getRoleLabel(currentUser.role);
  badge.className = 'role-badge ' + currentUser.role;

  // Coord toggle
  document.getElementById('coordToggle').classList.toggle('hidden', !isCoord());

  // Admin tab visibility
  if (isAdmin()) {
    document.getElementById('tabAdmin').style.display = '';
  } else if (isCoord()) {
    document.getElementById('tabAdmin').style.display = coordView ? '' : 'none';
  } else {
    document.getElementById('tabAdmin').style.display = 'none';
  }

  // Load data
  loadExercicios(1);
  loadRespostasAluno();
  loadProfileData();

  if (canSeeAdmin()) {
    loadAdminData();
  }

  // Garante o carregamento automático da tela inicial de códigos após o login
  switchTab('codigo');
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
  
  // Ocultar aba admin
  document.getElementById('tabAdmin').style.display = 'none';

  // Reset do formulário de cadastro
  document.getElementById('registerForm').reset();
  document.getElementById('registerError').classList.add('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('loginForm').classList.remove('hidden');
  document.getElementById('btnShowLogin').classList.add('hidden');
  document.getElementById('btnShowRegister').classList.remove('hidden');

  // Esconder botão da IA na página de login
  const aiBtn = document.getElementById('aiChatToggleBtn');
  if (aiBtn) aiBtn.classList.add('hidden');

  // Fechar o painel de chat da IA se estiver aberto
  const aiPanel = document.getElementById('aiChatPanel');
  if (aiPanel) aiPanel.classList.remove('ai-open');
  aiChatIsOpen = false;

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
function toggleUnidadesMenu() {
  const menu = document.getElementById('unidadesMenu');
  const toggle = document.querySelector('.tab-dropdown-toggle');
  menu.classList.toggle('show');
  toggle.classList.toggle('open');
}

document.addEventListener('click', function(e) {
  const dropdown = document.querySelector('.tab-dropdown');
  if (dropdown && !dropdown.contains(e.target)) {
    document.getElementById('unidadesMenu').classList.remove('show');
    document.querySelector('.tab-dropdown-toggle').classList.remove('open');
  }
});

function switchTab(tabId) {
  currentTab = tabId;

  // Fechar dropdown de unidades
  const menu = document.getElementById('unidadesMenu');
  if (menu) menu.classList.remove('show');
  const toggle = document.querySelector('.tab-dropdown-toggle');
  if (toggle) toggle.classList.remove('open');

  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const tabBtn = document.querySelector(`.tab[data-tab="${tabId}"]`);
  if (tabBtn) tabBtn.classList.add('active');

  // Marcar item ativo dentro do dropdown
  document.querySelectorAll('.tab-dropdown-menu button').forEach(b => b.classList.remove('active-unit'));
  const unitBtn = document.querySelector(`.tab-dropdown-menu button[data-tab="${tabId}"]`);
  if (unitBtn) {
    unitBtn.classList.add('active-unit');
    if (toggle) toggle.classList.add('active');
  }

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
        if (canMutateResponses()) {
          html += `<button class="btn btn-sm btn-outline" onclick="reDoExercise('${respKey}', ${unidade}, ${etapaKey}, ${exKey})">Refazer</button>`;
        }
        // Gabarito button
        html += `<button class="btn btn-sm btn-outline" onclick="verGabarito(${unidade}, ${etapaKey}, ${exKey})">Ver Gabarito</button>`;
        if (canMutateResponses() && resposta.id) {
          html += `<button class="btn btn-sm btn-danger" onclick="deleteResposta(${resposta.id}, '${respKey}', ${unidade})">Excluir</button>`;
        }
        html += `</div>`;
      } else if (canMutateResponses()) {
        html += renderExerciseForm(unidade, etapaKey, exKey);
      } else {
        html += '<p class="exercise-read-only">Conteúdo disponível para consulta neste perfil.</p>';
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
  if (!canMutateResponses()) return;
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
  if (!canMutateResponses()) return;
  delete respostasCache[respKey];
  renderExercicios(
    document.getElementById(`exercises-${unidade}`),
    unidade,
    exerciciosCache[unidade]
  );
}

// ===== Delete Resposta =====
async function deleteResposta(id, respKey, unidade) {
  if (!canMutateResponses()) return;
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
  roleEl.textContent = getRoleLabel(currentUser.role);
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

  container.innerHTML = (alunos || []).map(a => {
    let deleteBtnHtml = '';
    if (isAdmin()) {
      deleteBtnHtml = `
        <button class="btn btn-sm btn-danger" 
                onclick="event.stopPropagation(); deleteAluno(${a.id}, '${a.nome.replace(/'/g, "\\'")}')" 
                title="Excluir aluno"
                style="margin-top: 8px; width: 100%; display: flex; align-items: center; justify-content: center; gap: 4px;">
          🗑️ Excluir Perfil
        </button>
      `;
    }
    return `
      <div class="aluno-card" onclick="loadEvolucao(${a.id}, '${a.nome.replace(/'/g, "\\'")}')">
        <h4>${a.nome}</h4>
        <p class="aluno-email">${a.email}</p>
        <div class="aluno-stats">
          <span class="aluno-stat">Respostas: <strong>${a.total_respostas}</strong></span>
          <span class="aluno-stat">Média: <strong>${(Math.round(Number(a.media_nota) * 10) / 10).toFixed(1)}</strong></span>
        </div>
        ${deleteBtnHtml}
      </div>
    `;
  }).join('');
}

async function deleteAluno(alunoId, nome) {
  if (!confirm(`Tem certeza que deseja excluir permanentemente o perfil de "${nome}"? Esta ação não pode ser desfeita e excluirá todas as respostas e projetos salvos desse aluno.`)) {
    return;
  }

  try {
    const res = await fetchWithRetry(`/api/admin/alunos/${alunoId}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erro ao excluir perfil.');

    alert(data.message || 'Perfil excluído com sucesso.');
    
    // Recarregar os dados do painel admin
    loadAdminData();
    
    // Ocultar a seção de evolução caso o aluno deletado esteja selecionado
    const evolucaoNomeEl = document.getElementById('evolucaoNome');
    if (evolucaoNomeEl && evolucaoNomeEl.textContent === nome) {
      document.getElementById('adminEvolucao').classList.add('hidden');
      if (chartEvolucao) {
        chartEvolucao.destroy();
        chartEvolucao = null;
      }
    }
  } catch (err) {
    alert('Erro: ' + err.message);
  }
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

    if (!data.pastas || data.pastas.length === 0) {
      container.innerHTML = '<p style="color:var(--text-muted);">Nenhum documento encontrado.</p>';
      return;
    }

    container.innerHTML = data.pastas.map(pasta => {
      const filesHtml = pasta.arquivos.map(doc => {
        const isGab = doc.isGabarito;
        const canSee = !isGab || isAdmin() || isCoord();
        const icon = doc.tipo === 'pdf' ? '📄' : '🖼️';
        const lockClass = canSee ? '' : 'doc-locked';
        const gabLabel = isGab ? ' • Gabarito' : '';

        return `
          <div class="doc-file ${lockClass}" onclick="${canSee ? `openDoc('${doc.arquivo}', '${doc.nome.replace(/'/g, "\\'")}')` : 'alert(\\\'Gabaritos disponíveis apenas para administradores.\\\')'}">
            <span class="doc-file-icon">${icon}</span>
            <span class="doc-file-name">${doc.nome}${gabLabel}</span>
          </div>`;
      }).join('');

      return `
        <div class="folder-card folder-${pasta.cor}" onclick="toggleFolder(this, event)">
          <div class="folder-header">
            <span class="folder-icon">📁</span>
            <div class="folder-info">
              <h4>${pasta.label}</h4>
              <p class="folder-count">${pasta.arquivos.length} arquivo${pasta.arquivos.length !== 1 ? 's' : ''}</p>
            </div>
            <span class="folder-arrow">▶</span>
          </div>
          <div class="folder-files">${filesHtml}</div>
        </div>`;
    }).join('');
  } catch {
    container.innerHTML = '<p style="color: var(--accent-red);">Erro ao carregar documentos.</p>';
  }
}

function toggleFolder(el, e) {
  if (e.target.closest('.doc-file')) return;
  el.classList.toggle('folder-open');
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

// Modern markdown renderer using marked library
function renderMarkdown(md) {
  if (!md) return '';
  if (typeof marked !== 'undefined') {
    const parseFn = (typeof marked.parse === 'function') ? marked.parse.bind(marked) : marked;
    let processedMd = md;
    
    // Process <div align="center"> blocks to render markdown inside them
    processedMd = processedMd.replace(/<div align="center">([\s\S]*?)<\/div>/g, (match, p1) => {
      return '<div style="text-align: center;">' + parseFn(p1) + '</div>';
    });
    
    return parseFn(processedMd);
  }
  
  // Fallback to simple parser if marked failed to load
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

function isOwnCodeView() {
  return Boolean(currentUser) && Number(currentCodeUserId) === Number(currentUser.id);
}

function canEditCurrentProject() {
  if (viewingAdminProject || !currentUser) return false;
  if (isAdmin()) return true;
  return (isAluno() || isEspecial()) && isOwnCodeView();
}

function canCreateProjectInCurrentView() {
  return canCreateOwnProjects() && isOwnCodeView() && !viewingAdminProject;
}

// Imagens do projeto: { 'nome.png': 'data:image/png;base64,...' }
let projectAssets = {};

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

    // Tema claro personalizado (fundo claro)
    monaco.editor.defineTheme('p5Light', {
      base: 'vs',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '008000', fontStyle: 'italic' },
        { token: 'keyword', foreground: 'AF00DB' },
        { token: 'string', foreground: 'A31515' },
        { token: 'number', foreground: '098658' },
        { token: 'tag', foreground: '0000FF' },
        { token: 'attribute.name', foreground: 'E50000' },
        { token: 'attribute.value', foreground: 'A31515' },
      ],
      colors: {
        'editor.background': '#FFFFFF',
        'editor.foreground': '#1E293B',
        'editorCursor.foreground': '#F37021',
        'editor.lineHighlightBackground': '#FFF4EC',
        'editor.selectionBackground': '#FCD9BF',
        'editorLineNumber.foreground': '#94A3B8',
        'editorLineNumber.activeForeground': '#F37021',
        'editorIndentGuide.background': '#E2E8F0',
      }
    });

    monacoReady = true;
    callback();
  });
}

// Tema atual do editor (claro por padrão) e tamanho da fonte (zoom)
let currentEditorTheme = localStorage.getItem('editorTheme') || 'p5Light';
let editorFontSize = parseInt(localStorage.getItem('editorFontSize') || '15', 10);

function createMonacoEditor(containerId, language, value) {
  const container = document.getElementById(containerId);
  if (!container) return null;
  container.innerHTML = '';

  const langMap = { html: 'html', css: 'css', js: 'javascript', py: 'python' };
  const monacoLang = langMap[language] || language;

  const editor = monaco.editor.create(container, {
    value: value || '',
    language: monacoLang,
    theme: currentEditorTheme,
    automaticLayout: true,
    fontSize: editorFontSize,
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
    autoClosingTags: true,
    autoIndent: 'full',
    suggestOnTriggerCharacters: true,
    acceptSuggestionOnEnter: 'on',
    tabCompletion: 'on',
    wordBasedSuggestions: 'allDocuments',
    quickSuggestions: { other: true, comments: true, strings: true },
    quickSuggestionsDelay: 10,
    parameterHints: { enabled: true, cycle: true },
    suggestSelection: 'recentlyUsedByPrefix',
    snippetSuggestions: 'top',
    suggest: {
      showKeywords: true,
      showSnippets: true,
      showFunctions: true,
      showVariables: true,
      showClasses: true,
      showMethods: true,
      showProperties: true,
      showFields: true,
      showConstants: true,
      showColors: true,
      showWords: true,
      showStatusBar: true,
      preview: true,
      insertMode: 'replace',
      filterGraceful: true,
      localityBonus: true,
    },
    hover: { enabled: true, delay: 200 },
    bracketPairColorization: { enabled: true },
    guides: { bracketPairs: true, indentation: true },
    stickyScroll: { enabled: true },
    padding: { top: 12, bottom: 12 },
  });

  // Auto-run com debounce
  editor.onDidChangeModelContent(() => {
    if (document.getElementById('autoRunToggle') && document.getElementById('autoRunToggle').checked) {
      clearTimeout(autoRunTimer);
      autoRunTimer = setTimeout(() => {
        runCode();
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
      monacoEditors.py = createMonacoEditor('monacoPY', 'py', '');

      // Registrar snippets e completions customizados para JS
      registerCustomCompletions();
    }
    // Configurar área de arrastar-e-soltar arquivos
    setupCodeDropZone();
    // Forçar layout ao trocar aba
    setTimeout(() => {
      Object.values(monacoEditors).forEach(ed => ed && ed.layout());
    }, 100);
    // Sincronizar UI de zoom/tema
    updateZoomLabel();
    const tBtn = document.getElementById('btnToggleTheme');
    if (tBtn) tBtn.textContent = currentEditorTheme === 'p5Light' ? '🌙' : '☀️';
    const layout = document.querySelector('.code-ide-layout');
    if (layout) layout.classList.toggle('editor-dark', currentEditorTheme === 'p5Dark');
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

  // ===== CSS: snippets de propriedades comuns =====
  monaco.languages.registerCompletionItemProvider('css', {
    provideCompletionItems: function (model, position) {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };
      const snip = (label, insertText, documentation) => ({
        label, kind: monaco.languages.CompletionItemKind.Snippet,
        insertText, insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
        documentation, range,
      });
      return {
        suggestions: [
          snip('flex-center', 'display: flex;\njustify-content: center;\nalign-items: center;', 'Centralizar com flexbox'),
          snip('grid-template', 'display: grid;\ngrid-template-columns: repeat(${1:3}, 1fr);\ngap: ${2:16px};', 'Layout em grid'),
          snip('transition', 'transition: ${1:all} ${2:0.3s} ${3:ease};', 'Transição suave'),
          snip('box-shadow', 'box-shadow: ${1:0} ${2:4px} ${3:12px} rgba(0,0,0,${4:0.15});', 'Sombra'),
          snip('border-radius', 'border-radius: ${1:8px};', 'Cantos arredondados'),
          snip('media-query', '@media (max-width: ${1:768px}) {\n\t${2}\n}', 'Media query responsiva'),
          snip('keyframes', '@keyframes ${1:nome} {\n\tfrom { ${2:opacity: 0;} }\n\tto { ${3:opacity: 1;} }\n}', 'Animação @keyframes'),
          snip('gradient', 'background: linear-gradient(${1:135deg}, ${2:#F37021}, ${3:#FF9A56});', 'Gradiente linear'),
          snip('reset', '* {\n\tmargin: 0;\n\tpadding: 0;\n\tbox-sizing: border-box;\n}', 'Reset básico'),
        ]
      };
    }
  });

  // ===== Completions Python =====
  monaco.languages.registerCompletionItemProvider('python', {
    provideCompletionItems: function (model, position) {
      const word = model.getWordUntilPosition(position);
      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };
      const snip = (label, insertText, documentation) => ({
        label, kind: monaco.languages.CompletionItemKind.Snippet,
        insertText, insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
        documentation, range,
      });
      return {
        suggestions: [
          snip('print', 'print(${1:valor})', 'Imprime no console'),
          snip('def', 'def ${1:funcao}(${2:args}):\n\t${3:pass}', 'Define uma função'),
          snip('for', 'for ${1:item} in ${2:iteravel}:\n\t${3:pass}', 'Loop for'),
          snip('forrange', 'for ${1:i} in range(${2:10}):\n\t${3:pass}', 'Loop for com range'),
          snip('while', 'while ${1:condicao}:\n\t${2:pass}', 'Loop while'),
          snip('if', 'if ${1:condicao}:\n\t${2:pass}', 'Condição if'),
          snip('ifelse', 'if ${1:condicao}:\n\t${2:pass}\nelse:\n\t${3:pass}', 'Condição if/else'),
          snip('elif', 'elif ${1:condicao}:\n\t${2:pass}', 'Condição elif'),
          snip('class', 'class ${1:Nome}:\n\tdef __init__(self${2:, args}):\n\t\t${3:pass}', 'Define uma classe'),
          snip('try', 'try:\n\t${1:pass}\nexcept ${2:Exception} as e:\n\t${3:print(e)}', 'Tratamento de exceção'),
          snip('import', 'import ${1:modulo}', 'Importa um módulo'),
          snip('fromimport', 'from ${1:modulo} import ${2:nome}', 'Importa de um módulo'),
          snip('input', "${1:valor} = input('${2:Digite}')", 'Lê entrada do usuário'),
          snip('len', 'len(${1:objeto})', 'Tamanho de um objeto'),
          snip('range', 'range(${1:0}, ${2:10})', 'Sequência de números'),
          snip('lambda', 'lambda ${1:x}: ${2:x}', 'Função anônima'),
          snip('listcomp', '[${1:x} for ${2:x} in ${3:iteravel}]', 'List comprehension'),
          snip('main', "if __name__ == '__main__':\n\t${1:main()}", 'Bloco main'),
          snip('enumerate', 'for ${1:i}, ${2:item} in enumerate(${3:lista}):\n\t${4:pass}', 'Itera com índice'),
        ]
      };
    }
  });
}

// ===== Zoom e tema do editor =====
function applyEditorOptions(opts) {
  Object.values(monacoEditors).forEach(ed => { if (ed) ed.updateOptions(opts); });
}

function zoomEditorIn() {
  editorFontSize = Math.min(40, editorFontSize + 1);
  localStorage.setItem('editorFontSize', editorFontSize);
  applyEditorOptions({ fontSize: editorFontSize });
  updateZoomLabel();
}

function zoomEditorOut() {
  editorFontSize = Math.max(8, editorFontSize - 1);
  localStorage.setItem('editorFontSize', editorFontSize);
  applyEditorOptions({ fontSize: editorFontSize });
  updateZoomLabel();
}

function zoomEditorReset() {
  editorFontSize = 15;
  localStorage.setItem('editorFontSize', editorFontSize);
  applyEditorOptions({ fontSize: editorFontSize });
  updateZoomLabel();
}

function updateZoomLabel() {
  const el = document.getElementById('zoomLabel');
  if (el) el.textContent = Math.round((editorFontSize / 15) * 100) + '%';
}

function toggleEditorTheme() {
  currentEditorTheme = currentEditorTheme === 'p5Light' ? 'p5Dark' : 'p5Light';
  localStorage.setItem('editorTheme', currentEditorTheme);
  if (window.monaco) monaco.editor.setTheme(currentEditorTheme);
  const btn = document.getElementById('btnToggleTheme');
  if (btn) btn.textContent = currentEditorTheme === 'p5Light' ? '🌙' : '☀️';
  const layout = document.querySelector('.code-ide-layout');
  if (layout) layout.classList.toggle('editor-dark', currentEditorTheme === 'p5Dark');
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

  // Forçar layout do editor Monaco ativo
  if (monacoEditors[lang]) {
    setTimeout(() => monacoEditors[lang].layout(), 50);
  }

  // Mostrar botão "Rodar Python" apenas na aba Python
  const btnPy = document.getElementById('btnRunPython');
  if (btnPy) btnPy.style.display = lang === 'py' ? '' : 'none';
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

  if (canViewStudentProjects()) {
    // Carregar lista de alunos como sub-abas
    try {
      const res = await fetchWithRetry('/api/projetos-alunos', { headers: authHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      let html = '<div class="code-user-tabs-container">';
      // Administrador e Aluna Especial têm uma aba própria antes das abas de alunos.
      const hasOwnProjectsTab = isAdmin() || isEspecial();
      if (hasOwnProjectsTab) {
        html += `<button class="code-user-tab active" data-userid="${currentUser.id}" onclick="switchCodeUser(${currentUser.id}, this)">
          <span class="code-user-icon">👤</span> Meus Projetos
        </button>`;
      }
      (data.alunos || []).forEach(a => {
        const isActive = !hasOwnProjectsTab && a.id === (data.alunos[0] || {}).id ? ' active' : '';
        html += `<button class="code-user-tab${isActive}" data-userid="${a.id}" onclick="switchCodeUser(${a.id}, this)">
          <span class="code-user-icon">👤</span> ${escapeHtml(a.nome.split(' ')[0])}
          <span class="code-user-count">${a.total_projetos}</span>
        </button>`;
      });
      html += '</div>';
      tabArea.innerHTML = html;

      // Carregar projetos do primeiro usuário
      const firstUserId = hasOwnProjectsTab ? currentUser.id : (data.alunos[0] ? data.alunos[0].id : null);
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
    const ownView = Number(userId) === Number(currentUser.id);
    if (canViewStudentProjects() && !ownView) {
      res = await fetchWithRetry(`/api/projetos-aluno/${userId}`, { headers: authHeaders() });
    } else {
      res = await fetchWithRetry('/api/projetos', { headers: authHeaders() });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    projetosCache = (data.projetos || []).filter(p => Number(p.aluno_id) === Number(userId));

    // Carregar projetos do professor para alunos
    adminProjetosCache = [];
    if ((isAluno() || isEspecial()) && ownView) {
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

    // Projetos próprios ou projetos do aluno selecionado.
    const myGroup = document.createElement('optgroup');
    myGroup.label = ownView ? '📁 Meus Projetos' : '📁 Projetos do aluno';
    if (canCreateProjectInCurrentView()) {
      const newOpt = document.createElement('option');
      newOpt.value = 'new';
      newOpt.textContent = '+ Novo Projeto';
      myGroup.appendChild(newOpt);
    }
    projetosCache.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.nome + (p.visto ? ' ✅' : '');
      myGroup.appendChild(opt);
    });
    if (myGroup.children.length > 0) select.appendChild(myGroup);

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
    } else if (adminProjetosCache.length > 0 && (isAluno() || isEspecial())) {
      select.value = 'admin_' + adminProjetosCache[0].id;
      viewingAdminProject = true;
      loadProjectIntoEditor(adminProjetosCache[0]);
    } else if (canCreateProjectInCurrentView()) {
      select.value = 'new';
      viewingAdminProject = false;
      clearEditor();
    } else {
      const emptyOpt = document.createElement('option');
      emptyOpt.value = '';
      emptyOpt.textContent = 'Nenhum projeto cadastrado';
      emptyOpt.disabled = true;
      emptyOpt.selected = true;
      select.appendChild(emptyOpt);
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
  setEditorValue('py', projeto.py);

  // Carregar imagens do projeto
  projectAssets = {};
  if (projeto.assets) {
    try { projectAssets = JSON.parse(projeto.assets) || {}; } catch (e) { projectAssets = {}; }
  }
  renderAssetTree();

  // Renderizar botão de visto
  renderVistoButton(projeto);

  const canDel = canEditCurrentProject();
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
  setEditorValue('py', '');
  projectAssets = {};
  renderAssetTree();
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
  const isOwner = isOwnCodeView();
  const canEdit = canEditCurrentProject();
  setEditorsReadOnly(!canEdit);
  document.getElementById('codeProjectName').readOnly = !canEdit;

  // Esconder botões de ação se não pode editar
  const saveBtn = document.querySelector('.code-project-actions .btn-primary');
  if (saveBtn) saveBtn.style.display = canEdit ? '' : 'none';
  document.getElementById('btnDeleteProjeto').style.display = canEdit && currentProjectId ? '' : 'none';
  const importFilesBtn = document.getElementById('btnImportProjectFiles');
  const importImagesBtn = document.getElementById('btnImportProjectImages');
  if (importFilesBtn) importFilesBtn.style.display = canEdit ? '' : 'none';
  if (importImagesBtn) importImagesBtn.style.display = canEdit ? '' : 'none';

  // Identificar claramente projetos alheios em modo somente leitura.
  let readOnlyLabel = document.getElementById('readOnlyLabel');
  const readOnlyReason = viewingAdminProject
    ? '👁 Modo Visualização (Projeto do Professor)'
    : (!isOwner ? '👁 Modo Visualização (Projeto de outro aluno)' : '');
  if (!canEdit && readOnlyReason) {
    if (!readOnlyLabel) {
      readOnlyLabel = document.createElement('span');
      readOnlyLabel.id = 'readOnlyLabel';
      readOnlyLabel.className = 'read-only-label';
      const projectInfo = document.querySelector('.code-project-info');
      if (projectInfo) projectInfo.appendChild(readOnlyLabel);
    }
    readOnlyLabel.textContent = readOnlyReason;
    readOnlyLabel.style.display = '';
  } else if (readOnlyLabel) {
    readOnlyLabel.style.display = 'none';
  }

  renderAssetTree();
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

// Script injetado no preview para capturar console e erros
const CONSOLE_CAPTURE_SCRIPT = `
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
<\/script>`;

// Escapa HTML para inserção segura em innerHTML.
function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Substitui referências a imagens do projeto (src/href/url) pelas data URLs.
// Aceita caminhos com "./", "/" ou subpastas antes do nome do arquivo.
function resolveAssetRefs(text, kind) {
  if (!text || !projectAssets) return text || '';
  const names = Object.keys(projectAssets);
  if (!names.length) return text;
  names.forEach((name) => {
    const dataUrl = projectAssets[name];
    if (!dataUrl) return;
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const prefix = '(?:\\.{0,2}/)*'; // ./  ../  /  (repetidos)
    const put = (re) => { text = text.replace(re, (m, p1, p2) => p1 + dataUrl + (p2 || '')); };
    if (kind === 'html') {
      put(new RegExp('((?:src|href|poster|data-src)\\s*=\\s*")' + prefix + esc + '(")', 'gi'));
      put(new RegExp("((?:src|href|poster|data-src)\\s*=\\s*')" + prefix + esc + "(')", 'gi'));
      put(new RegExp('(url\\(\\s*"?\'?)' + prefix + esc + '("?\'?\\s*\\))', 'gi'));
    } else if (kind === 'css') {
      put(new RegExp('(url\\(\\s*")' + prefix + esc + '("\\s*\\))', 'gi'));
      put(new RegExp("(url\\(\\s*')" + prefix + esc + "('\\s*\\))", 'gi'));
      put(new RegExp('(url\\(\\s*)' + prefix + esc + '(\\s*\\))', 'gi'));
    } else { // js: literais de string
      put(new RegExp('(")' + prefix + esc + '(")', 'gi'));
      put(new RegExp("(')" + prefix + esc + "(')", 'gi'));
      put(new RegExp('(`)' + prefix + esc + '(`)', 'gi'));
    }
  });
  return text;
}

// Monta um documento HTML completo vinculando CSS e JS ao HTML.
// Resolve referências locais a style.css/script.js e injeta o conteúdo inline,
// funcionando tanto com HTML parcial quanto com documentos completos.
function buildFullCode(html, css, js, opts) {
  opts = opts || {};
  const title = opts.title || 'Preview';
  const includeConsole = opts.console !== false;
  html = resolveAssetRefs(html || '', 'html');
  css = resolveAssetRefs(css || '', 'css');
  js = resolveAssetRefs(js || '', 'js');

  const consoleCapture = includeConsole ? CONSOLE_CAPTURE_SCRIPT : '';
  const styleTag = css.trim() ? '<style>\n' + css + '\n</style>' : '';
  const scriptTag = js.trim() ? '<script>\n' + js + '\n<\/script>' : '';

  const hasFullDoc = /<html[\s>]/i.test(html) || /<!DOCTYPE/i.test(html);

  if (hasFullDoc) {
    let doc = html;
    // Remover referências a arquivos locais que serão injetados inline
    doc = doc.replace(/<link\b[^>]*href=["'][^"']*(?:style|styles|main)\.css["'][^>]*>/gi, '');
    doc = doc.replace(/<script\b[^>]*src=["'][^"']*(?:script|main|app|index)\.js["'][^>]*>\s*<\/script>/gi, '');

    // Injetar CSS no <head>
    if (/<\/head>/i.test(doc)) {
      doc = doc.replace(/<\/head>/i, styleTag + '\n</head>');
    } else if (/<head\b[^>]*>/i.test(doc)) {
      doc = doc.replace(/<head\b[^>]*>/i, function (m) { return m + '\n' + styleTag; });
    } else if (/<html\b[^>]*>/i.test(doc)) {
      doc = doc.replace(/<html\b[^>]*>/i, function (m) { return m + '\n<head><meta charset="UTF-8">' + styleTag + '</head>'; });
    } else {
      doc = styleTag + '\n' + doc;
    }

    // Injetar console + JS antes de </body>
    const inject = consoleCapture + '\n' + scriptTag;
    if (/<\/body>/i.test(doc)) {
      doc = doc.replace(/<\/body>/i, inject + '\n</body>');
    } else {
      doc = doc + '\n' + inject;
    }
    return doc;
  }

  // HTML parcial: montar documento completo
  return '<!DOCTYPE html>\n<html lang="pt-br">\n<head>\n'
    + '<meta charset="UTF-8">\n'
    + '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    + '<title>' + title + '</title>\n'
    + styleTag + '\n</head>\n<body>\n'
    + html + '\n' + consoleCapture + '\n' + scriptTag + '\n</body>\n</html>';
}

function runCode() {
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');

  clearConsole();

  const fullCode = buildFullCode(html, css, js, { console: true });

  const iframe = document.getElementById('codePreview');
  iframe.srcdoc = fullCode;

  // Show brief loading shimmer on preview
  const previewBody = document.getElementById('codePreviewBody');
  if (previewBody) {
    previewBody.classList.add('loading');
    setTimeout(() => previewBody.classList.remove('loading'), 600);
  }

  // Flash the status badge
  const badge = document.getElementById('previewStatus');
  if (badge) {
    badge.textContent = 'Updating...';
    badge.style.color = '#F59E0B';
    badge.style.borderColor = 'rgba(245, 158, 11, 0.3)';
    badge.style.background = 'rgba(245, 158, 11, 0.15)';
    setTimeout(() => {
      badge.textContent = 'Auto';
      badge.style.color = '#22C55E';
      badge.style.borderColor = 'rgba(34, 197, 94, 0.3)';
      badge.style.background = 'rgba(34, 197, 94, 0.15)';
    }, 800);
  }
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

function toggleConsole() {
  const consoleEl = document.querySelector('.code-console-full');
  if (!consoleEl) return;
  
  const isHidden = consoleEl.classList.toggle('hidden');
  
  // Atualizar visual do botão no toolbar
  const btnToggle = document.getElementById('btnToggleConsole');
  if (btnToggle) {
    if (isHidden) {
      btnToggle.classList.add('console-hidden');
      btnToggle.title = 'Mostrar Console';
      btnToggle.style.opacity = '0.6';
    } else {
      btnToggle.classList.remove('console-hidden');
      btnToggle.title = 'Ocultar Console';
      btnToggle.style.opacity = '1';
    }
  }

  // Recalcular layout do Monaco
  setTimeout(() => {
    Object.values(monacoEditors).forEach(ed => ed && ed.layout());
  }, 50);
}

// ===== Toggle Live Preview =====
function togglePreview() {
  const panel = document.getElementById('codePreviewPanel');
  if (!panel) return;

  const isCollapsed = panel.classList.toggle('preview-collapsed');

  // Atualizar texto do botão no painel
  const btnToggle = document.getElementById('btnTogglePreview');
  if (btnToggle) {
    btnToggle.innerHTML = isCollapsed ? '🔼 Mostrar' : '🔽 Ocultar';
  }

  // Atualizar visual do botão no toolbar
  const btnToolbar = document.getElementById('btnTogglePreviewToolbar');
  if (btnToolbar) {
    btnToolbar.style.opacity = isCollapsed ? '0.6' : '1';
    btnToolbar.title = isCollapsed ? 'Mostrar Preview' : 'Ocultar Preview';
  }

  // Recalcular layout do Monaco
  setTimeout(() => {
    Object.values(monacoEditors).forEach(ed => ed && ed.layout());
  }, 50);
}

// ===== Resize Live Preview =====
let previewHeight = parseInt(localStorage.getItem('previewHeight')) || 480;

function resizePreview(delta) {
  const iframe = document.querySelector('#codePreviewBody iframe');
  if (!iframe) return;

  previewHeight = Math.max(160, Math.min(960, previewHeight + delta));
  iframe.style.height = previewHeight + 'px';
  localStorage.setItem('previewHeight', previewHeight);
  updatePreviewSizeLabel();
}

function resetPreviewSize() {
  previewHeight = 480;
  const iframe = document.querySelector('#codePreviewBody iframe');
  if (iframe) iframe.style.height = previewHeight + 'px';
  localStorage.setItem('previewHeight', previewHeight);
  updatePreviewSizeLabel();
}

function updatePreviewSizeLabel() {
  const label = document.getElementById('previewSizeLabel');
  if (label) label.textContent = previewHeight + 'px';
}

// Drag-to-resize handle
document.addEventListener('DOMContentLoaded', () => {
  const handle = document.getElementById('previewResizeHandle');
  const sizeLabel = document.getElementById('previewSizeLabel');

  // Restaurar tamanho salvo
  const savedHeight = parseInt(localStorage.getItem('previewHeight'));
  if (savedHeight && savedHeight >= 160 && savedHeight <= 960) {
    previewHeight = savedHeight;
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.height = previewHeight + 'px';
    updatePreviewSizeLabel();
  }

  // Clique no label reseta o tamanho
  if (sizeLabel) {
    sizeLabel.addEventListener('dblclick', resetPreviewSize);
  }

  if (!handle) return;

  let isDragging = false;
  let startY = 0;
  let startHeight = 0;

  handle.addEventListener('mousedown', (e) => {
    e.preventDefault();
    isDragging = true;
    startY = e.clientY;
    startHeight = previewHeight;
    document.body.style.cursor = 'ns-resize';
    document.body.style.userSelect = 'none';
    // Prevent iframe from stealing mouse events
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.pointerEvents = 'none';
  });

  // Touch support
  handle.addEventListener('touchstart', (e) => {
    isDragging = true;
    startY = e.touches[0].clientY;
    startHeight = previewHeight;
    document.body.style.userSelect = 'none';
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.pointerEvents = 'none';
  }, { passive: true });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    const diff = e.clientY - startY;
    previewHeight = Math.max(160, Math.min(960, startHeight + diff));
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.height = previewHeight + 'px';
    updatePreviewSizeLabel();
  });

  document.addEventListener('touchmove', (e) => {
    if (!isDragging) return;
    const diff = e.touches[0].clientY - startY;
    previewHeight = Math.max(160, Math.min(960, startHeight + diff));
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.height = previewHeight + 'px';
    updatePreviewSizeLabel();
  }, { passive: true });

  const stopDrag = () => {
    if (!isDragging) return;
    isDragging = false;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    localStorage.setItem('previewHeight', previewHeight);
    const iframe = document.querySelector('#codePreviewBody iframe');
    if (iframe) iframe.style.pointerEvents = '';
  };

  document.addEventListener('mouseup', stopDrag);
  document.addEventListener('touchend', stopDrag);
});

async function salvarProjeto() {
  if (!canEditCurrentProject()) {
    showCodeNotification('Este projeto está disponível somente para visualização.', 'error');
    return;
  }

  const nome = document.getElementById('codeProjectName').value.trim() || 'Meu Projeto';
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');
  const py = getEditorValue('py');
  const assets = JSON.stringify(projectAssets || {});

  try {
    let res;
    if (currentProjectId) {
      res = await fetchWithRetry(`/api/projetos/${currentProjectId}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({ nome, html, css, js, py, assets }),
      });
    } else {
      res = await fetchWithRetry('/api/projetos', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ nome, html, css, js, py, assets }),
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
  if (!currentProjectId || !canEditCurrentProject()) return;
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

  // Baixar os arquivos individualmente
  downloadBlob(fullHtml, `${sanitizedName}/index.html`, 'text/html');
  setTimeout(() => downloadBlob(css, `${sanitizedName}/style.css`, 'text/css'), 200);
  setTimeout(() => downloadBlob(js, `${sanitizedName}/script.js`, 'text/javascript'), 400);
  const py = getEditorValue('py');
  if (py && py.trim()) {
    setTimeout(() => downloadBlob(py, `${sanitizedName}/main.py`, 'text/x-python'), 600);
  }
  // Baixar imagens do projeto
  let delay = 800;
  Object.keys(projectAssets).forEach((name) => {
    const blob = dataURLToBlob(projectAssets[name]);
    if (blob) {
      setTimeout(() => downloadBlobObject(blob, `${sanitizedName}/${name}`), delay);
      delay += 200;
    }
  });
}

function dataURLToBlob(dataUrl) {
  try {
    const [head, body] = String(dataUrl).split(',');
    const mime = (head.match(/data:([^;]+)/) || [])[1] || 'application/octet-stream';
    if (/;base64/i.test(head)) {
      const bin = atob(body);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return new Blob([arr], { type: mime });
    }
    return new Blob([decodeURIComponent(body)], { type: mime });
  } catch (e) {
    return null;
  }
}

function downloadBlobObject(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
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
  } else if (type === 'py') {
    downloadBlob(getEditorValue('py'), 'main.py', 'text/x-python');
  }
}

// ===== Live Server Preview =====
function openLivePreview() {
  const html = getEditorValue('html');
  const css = getEditorValue('css');
  const js = getEditorValue('js');
  const nome = document.getElementById('codeProjectName').value.trim() || 'Meu Projeto';

  // Documento completo com CSS e JS já vinculados ao HTML
  const fullCode = buildFullCode(html, css, js, { title: nome + ' — Live Server', console: false });

  // Abrir SEMPRE em uma nova aba usando um Blob URL
  const blob = new Blob([fullCode], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');

  if (!win) {
    showCodeNotification('Permita pop-ups para abrir o Live Server em nova aba.', 'error');
  } else {
    showCodeNotification('Live Server aberto em nova aba!', 'success');
  }

  // Liberar o Blob após a aba carregar
  setTimeout(() => URL.revokeObjectURL(url), 60000);

  // Atualizar também o preview/console embutido
  runCode();
}

// ===== Execução de Python (Pyodide) =====
let pyodideInstance = null;
let pyodideLoadingPromise = null;

async function ensurePyodide() {
  if (pyodideInstance) return pyodideInstance;
  if (pyodideLoadingPromise) return pyodideLoadingPromise;
  pyodideLoadingPromise = (async () => {
    if (!window.loadPyodide) {
      await new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js';
        s.onload = resolve;
        s.onerror = () => reject(new Error('Falha ao carregar o interpretador Python (Pyodide).'));
        document.head.appendChild(s);
      });
    }
    pyodideInstance = await window.loadPyodide({ indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.26.2/full/' });
    return pyodideInstance;
  })();
  return pyodideLoadingPromise;
}

async function runPython() {
  const code = getEditorValue('py');
  clearConsole();
  if (!code.trim()) {
    appendConsole('info', 'Escreva algum código Python em main.py para executar.');
    return;
  }
  appendConsole('info', '🐍 Carregando interpretador Python...');
  try {
    const py = await ensurePyodide();
    py.setStdout({ batched: (s) => appendConsole('log', s) });
    py.setStderr({ batched: (s) => appendConsole('error', s) });
    clearConsole();
    await py.runPythonAsync(code);
    appendConsole('info', '✓ Execução concluída.');
  } catch (err) {
    appendConsole('error', String((err && err.message) || err));
  }
}

// ===== Importação de arquivos (botão + arrastar e soltar) =====
const IMAGE_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'ico', 'avif', 'apng', 'jfif', 'tiff', 'tif'];

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('Falha ao ler ' + file.name));
    r.readAsDataURL(file);
  });
}

// Garante um nome único e seguro para o asset (mantém legível para chamar no HTML).
function sanitizeAssetName(name) {
  let base = (name || 'imagem').split(/[\\/]/).pop().trim();
  base = base.replace(/["'<>`\s]+/g, '_');
  if (!base) base = 'imagem';
  let final = base;
  let i = 1;
  while (projectAssets[final]) {
    const dot = base.lastIndexOf('.');
    if (dot > 0) final = base.slice(0, dot) + '-' + i + base.slice(dot);
    else final = base + '-' + i;
    i++;
  }
  return final;
}

async function handleFileImport(files) {
  if (!canEditCurrentProject()) {
    showCodeNotification('Não é possível importar arquivos em um projeto de outra pessoa.', 'error');
    return;
  }
  if (!files || !files.length) return;
  const imported = [];
  let addedImages = false;
  for (const file of files) {
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const isImage = (file.type && file.type.startsWith('image/')) || IMAGE_EXTS.includes(ext);
    if (isImage) {
      try {
        const dataUrl = await readFileAsDataURL(file);
        const name = sanitizeAssetName(file.name);
        projectAssets[name] = dataUrl;
        imported.push(name);
        addedImages = true;
      } catch (e) {
        showCodeNotification('Falha ao importar imagem: ' + file.name, 'error');
      }
      continue;
    }
    let text = '';
    try { text = await file.text(); } catch (e) { continue; }
    if (ext === 'html' || ext === 'htm') { setEditorValue('html', text); imported.push('index.html'); }
    else if (ext === 'css') { setEditorValue('css', text); imported.push('style.css'); }
    else if (ext === 'js') { setEditorValue('js', text); imported.push('script.js'); }
    else if (ext === 'py') { setEditorValue('py', text); imported.push('main.py'); }
    else { showCodeNotification('Tipo não suportado: ' + file.name, 'error'); }
  }
  if (addedImages) renderAssetTree();
  if (imported.length) {
    runCode();
    showCodeNotification('Importado: ' + imported.join(', '), 'success');
  }
}

// ===== Gerenciamento de imagens do projeto =====
function renderAssetTree() {
  const tree = document.getElementById('codeImageTree');
  if (!tree) return;
  const canEdit = canEditCurrentProject();
  const names = Object.keys(projectAssets);
  if (!names.length) {
    const hint = canEdit ? '<br><small>Arraste ou clique em +</small>' : '';
    tree.innerHTML = '<div class="code-img-empty">Nenhuma imagem.' + hint + '</div>';
    return;
  }
  tree.innerHTML = names.map((name) => {
    const url = projectAssets[name];
    const safe = escapeHtml(name);
    const attr = name.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const editActions = canEdit
      ? '<button class="file-tree-btn" onclick="event.stopPropagation(); insertImageTag(\'' + attr + '\')" title="Inserir &lt;img&gt; no HTML">&lt;&gt;</button>'
        + '<button class="file-tree-btn" onclick="event.stopPropagation(); removeAsset(\'' + attr + '\')" title="Remover imagem">🗑</button>'
      : '';
    return '<div class="code-file-tree-item code-img-item" title="' + safe + '">'
      + '<span class="file-tree-img-thumb" style="background-image:url(&quot;' + url + '&quot;)"></span>'
      + '<span class="file-tree-name" onclick="copyAssetPath(\'' + attr + '\')">' + safe + '</span>'
      + '<div class="file-tree-actions">'
      + '<button class="file-tree-btn" onclick="event.stopPropagation(); copyAssetPath(\'' + attr + '\')" title="Copiar caminho">📋</button>'
      + editActions
      + '</div></div>';
  }).join('');
}

async function copyAssetPath(name) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(name);
    } else {
      const ta = document.createElement('textarea');
      ta.value = name;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    showCodeNotification('Caminho copiado: ' + name, 'success');
  } catch (e) {
    showCodeNotification('Não foi possível copiar. Caminho: ' + name, 'error');
  }
}

function insertImageTag(name) {
  if (!canEditCurrentProject()) {
    copyAssetPath(name);
    return;
  }
  const snippet = '<img src="' + name + '" alt="' + name.replace(/\.[^.]+$/, '') + '">';
  switchCodeLang('html');
  const ed = monacoEditors.html;
  if (ed && ed.executeEdits) {
    const sel = ed.getSelection();
    ed.executeEdits('insert-image', [{ range: sel, text: snippet, forceMoveMarkers: true }]);
    ed.focus();
  } else {
    setEditorValue('html', getEditorValue('html') + '\n' + snippet);
  }
  runCode();
  showCodeNotification('Imagem inserida no HTML.', 'success');
}

function removeAsset(name) {
  if (!canEditCurrentProject()) return;
  if (!projectAssets[name]) return;
  if (!confirm('Remover a imagem "' + name + '" do projeto?')) return;
  delete projectAssets[name];
  renderAssetTree();
  runCode();
  showCodeNotification('Imagem removida: ' + name, 'success');
}

function setupCodeDropZone() {
  const layout = document.querySelector('.code-ide-layout');
  if (!layout || layout.dataset.dropReady) return;
  layout.dataset.dropReady = '1';

  const overlay = document.createElement('div');
  overlay.className = 'code-drop-overlay';
  overlay.innerHTML = '<div class="code-drop-inner">📥 Solte os arquivos aqui<br><small>.html · .css · .js · .py · imagens</small></div>';
  layout.appendChild(overlay);

  let counter = 0;
  const hasFiles = (e) => e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') !== -1;

  layout.addEventListener('dragenter', (e) => {
    if (!hasFiles(e) || !canEditCurrentProject()) return;
    e.preventDefault();
    counter++;
    layout.classList.add('drag-active');
  });
  layout.addEventListener('dragover', (e) => {
    if (hasFiles(e) && canEditCurrentProject()) e.preventDefault();
  });
  layout.addEventListener('dragleave', () => {
    counter--;
    if (counter <= 0) { counter = 0; layout.classList.remove('drag-active'); }
  });
  layout.addEventListener('drop', (e) => {
    if (!canEditCurrentProject()) return;
    e.preventDefault();
    counter = 0;
    layout.classList.remove('drag-active');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      handleFileImport(e.dataTransfer.files);
    }
  });
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
    
    // Obter líder atual e gerenciar mensagem dinâmica
    const lider = ranking[0];
    let msgLiderHtml = '';
    if (lider) {
      const leaderMsgList = [
        `🏆 <strong>${lider.nome}</strong> está dominando o topo do ranking! Quem conseguirá superá-lo?`,
        `🔥 O primeiro lugar é de <strong>${lider.nome}</strong>! Continue programando para subir de posição!`,
        `🚀 Dedicação extrema: <strong>${lider.nome}</strong> é o atual líder da nossa jornada!`,
        `⭐ Incrível! <strong>${lider.nome}</strong> conquistou a liderança disparada do ranking!`,
        `🎯 Foco absoluto! <strong>${lider.nome}</strong> segue brilhando como nº 1 no pódio!`
      ];

      const prevLeader = localStorage.getItem('ranking_leader');
      let msg = '';
      if (prevLeader && prevLeader !== lider.nome) {
        msg = `⚡ ATENÇÃO! Temos uma mudança emocionante na liderança! <strong>${lider.nome}</strong> acaba de assumir o topo, superando ${prevLeader}! Parabenize o novo líder! 🎉`;
      } else {
        const msgIdx = lider.nome.length % leaderMsgList.length;
        msg = leaderMsgList[msgIdx];
      }
      localStorage.setItem('ranking_leader', lider.nome);

      msgLiderHtml = `<div class="ranking-leader-msg">${msg}</div>`;
    }

    let html = `
      <div class="ranking-header">
        <h3>🏆 Ranking dos Alunos</h3>
        <button class="btn btn-sm btn-outline ranking-toggle" onclick="toggleRankingView()">Minimizar</button>
      </div>
      <div id="rankingBody" class="ranking-body">
        ${msgLiderHtml}
        <div class="ranking-cards">
    `;

    ranking.forEach((aluno, i) => {
      const isTop3 = i < 3;
      const medal = medals[i] || `${i + 1}º`;
      const medalClass = isTop3 ? `ranking-top-${i + 1}` : '';
      
      let incentivoIndividual = 'Dev Ativo';
      if (i === 0) incentivoIndividual = 'Líder Supremo!';
      else if (i === 1) incentivoIndividual = 'Vice-Líder!';
      else if (i === 2) incentivoIndividual = 'No Pódio!';
      else if (aluno.totalProjetos >= 5) incentivoIndividual = 'Multi-Projetos';
      else if (aluno.totalLinhas >= 1000) incentivoIndividual = 'Fera do Código';
      else if (aluno.totalLinhas >= 500) incentivoIndividual = 'Codificador';

      html += `
        <div class="ranking-card ${medalClass}">
          <div class="ranking-card-medal">${medal}</div>
          <div class="ranking-card-name" title="${aluno.nome}">${aluno.nome}</div>
          <div class="ranking-card-incentivo ${isTop3 ? '' : 'muted'}">${incentivoIndividual}</div>
          <div class="ranking-card-stats">
            <span>📁 ${aluno.totalProjetos} ${aluno.totalProjetos === 1 ? 'projeto' : 'projetos'}</span>
            <span>✍️ ${aluno.totalLinhas.toLocaleString('pt-BR')} linhas</span>
            <span>📝 ${aluno.totalPalavras.toLocaleString('pt-BR')} palavras</span>
          </div>
        </div>
      `;
    });

    html += `
        </div>
      </div>
    `;
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

// ===== AI CHAT =====
let aiChatHistory = [];
let aiChatIsOpen = false;

function toggleAIChat() {
  const panel = document.getElementById('aiChatPanel');
  aiChatIsOpen = !aiChatIsOpen;
  panel.classList.toggle('ai-open', aiChatIsOpen);
  if (aiChatIsOpen) {
    setTimeout(() => {
      const input = document.getElementById('aiChatInput');
      if (input) input.focus();
      scrollAIChat();
    }, 50);
  }
}

function clearAIChat() {
  aiChatHistory = [];
  const msgs = document.getElementById('aiChatMessages');
  if (!msgs) return;
  msgs.innerHTML = `
    <div class="ai-msg ai-msg-assistant">
      <div class="ai-msg-avatar">🤖</div>
      <div class="ai-msg-bubble"><p>Conversa reiniciada! Como posso te ajudar?</p></div>
    </div>`;
}

function aiHandleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendAIMessage();
  }
}

function aiExplainCode() {
  const lang = document.querySelector('.code-lang-tab.active')?.dataset?.lang || 'html';
  const code = getEditorValue(lang) || '';
  if (!code.trim()) {
    appendAIMsg('assistant', '⚠️ Não encontrei código no editor. Escreva algum código primeiro e tente novamente!');
    return;
  }
  sendAIMessage('Explique detalhadamente o que este código faz, de forma didática para um aluno de ADS:', true);
}

function aiQuickAsk(question) {
  sendAIMessage(question, true);
}

async function sendAIMessage(overrideText, includeCode) {
  includeCode = includeCode || false;
  const input = document.getElementById('aiChatInput');
  const userText = overrideText !== undefined ? overrideText : (input ? input.value.trim() : '');
  if (!userText) return;

  if (!overrideText && input) input.value = '';

  // Abrir o painel se estiver fechado
  if (!aiChatIsOpen) toggleAIChat();

  appendAIMsg('user', userText);
  aiChatHistory.push({ role: 'user', content: userText });

  const sendBtn = document.getElementById('aiSendBtn');
  if (sendBtn) sendBtn.disabled = true;

  const typingId = appendAITyping();

  try {
    const lang = document.querySelector('.code-lang-tab.active')?.dataset?.lang || 'html';
    const body = {
      messages: aiChatHistory.slice(-20),
      includeCode: includeCode,
    };
    if (includeCode) {
      body.codigoContexto = getEditorValue(lang) || '';
    }

    const res = await fetchWithRetry('/api/ai/chat', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(body),
    });

    removeAITyping(typingId);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erro ao contatar IA.');

    aiChatHistory.push({ role: 'assistant', content: data.reply });
    appendAIMsg('assistant', data.reply);
  } catch (err) {
    removeAITyping(typingId);
    appendAIMsg('assistant', '❌ ' + (err.message || 'Erro ao contatar IA. Tente novamente.'));
  } finally {
    if (sendBtn) sendBtn.disabled = false;
    const inp = document.getElementById('aiChatInput');
    if (inp) inp.focus();
  }
}

function appendAIMsg(role, text) {
  const msgs = document.getElementById('aiChatMessages');
  if (!msgs) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg-' + role;
  const avatar = role === 'user'
    ? (currentUser && currentUser.nome ? currentUser.nome.charAt(0).toUpperCase() : '👤')
    : '🤖';
  div.innerHTML =
    '<div class="ai-msg-avatar">' + avatar + '</div>' +
    '<div class="ai-msg-bubble">' + formatAIText(text) + '</div>';
  msgs.appendChild(div);
  scrollAIChat();
}

function appendAITyping() {
  const msgs = document.getElementById('aiChatMessages');
  if (!msgs) return '';
  const id = 'ai-typing-' + Date.now();
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg-assistant';
  div.id = id;
  div.innerHTML =
    '<div class="ai-msg-avatar">🤖</div>' +
    '<div class="ai-typing"><span></span><span></span><span></span></div>';
  msgs.appendChild(div);
  scrollAIChat();
  return id;
}

function removeAITyping(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function scrollAIChat() {
  const msgs = document.getElementById('aiChatMessages');
  if (msgs) msgs.scrollTop = msgs.scrollHeight;
}

function formatAIText(raw) {
  // Extrai blocos de código antes de escapar
  const blocks = [];
  let text = raw.replace(/```(\w*)\n?([\s\S]*?)```/g, function(_, lang, code) {
    const i = blocks.length;
    blocks.push({ lang: lang || 'code', code: code.trim() });
    return '\x00BLOCK' + i + '\x00';
  });

  // Escapa HTML
  text = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Código inline
  text = text.replace(/`([^`\n]+)`/g, '<code>$1</code>');

  // Negrito e itálico
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');

  // Listas com - ou •
  text = text.replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>');
  text = text.replace(/(<li>[\s\S]*?<\/li>)/g, function(m) {
    return '<ul>' + m + '</ul>';
  });

  // Parágrafos
  text = '<p>' + text.replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>') + '</p>';

  // Restaura blocos de código
  blocks.forEach(function(b, i) {
    var escaped = b.code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    text = text.replace('\x00BLOCK' + i + '\x00',
      '<pre><code class="lang-' + b.lang + '">' + escaped + '</code></pre>');
  });

  return text;
}

