// ===== Estado da Aplicação =====
let currentUser = null;
let currentTab = 1;
let exerciciosCache = {};
let respostasCache = {};

// ===== Inicialização =====
document.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('adsUser');
  if (saved) {
    try {
      currentUser = JSON.parse(saved);
      showApp();
    } catch (e) {
      localStorage.removeItem('adsUser');
    }
  }

  document.getElementById('loginForm').addEventListener('submit', handleLogin);
});

// ===== Login =====
async function handleLogin(e) {
  e.preventDefault();
  const nome = document.getElementById('nome').value.trim();
  const email = document.getElementById('email').value.trim();
  if (!nome || !email) return;

  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'Entrando...';

  try {
    const res = await fetch('/api/alunos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nome, email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    currentUser = data.aluno;
    localStorage.setItem('adsUser', JSON.stringify(currentUser));
    showApp();
  } catch (err) {
    alert('Erro ao entrar: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Entrar';
  }
}

function showApp() {
  document.getElementById('loginModal').classList.remove('active');
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('userNameDisplay').textContent = currentUser.nome;
  loadExercicios(currentTab);
  loadRespostasAluno();
}

function logout() {
  currentUser = null;
  exerciciosCache = {};
  respostasCache = {};
  localStorage.removeItem('adsUser');
  document.getElementById('app').classList.add('hidden');
  document.getElementById('loginModal').classList.add('active');
  document.getElementById('loginForm').reset();
}

// ===== Tabs =====
function switchTab(num) {
  currentTab = num;

  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab[data-tab="${num}"]`).classList.add('active');

  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById(`tab-${num}`).classList.add('active');

  loadExercicios(num);
}

// ===== Conceitos Toggle =====
function toggleConcept(header) {
  const card = header.closest('.concept-card');
  card.classList.toggle('open');
}

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
    container.innerHTML = `<p style="color: var(--accent-red);">Erro ao carregar exercícios: ${err.message}</p>`;
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
        html += renderFeedback(resposta);
        html += `<div style="margin-top:12px;">`;
        html += `<button class="btn btn-sm btn-outline" onclick="reDoExercise('${respKey}', ${unidade}, ${etapaKey}, ${exKey})">Refazer</button>`;
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
  const id = `form-${unidade}-${etapa}-${exercicio}`;
  return `
    <form class="exercise-form" id="${id}" onsubmit="submitResposta(event, ${unidade}, ${etapa}, ${exercicio})">
      <div class="form-group">
        <label for="resp-${unidade}-${etapa}-${exercicio}">Sua Resposta</label>
        <textarea id="resp-${unidade}-${etapa}-${exercicio}" placeholder="Escreva sua resposta aqui... (mínimo 15 palavras para nota completa)" required></textarea>
      </div>
      <button type="submit" class="btn btn-primary">Enviar Resposta</button>
    </form>
  `;
}

function renderFeedback(resp) {
  const nota = Number(resp.nota);
  let classe, corClasse;
  if (nota >= 8) {
    classe = 'nota-alta';
    corClasse = 'alta';
  } else if (nota >= 5) {
    classe = 'nota-media';
    corClasse = 'media';
  } else {
    classe = 'nota-baixa';
    corClasse = 'baixa';
  }

  let feedbackData;
  if (typeof resp.feedback === 'string') {
    try { feedbackData = JSON.parse(resp.feedback); } catch { feedbackData = null; }
  } else {
    feedbackData = resp;
  }

  let html = `<div class="feedback-box ${classe}">`;
  html += `<div class="feedback-header">`;
  html += `<span class="feedback-nota ${corClasse}">Nota: ${nota}/10</span>`;

  if (feedbackData && feedbackData.percentualAcerto !== undefined) {
    html += `<span class="feedback-percentual">${feedbackData.percentualAcerto}% de acerto</span>`;
  }
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        aluno_id: currentUser.id,
        unidade,
        etapa,
        exercicio,
        resposta,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    const respKey = `${unidade}-${etapa}-${exercicio}`;
    respostasCache[respKey] = data.avaliacao;

    renderExercicios(
      document.getElementById(`exercises-${unidade}`),
      unidade,
      exerciciosCache[unidade]
    );

    const exCard = document.getElementById(`ex-${respKey}`);
    if (exCard) {
      exCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  } catch (err) {
    alert('Erro ao enviar resposta: ' + err.message);
    btn.disabled = false;
    btn.textContent = 'Enviar Resposta';
  }
}

// ===== Refazer Exercício =====
function reDoExercise(respKey, unidade, etapa, exercicio) {
  delete respostasCache[respKey];
  renderExercicios(
    document.getElementById(`exercises-${unidade}`),
    unidade,
    exerciciosCache[unidade]
  );
}

// ===== Carregar Respostas Anteriores =====
async function loadRespostasAluno() {
  if (!currentUser) return;

  try {
    const res = await fetch(`/api/respostas/${currentUser.id}`);
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
          nota: r.nota,
          feedback: feedbackData ? feedbackData.feedback || r.feedback : r.feedback,
          acertos: feedbackData ? feedbackData.acertos : [],
          sugestoes: feedbackData ? feedbackData.sugestoes : [],
          gabaritoResumo: feedbackData ? feedbackData.gabaritoResumo : null,
          percentualAcerto: feedbackData ? feedbackData.percentualAcerto : null,
        };
      }

      // Re-render current tab exercises
      if (exerciciosCache[currentTab]) {
        renderExercicios(
          document.getElementById(`exercises-${currentTab}`),
          currentTab,
          exerciciosCache[currentTab]
        );
      }
    }
  } catch (err) {
    console.error('Erro ao carregar respostas:', err);
  }
}
