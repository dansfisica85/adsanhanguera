(function () {
  'use strict';

  const STORAGE_KEY = 'ads-eng-lab-progress-v1';
  let initialized = false;
  let quizState = {};
  let glossaryFilter = { search: '', category: 'todos' };

  function getStorageKey() {
    const userId = typeof currentUser !== 'undefined' && currentUser && currentUser.id;
    return userId ? `${STORAGE_KEY}-user-${userId}` : `${STORAGE_KEY}-device`;
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    })[char]);
  }

  function loadProgress() {
    try {
      const saved = JSON.parse(localStorage.getItem(getStorageKey()) || '{}');
      quizState = saved && typeof saved === 'object' ? saved : {};
    } catch {
      quizState = {};
    }
  }

  function saveProgress() {
    try { localStorage.setItem(getStorageKey(), JSON.stringify(quizState)); } catch { /* progresso local opcional */ }
  }

  function renderQuizSummary() {
    const data = window.ENGENHARIA_LAB_DATA;
    const total = data.units.reduce((sum, unit) => sum + unit.questions.length, 0);
    let answered = 0;
    let correct = 0;
    data.units.forEach(unit => unit.questions.forEach((question, index) => {
      const answer = quizState[`${unit.id}-${index}`];
      if (Number.isInteger(answer)) {
        answered += 1;
        if (answer === question.answer) correct += 1;
      }
    }));
    const percent = total ? Math.round((correct / total) * 100) : 0;
    const summary = document.getElementById('engQuizSummary');
    summary.innerHTML = `
      <div><span>Respondidas</span><strong>${answered}/${total}</strong></div>
      <div><span>Acertos</span><strong>${correct}</strong></div>
      <div><span>Aproveitamento</span><strong>${percent}%</strong></div>
      <div class="eng-progress-track" role="progressbar" aria-label="Aproveitamento" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><span style="width:${percent}%"></span></div>
      <button type="button" class="eng-secondary-button" data-eng-action="reset-quizzes">Refazer atividades</button>`;
  }

  function renderQuizzes(openUnitId = 'u1') {
    const container = document.getElementById('engQuizContainer');
    const data = window.ENGENHARIA_LAB_DATA;
    container.innerHTML = data.units.map((unit, unitIndex) => {
      const questions = unit.questions.map((question, questionIndex) => {
        const key = `${unit.id}-${questionIndex}`;
        const selected = quizState[key];
        const answered = Number.isInteger(selected);
        const isCorrect = answered && selected === question.answer;
        const options = question.options.map((option, optionIndex) => {
          let stateClass = '';
          if (answered && optionIndex === question.answer) stateClass = ' is-correct';
          else if (answered && optionIndex === selected) stateClass = ' is-wrong';
          return `<button type="button" class="eng-option${stateClass}" data-eng-answer="${unit.id}" data-question="${questionIndex}" data-option="${optionIndex}" ${answered ? 'disabled' : ''}>
            <span>${String.fromCharCode(65 + optionIndex)}</span>${escapeHtml(option)}
          </button>`;
        }).join('');
        return `<article class="eng-question-card" data-question-key="${key}">
          <p class="eng-question-number">Questão ${questionIndex + 1}</p>
          <h4>${escapeHtml(question.q)}</h4>
          <div class="eng-options">${options}</div>
          ${answered ? `<div class="eng-feedback ${isCorrect ? 'is-correct' : 'is-wrong'}" role="status"><strong>${isCorrect ? '✓ Resposta correta' : '✕ Revise este conceito'}</strong><p>${escapeHtml(question.why)}</p></div>` : ''}
        </article>`;
      }).join('');
      return `<details class="eng-unit-quiz" ${unit.id === openUnitId ? 'open' : ''}>
        <summary>
          <span class="eng-unit-icon">${unit.icon}</span>
          <span><small>${unit.number}</small><strong>${escapeHtml(unit.title)}</strong><em>${escapeHtml(unit.summary)}</em></span>
          <span class="eng-unit-score">${unit.questions.filter((q, index) => quizState[`${unit.id}-${index}`] === q.answer).length}/${unit.questions.length}</span>
        </summary>
        <div class="eng-questions-grid">${questions}</div>
      </details>`;
    }).join('');
    renderQuizSummary();
  }

  function renderSimulations() {
    const container = document.getElementById('engSimulationsContainer');
    container.innerHTML = window.ENGENHARIA_LAB_DATA.units.map((unit, unitIndex) => {
      const nodes = unit.simulation.nodes.map((node, index) => {
        const angle = (360 / unit.simulation.nodes.length) * index;
        return `
        <button type="button" class="eng-3d-node" data-eng-node="${unit.id}" data-node-index="${index}" style="--node-angle:${angle}deg; --node-inverse:${-angle}deg" aria-label="${escapeHtml(node.label)}: ${escapeHtml(node.detail)}">
          <span>${node.icon}</span><strong>${escapeHtml(node.label)}</strong>
        </button>`;
      }).join('');
      return `<article class="eng-simulation-card" data-simulation="${unit.id}" style="--sim-accent:${unitIndex}">
        <header><span>${unit.icon}</span><div><small>${unit.number}</small><h4>${escapeHtml(unit.simulation.title)}</h4><p>${escapeHtml(unit.simulation.hint)}</p></div></header>
        <div class="eng-3d-viewport" data-eng-viewport="${unit.id}" tabindex="0" role="group" aria-label="${escapeHtml(unit.simulation.title)}. Use o mouse, toque ou setas para girar.">
          <div class="eng-3d-world" data-eng-world="${unit.id}" style="--rx:-15deg;--ry:-22deg;--zoom:1">
            <div class="eng-3d-platform"><span>${unit.number}</span></div>${nodes}
          </div>
        </div>
        <div class="eng-3d-controls" role="group" aria-label="Controles da simulação">
          <button type="button" data-eng-rotate="${unit.id}" data-delta="-18" aria-label="Girar para esquerda">↶</button>
          <button type="button" data-eng-rotate="${unit.id}" data-delta="18" aria-label="Girar para direita">↷</button>
          <button type="button" data-eng-zoom="${unit.id}" data-delta="0.1" aria-label="Aumentar zoom">＋</button>
          <button type="button" data-eng-zoom="${unit.id}" data-delta="-0.1" aria-label="Diminuir zoom">－</button>
          <button type="button" data-eng-reset="${unit.id}">Redefinir</button>
        </div>
        <div class="eng-node-detail" id="engDetail-${unit.id}" aria-live="polite"><span>${unit.simulation.nodes[0].icon}</span><div><strong>${escapeHtml(unit.simulation.nodes[0].label)}</strong><p>${escapeHtml(unit.simulation.nodes[0].detail)}</p></div></div>
      </article>`;
    }).join('');

    window.ENGENHARIA_LAB_DATA.units.forEach(unit => setup3D(unit));
  }

  function setup3D(unit) {
    const viewport = document.querySelector(`[data-eng-viewport="${unit.id}"]`);
    const world = document.querySelector(`[data-eng-world="${unit.id}"]`);
    const state = { x: -15, y: -22, zoom: 1, dragging: false, px: 0, py: 0 };
    viewport._engState = state;
    function update() {
      world.style.setProperty('--rx', `${state.x}deg`);
      world.style.setProperty('--ry', `${state.y}deg`);
      world.style.setProperty('--zoom', state.zoom);
    }
    viewport.addEventListener('pointerdown', event => {
      state.dragging = true; state.px = event.clientX; state.py = event.clientY;
      viewport.setPointerCapture(event.pointerId);
    });
    viewport.addEventListener('pointermove', event => {
      if (!state.dragging) return;
      state.y += (event.clientX - state.px) * 0.35;
      state.x = Math.max(-55, Math.min(35, state.x - (event.clientY - state.py) * 0.25));
      state.px = event.clientX; state.py = event.clientY; update();
    });
    viewport.addEventListener('pointerup', () => { state.dragging = false; });
    viewport.addEventListener('pointercancel', () => { state.dragging = false; });
    viewport.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
      event.preventDefault();
      if (event.key === 'ArrowLeft') state.y -= 12;
      if (event.key === 'ArrowRight') state.y += 12;
      if (event.key === 'ArrowUp') state.x = Math.max(-55, state.x - 8);
      if (event.key === 'ArrowDown') state.x = Math.min(35, state.x + 8);
      update();
    });
    update();
  }

  function update3D(unitId, type, delta) {
    const viewport = document.querySelector(`[data-eng-viewport="${unitId}"]`);
    const world = document.querySelector(`[data-eng-world="${unitId}"]`);
    if (!viewport || !world || !viewport._engState) return;
    const state = viewport._engState;
    if (type === 'rotate') state.y += delta;
    if (type === 'zoom') state.zoom = Math.max(0.72, Math.min(1.32, state.zoom + delta));
    if (type === 'reset') { state.x = -15; state.y = -22; state.zoom = 1; }
    world.style.setProperty('--rx', `${state.x}deg`);
    world.style.setProperty('--ry', `${state.y}deg`);
    world.style.setProperty('--zoom', state.zoom);
  }

  function renderFlow() {
    const data = window.ENGENHARIA_LAB_DATA;
    document.getElementById('engFlowContainer').innerHTML = `
      <div class="eng-flow-track">${data.flow.map((step, index) => `
        <button type="button" class="eng-flow-step ${index === 0 ? 'is-active' : ''}" data-eng-flow-step="${index}" aria-pressed="${index === 0}">
          <span class="eng-flow-icon">${step.icon}</span><strong>${escapeHtml(step.title)}</strong><small>${escapeHtml(step.output)}</small>
        </button>`).join('')}</div>
      <article id="engFlowDetail" class="eng-flow-detail" aria-live="polite"></article>`;
    renderFlowDetail(0);
    document.getElementById('engCodeExamples').innerHTML = data.codeExamples.map(example => `
      <article class="eng-code-card"><header><strong>${escapeHtml(example.title)}</strong><span>${escapeHtml(example.language)}</span></header><pre tabindex="0"><code>${escapeHtml(example.code)}</code></pre></article>`).join('');
  }

  function renderFlowDetail(index) {
    const step = window.ENGENHARIA_LAB_DATA.flow[index];
    document.querySelectorAll('[data-eng-flow-step]').forEach((button, itemIndex) => {
      const active = itemIndex === index;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    document.getElementById('engFlowDetail').innerHTML = `<span>${step.icon}</span><div><small>Responsáveis: ${escapeHtml(step.role)}</small><h4>${escapeHtml(step.title)} — ${escapeHtml(step.output)}</h4><p>${escapeHtml(step.detail)}</p></div>`;
  }

  function normalizeSearch(value) {
    return String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  }

  function renderGlossary() {
    const data = window.ENGENHARIA_LAB_DATA;
    const search = normalizeSearch(glossaryFilter.search);
    const groups = Object.entries(data.categories).map(([categoryId, category]) => {
      if (glossaryFilter.category !== 'todos' && glossaryFilter.category !== categoryId) return '';
      const entries = data.glossary.filter(item => item.category === categoryId && (!search || normalizeSearch(Object.values(item).join(' ')).includes(search)));
      if (!entries.length) return '';
      return `<section class="eng-glossary-group" aria-labelledby="eng-cat-${categoryId}">
        <header><span>${category.icon}</span><div><h4 id="eng-cat-${categoryId}">${escapeHtml(category.label)}</h4><p>${escapeHtml(category.description)}</p></div><strong>${entries.length}</strong></header>
        <div class="eng-glossary-grid">${entries.map(item => `
          <article class="eng-glossary-card">
            <div class="eng-glossary-title"><div><span>${escapeHtml(item.kind)}</span><h5>${escapeHtml(item.name)}</h5></div><span class="eng-country">${escapeHtml(item.country)}</span></div>
            <dl>
              <div><dt>Para que serve</dt><dd>${escapeHtml(item.use)}</dd></div>
              <div><dt>Exemplo prático</dt><dd>${escapeHtml(item.example)}</dd></div>
              <div><dt>Criação</dt><dd>${escapeHtml(item.creator)}</dd></div>
              <div><dt>Quando</dt><dd>${escapeHtml(item.date)}</dd></div>
              <div><dt>Como surgiu</dt><dd>${escapeHtml(item.origin)}</dd></div>
            </dl>
            <a href="${escapeHtml(item.source)}" target="_blank" rel="noopener noreferrer">Consultar fonte histórica ↗</a>
          </article>`).join('')}</div>
      </section>`;
    }).join('');
    const count = data.glossary.filter(item => (glossaryFilter.category === 'todos' || item.category === glossaryFilter.category) && (!search || normalizeSearch(Object.values(item).join(' ')).includes(search))).length;
    document.getElementById('engGlossaryGroups').innerHTML = groups || '<p class="eng-empty-state">Nenhuma tecnologia corresponde à busca.</p>';
    document.getElementById('engGlossaryCount').textContent = `${count} tecnologia${count === 1 ? '' : 's'} encontrada${count === 1 ? '' : 's'}`;
    document.getElementById('engGlossaryTotal').textContent = String(data.glossary.length);
  }

  function handleClick(event) {
    const answer = event.target.closest('[data-eng-answer]');
    if (answer) {
      quizState[`${answer.dataset.engAnswer}-${answer.dataset.question}`] = Number(answer.dataset.option);
      saveProgress(); renderQuizzes(answer.dataset.engAnswer); return;
    }
    if (event.target.closest('[data-eng-action="reset-quizzes"]')) {
      quizState = {}; saveProgress(); renderQuizzes(); return;
    }
    const node = event.target.closest('[data-eng-node]');
    if (node) {
      const unit = window.ENGENHARIA_LAB_DATA.units.find(item => item.id === node.dataset.engNode);
      const item = unit.simulation.nodes[Number(node.dataset.nodeIndex)];
      document.querySelectorAll(`[data-eng-node="${unit.id}"]`).forEach(button => button.classList.remove('is-active'));
      node.classList.add('is-active');
      document.getElementById(`engDetail-${unit.id}`).innerHTML = `<span>${item.icon}</span><div><strong>${escapeHtml(item.label)}</strong><p>${escapeHtml(item.detail)}</p></div>`;
      return;
    }
    const rotate = event.target.closest('[data-eng-rotate]');
    if (rotate) return update3D(rotate.dataset.engRotate, 'rotate', Number(rotate.dataset.delta));
    const zoom = event.target.closest('[data-eng-zoom]');
    if (zoom) return update3D(zoom.dataset.engZoom, 'zoom', Number(zoom.dataset.delta));
    const reset = event.target.closest('[data-eng-reset]');
    if (reset) return update3D(reset.dataset.engReset, 'reset', 0);
    const flow = event.target.closest('[data-eng-flow-step]');
    if (flow) renderFlowDetail(Number(flow.dataset.engFlowStep));
  }

  function attachEvents() {
    const root = document.getElementById('engenhariaLabRoot');
    root.addEventListener('click', handleClick);
    document.getElementById('engGlossarySearch').addEventListener('input', event => {
      glossaryFilter.search = event.target.value; renderGlossary();
    });
    document.getElementById('engGlossaryCategory').addEventListener('change', event => {
      glossaryFilter.category = event.target.value; renderGlossary();
    });
  }

  window.initEngenhariaLab = function initEngenhariaLab() {
    if (initialized) return;
    if (!window.ENGENHARIA_LAB_DATA || !document.getElementById('engenhariaLabRoot')) return;
    loadProgress(); renderQuizzes(); renderSimulations(); renderFlow(); renderGlossary(); attachEvents();
    initialized = true;
  };
})();
