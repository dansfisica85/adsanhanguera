/* Integração independente do Monaco e dos projetos existentes. */
(function () {
  'use strict';

  let configured = null;
  let busy = false;
  let generation = 0;
  let controller = null;
  let frame = null;
  let frameTimer = null;
  const openedWindows = new Set();

  const element = id => document.getElementById(id);
  const token = () => typeof authToken === 'string' ? authToken : null;
  const stillCurrent = (version, owner) => generation === version && token() === owner && Boolean(owner);

  function message(text, compact = Boolean(frame)) {
    const status = element('vscodeStatus');
    if (!status) return;
    element('vscodeMessage').textContent = text;
    status.classList.toggle('is-compact', compact);
  }

  function controls({ retry = false, editor = false } = {}) {
    const open = element('vscodeOpenButton');
    if (!open) return;
    open.hidden = configured !== true;
    open.disabled = busy;
    open.textContent = frame ? 'Reconectar' : 'Abrir VS Code';
    element('vscodeNewTabButton').hidden = configured !== true;
    element('vscodeNewTabButton').disabled = busy;
    element('vscodeFullscreenButton').hidden = !frame || !element('vscodeShell').requestFullscreen;
    element('vscodeRetryButton').hidden = !retry;
    element('vscodeRetryButton').disabled = busy;
    element('vscodeEditorButton').hidden = !editor;
    element('vscodeShell').setAttribute('aria-busy', String(busy));
  }

  function removeFrame() {
    clearTimeout(frameTimer);
    frameTimer = null;
    if (frame) {
      frame.onload = null;
      frame.onerror = null;
      frame.remove();
      frame = null;
    }
    const host = element('vscodeFrameHost');
    if (host) host.hidden = true;
  }

  async function request(url, method) {
    controller = new AbortController();
    const activeController = controller;
    const timeout = setTimeout(() => activeController.abort(), 30000);
    try {
      const response = await fetch(url, {
        method,
        headers: authHeaders(),
        cache: 'no-store',
        signal: activeController.signal,
        ...(method === 'POST' ? { body: '{}' } : {}),
      });
      if (response.status === 401 || response.status === 403) {
        throw new Error('Sua sessão expirou. Saia e entre novamente para abrir o VS Code.');
      }
      if (!response.ok) throw new Error('Não foi possível conectar ao VS Code. Tente novamente em instantes.');
      return await response.json();
    } finally {
      clearTimeout(timeout);
      if (controller === activeController) controller = null;
    }
  }

  function errorMessage(error) {
    if (error.name === 'AbortError') return 'A conexão com o VS Code demorou mais que o esperado. Tente novamente.';
    // Não expõe corpos de resposta, URLs, tickets nem mensagens técnicas do servidor.
    if (error.message.startsWith('Sua sessão') || error.message.startsWith('Não foi possível conectar')) return error.message;
    return 'Não foi possível abrir o VS Code. Tente novamente em instantes.';
  }

  async function show(force = false) {
    if (!token() || busy || !element('vscodeShell')) return;
    if (configured === true && !force) return;
    const version = generation;
    const owner = token();
    busy = true;
    message('Verificando a disponibilidade do VS Code…');
    controls();
    try {
      const result = await request('/api/ide/status', 'GET');
      if (!stillCurrent(version, owner)) return;
      configured = result && result.configured === true;
      if (!configured) removeFrame();
      message(configured
        ? 'Tudo pronto para começar. Abra o VS Code para acessar seu espaço de trabalho.'
        : 'VS Code ainda não está disponível. Você pode continuar usando o editor de projetos.');
    } catch (error) {
      if (!stillCurrent(version, owner)) return;
      configured = null;
      message(errorMessage(error));
    } finally {
      if (stillCurrent(version, owner)) {
        busy = false;
        controls({ retry: configured !== true, editor: configured !== true });
      }
    }
  }

  function validateSession(result) {
    if (!result || typeof result.launchUrl !== 'string' || typeof result.ticket !== 'string' || !result.ticket || result.ticket.length > 8192) throw new Error('Resposta inválida');
    const launchUrl = new URL(result.launchUrl);
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(launchUrl.hostname);
    if ((launchUrl.protocol !== 'https:' && !(launchUrl.protocol === 'http:' && loopback)) || launchUrl.username || launchUrl.password || launchUrl.search || launchUrl.hash) throw new Error('Destino inválido');
    const expiresAt = Date.parse(result.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error('Sessão expirada');
    return launchUrl.href;
  }

  function postTicket(targetDocument, targetName, launchUrl, ticket) {
    const form = targetDocument.createElement('form');
    form.method = 'POST';
    form.action = launchUrl;
    form.target = targetName;
    form.hidden = true;
    const input = targetDocument.createElement('input');
    input.type = 'hidden';
    input.name = 'ticket';
    input.value = ticket;
    form.appendChild(input);
    targetDocument.body.appendChild(form);
    try {
      form.submit();
    } finally {
      input.value = '';
      form.remove();
    }
  }

  async function launch(destination = 'iframe') {
    if (!token() || busy || configured !== true) return;
    const version = generation;
    const owner = token();
    let popup = null;
    // Abre durante o clique para não depender de pop-ups após uma requisição.
    if (destination === 'tab') {
      popup = window.open('about:blank', '_blank');
      if (!popup) {
        message('Permita a abertura de uma nova aba no navegador e tente novamente.');
        return;
      }
      popup.opener = null;
      popup.document.title = 'Abrindo VS Code…';
      popup.document.body.textContent = 'Preparando seu espaço de trabalho…';
      openedWindows.add(popup);
    }
    busy = true;
    message('Preparando seu espaço de trabalho…');
    controls();
    try {
      const result = await request('/api/ide/session', 'POST');
      if (!stillCurrent(version, owner)) return;
      const launchUrl = validateSession(result);
      if (popup) {
        if (popup.closed) throw new Error('Aba fechada');
        postTicket(popup.document, '_self', launchUrl, result.ticket);
        message('VS Code aberto em uma nova aba. Você pode continuar usando a plataforma.');
      } else {
        removeFrame();
        frame = document.createElement('iframe');
        frame.className = 'vscode-frame';
        frame.name = 'vscode-workspace';
        frame.title = 'VS Code — meu espaço de trabalho';
        frame.referrerPolicy = 'no-referrer';
        const origin = new URL(launchUrl).origin;
        frame.setAttribute('allow', `clipboard-read ${origin}; clipboard-write ${origin}; fullscreen ${origin}`);
        const currentFrame = frame;
        frame.onload = () => {
          if (!stillCurrent(version, owner) || frame !== currentFrame) return;
          // O documento inicial vazio também emite load em alguns navegadores.
          try { if (frame.contentWindow.location.href === 'about:blank') return; } catch { /* IDE em outra origem. */ }
          clearTimeout(frameTimer);
          message('Se a IDE não aparecer aqui, use “Abrir em nova aba”.');
        };
        frame.onerror = () => {
          if (stillCurrent(version, owner) && frame === currentFrame) message('Não foi possível carregar a IDE aqui. Tente reconectar ou abrir em nova aba.');
        };
        const host = element('vscodeFrameHost');
        host.appendChild(frame);
        host.hidden = false;
        message('Abrindo o VS Code. Se a IDE não aparecer, use “Abrir em nova aba”.');
        frameTimer = setTimeout(() => {
          if (stillCurrent(version, owner) && frame === currentFrame) message('A IDE está demorando para aparecer. Tente reconectar ou abrir em nova aba.');
        }, 45000);
        postTicket(document, frame.name, launchUrl, result.ticket);
      }
    } catch (error) {
      if (popup) {
        popup.close();
        openedWindows.delete(popup);
      }
      if (stillCurrent(version, owner)) message(errorMessage(error));
    } finally {
      if (stillCurrent(version, owner)) {
        busy = false;
        controls();
      }
    }
  }

  async function fullscreen() {
    const shell = element('vscodeShell');
    if (!frame || !shell) return;
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else if (shell.requestFullscreen) await shell.requestFullscreen();
    } catch {
      message('Não foi possível ativar a tela cheia. Você também pode abrir a IDE em nova aba.');
    }
  }

  function reset(headers) {
    generation += 1;
    if (controller) controller.abort();
    controller = null;
    removeFrame();
    for (const popup of openedWindows) {
      try { popup.close(); } catch { /* A sessão também é revogada pelo servidor. */ }
    }
    openedWindows.clear();
    configured = null;
    busy = false;
    message('Verificando a disponibilidade do VS Code…', false);
    controls();
    // Usa os cabeçalhos capturados antes de clearAuth apagar a sessão local.
    if (headers) {
      fetch('/api/ide/session', { method: 'DELETE', headers, keepalive: true }).catch(() => {});
    }
  }

  window.vscodeIDE = { show, launch, fullscreen, reset };
})();
