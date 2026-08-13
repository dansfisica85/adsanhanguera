const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
const lab = fs.readFileSync(path.join(root, 'public', 'engenharia-lab.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'public', 'engenharia-lab.css'), 'utf8');
const dataSource = fs.readFileSync(path.join(root, 'public', 'engenharia-data.js'), 'utf8');
const context = { window: {} };
vm.createContext(context);
vm.runInContext(dataSource, context);
const data = context.window.ENGENHARIA_LAB_DATA;

test('nova aba de engenharia possui navegacao, secao e arquivos isolados', () => {
  assert.match(html, /data-tab="engenharia"/);
  assert.match(html, /id="tab-engenharia" class="tab-content"/);
  assert.match(html, /href="engenharia-lab\.css"/);
  assert.match(html, /src="engenharia-data\.js"/);
  assert.match(html, /src="engenharia-lab\.js"/);
  assert.match(app, /tabId === 'engenharia'.*initEngenhariaLab/);
  assert.match(css, /^#app #tab-engenharia/m);
  assert.doesNotMatch(css, /(^|\n)\s*(body|:root|\.login-screen)\s*[{,]/);
});

test('conteudo pedagogico cobre quatro unidades e vinte questoes autocorretivas', () => {
  assert.equal(data.units.length, 4);
  assert.deepEqual(Array.from(data.units, unit => unit.id), ['u1', 'u2', 'u3', 'u4']);
  assert.equal(data.units.reduce((total, unit) => total + unit.questions.length, 0), 20);
  for (const unit of data.units) {
    assert.equal(unit.questions.length, 5);
    assert.equal(unit.simulation.nodes.length, 5);
    for (const question of unit.questions) {
      assert.ok(question.q.length > 10);
      assert.ok(question.options.length >= 4);
      assert.ok(Number.isInteger(question.answer));
      assert.ok(question.answer >= 0 && question.answer < question.options.length);
      assert.ok(question.why.length > 20);
    }
  }
});

test('simulacoes 3D oferecem interacao equivalente por ponteiro teclado e botoes', () => {
  assert.match(lab, /pointerdown/);
  assert.match(lab, /pointermove/);
  assert.match(lab, /ArrowLeft/);
  assert.match(lab, /data-eng-rotate/);
  assert.match(lab, /data-eng-zoom/);
  assert.match(css, /perspective:\s*900px/);
  assert.match(css, /transform-style:\s*preserve-3d/);
  assert.match(css, /prefers-reduced-motion/);
});

test('fluxo real e glossario possuem estrutura completa e fontes', () => {
  assert.equal(data.flow.length, 7);
  assert.equal(data.codeExamples.length, 3);
  assert.ok(data.glossary.length >= 40);
  assert.deepEqual(Array.from(Object.keys(data.categories)), ['frontend', 'backend', 'dados', 'redes', 'sistemas']);
  const names = new Set();
  for (const item of data.glossary) {
    assert.ok(!names.has(item.name), `tecnologia duplicada: ${item.name}`);
    names.add(item.name);
    for (const field of ['name', 'category', 'kind', 'use', 'example', 'creator', 'date', 'country', 'origin', 'source']) {
      assert.ok(String(item[field] || '').trim(), `${item.name || 'item'} sem ${field}`);
    }
    assert.ok(data.categories[item.category]);
    assert.match(item.source, /^https:\/\//);
  }
});

test('laboratorio nao altera notas respostas projetos ou usuarios', () => {
  assert.doesNotMatch(lab, /fetch\s*\(/);
  assert.doesNotMatch(lab, /\/api\/(respostas|projetos|admin|auth)/);
  assert.match(lab, /localStorage/);
  assert.match(html, /não altera suas notas/);
});
