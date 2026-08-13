const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const appSource = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
const modernCss = fs.readFileSync(path.join(root, 'public', 'app-modern.css'), 'utf8');

test('interface exibe o selo literal ALUNA ESPECIAL', () => {
  assert.match(appSource, /especial:\s*'ALUNA ESPECIAL'/);
  assert.match(modernCss, /#app\s+\.role-badge\.especial/);
});

test('interface separa leitura global de mutacao das respostas e projetos', () => {
  assert.match(appSource, /function canMutateResponses\(\)/);
  assert.match(appSource, /function canEditCurrentProject\(\)/);
  assert.match(appSource, /Modo Visualização \(Projeto de outro aluno\)/);
});
