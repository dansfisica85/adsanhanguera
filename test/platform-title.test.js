const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const index = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
const explorer = fs.readFileSync(path.join(root, 'public', 'explorer.html'), 'utf8');
const modernCss = fs.readFileSync(path.join(root, 'public', 'app-modern.css'), 'utf8');
const baseCss = fs.readFileSync(path.join(root, 'public', 'style.css'), 'utf8');
const explorerCss = fs.readFileSync(path.join(root, 'public', 'explorer.css'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const title = 'Curso Superior de Tecnologia em Análise e Desenvolvimento de Sistemas';

test('titulo institucional aparece no documento, cabecalho global e rodape', () => {
  assert.match(index, new RegExp(`<title>${title}</title>`));
  assert.equal(index.match(new RegExp(`<h1>${title}</h1>`, 'g')).length, 2);
  assert.match(index, new RegExp(`<p class="footer-main">${title}</p>`));
  assert.doesNotMatch(index, /<h1>ADS Anhanguera<\/h1>/);
  assert.doesNotMatch(index, /<h1>Projeto de Software<\/h1>/);
  assert.doesNotMatch(index, /<span class="subtitle">ADS\s*[–-]\s*Anhanguera\s*\|\s*Nutrientes Delivery<\/span>/);
});

test('pagina do explorador usa o mesmo titulo institucional', () => {
  assert.match(explorer, new RegExp(`<title>${title}</title>`));
  assert.match(explorer, new RegExp(`<h1>${title}</h1>`));
});

test('login e README exibem a mesma identidade institucional', () => {
  assert.match(index, new RegExp(`<div class="login-logo">[\\s\\S]*?<h1>${title}</h1>`));
  assert.match(readme, new RegExp(`^# ${title}$`, 'm'));
  assert.ok(server.includes(`# ${title}\\nREADME não encontrado.`));
});

test('titulo longo possui regras responsivas e preserva as cores do login', () => {
  assert.match(modernCss, /#app \.logo h1/);
  assert.match(modernCss, /max-width:\s*285px/);
  assert.match(modernCss, /text-wrap:\s*balance/);
  assert.doesNotMatch(modernCss, /\.login-screen/);
  assert.match(baseCss, /\.login-logo h1\s*\{[\s\S]*?color:\s*var\(--primary\);[\s\S]*?overflow-wrap:\s*anywhere;[\s\S]*?text-wrap:\s*balance;/);
  assert.match(explorerCss, /\.welcome-screen h1\s*\{[\s\S]*?overflow-wrap:\s*anywhere;[\s\S]*?text-wrap:\s*balance;/);
});
