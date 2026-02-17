/**
 * Módulo Google Drive — Upload de Imagens (Mínimo de Permissões)
 * 
 * Usa Service Account com escopo `drive.file`:
 *   - Só pode CRIAR arquivos/pastas
 *   - NÃO pode ler, editar ou excluir outros arquivos do Drive
 *   - NÃO acessa nenhum outro dado do Google
 * 
 * Variáveis de ambiente necessárias:
 *   GOOGLE_SERVICE_ACCOUNT_EMAIL  — email da service account
 *   GOOGLE_PRIVATE_KEY            — chave privada (PEM) da service account
 *   GOOGLE_DRIVE_FOLDER_ID        — ID da pasta raiz no Drive para uploads
 */

const crypto = require('crypto');
const https = require('https');

// ===== Configuração =====
const SERVICE_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
const PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const ROOT_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID;

function isConfigured() {
  return !!(SERVICE_EMAIL && PRIVATE_KEY && ROOT_FOLDER_ID);
}

// ===== JWT para Google OAuth2 =====
function base64url(data) {
  return Buffer.from(data).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createJWT() {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: SERVICE_EMAIL,
    // Escopo mínimo: só pode criar arquivos no Drive (não acessa nada mais)
    scope: 'https://www.googleapis.com/auth/drive.file',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600, // 1 hora
  };

  const unsigned = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(unsigned);
  const signature = sign.sign(PRIVATE_KEY, 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return unsigned + '.' + signature;
}

// ===== Obter Access Token =====
let cachedToken = null;
let tokenExpiry = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const jwt = createJWT();
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;

  const data = await httpRequest('POST', 'oauth2.googleapis.com', '/token', body, {
    'Content-Type': 'application/x-www-form-urlencoded',
  });

  const parsed = JSON.parse(data);
  if (parsed.error) throw new Error(`Google OAuth error: ${parsed.error_description || parsed.error}`);

  cachedToken = parsed.access_token;
  tokenExpiry = Date.now() + (parsed.expires_in - 60) * 1000; // refresh 1min antes
  return cachedToken;
}

// ===== HTTP Helper (sem dependência externa) =====
function httpRequest(method, host, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host,
      port: 443,
      path,
      method,
      headers: {
        ...headers,
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve(data));
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function httpsRaw(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ===== Criar Pasta no Drive =====
async function criarPasta(nome, parentId) {
  const token = await getAccessToken();
  const metadata = JSON.stringify({
    name: nome,
    mimeType: 'application/vnd.google-apps.folder',
    parents: [parentId],
  });

  const result = await httpRequest(
    'POST',
    'www.googleapis.com',
    '/drive/v3/files',
    metadata,
    {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    }
  );

  const parsed = JSON.parse(result);
  if (parsed.error) throw new Error(`Erro ao criar pasta: ${parsed.error.message}`);
  return parsed.id;
}

// ===== Upload de Imagem via Multipart =====
async function uploadImagem(buffer, nomeArquivo, mimeType, pastaId) {
  const token = await getAccessToken();
  const boundary = '----GDriveBoundary' + Date.now();

  const metadata = JSON.stringify({
    name: nomeArquivo,
    parents: [pastaId],
  });

  // Construir body multipart
  const preamble = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${metadata}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: ${mimeType}\r\n\r\n`
  );
  const postamble = Buffer.from(`\r\n--${boundary}--`);
  const fullBody = Buffer.concat([preamble, buffer, postamble]);

  const result = await httpsRaw({
    hostname: 'www.googleapis.com',
    port: 443,
    path: '/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink,webContentLink',
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
      'Content-Length': fullBody.length,
    },
  }, fullBody);

  const parsed = JSON.parse(result.body);
  if (parsed.error) throw new Error(`Erro upload: ${parsed.error.message}`);

  // Tornar arquivo público para visualização (somente leitura)
  try {
    const permBody = JSON.stringify({ role: 'reader', type: 'anyone' });
    await httpRequest(
      'POST',
      'www.googleapis.com',
      `/drive/v3/files/${parsed.id}/permissions`,
      permBody,
      {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      }
    );
  } catch (e) {
    console.warn('⚠️ Não foi possível tornar imagem pública:', e.message);
  }

  return {
    fileId: parsed.id,
    viewLink: `https://drive.google.com/file/d/${parsed.id}/view`,
    directLink: `https://drive.google.com/uc?export=view&id=${parsed.id}`,
  };
}

// ===== Função Principal — Upload com Criação de Pasta por Data/Nome =====
async function uploadImagemAluno(buffer, nomeOriginal, mimeType, nomeAluno) {
  if (!isConfigured()) {
    throw new Error('Google Drive não configurado. Defina GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_PRIVATE_KEY e GOOGLE_DRIVE_FOLDER_ID.');
  }

  // Validar tipo de imagem
  const tiposPermitidos = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (!tiposPermitidos.includes(mimeType)) {
    throw new Error(`Tipo de arquivo não permitido: ${mimeType}. Apenas imagens (JPEG, PNG, GIF, WebP).`);
  }

  // Criar nome da pasta: "2026-02-17 - Nome do Aluno"
  const hoje = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const nomePasta = `${hoje} - ${nomeAluno}`;

  // Criar pasta dentro da raiz do Drive
  const pastaId = await criarPasta(nomePasta, ROOT_FOLDER_ID);

  // Fazer upload da imagem na pasta criada
  const resultado = await uploadImagem(buffer, nomeOriginal, mimeType, pastaId);

  return {
    ...resultado,
    pastaId,
    nomePasta,
  };
}

module.exports = { uploadImagemAluno, isConfigured };
