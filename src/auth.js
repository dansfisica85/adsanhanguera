const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_EXPIRES = '7d';
let carregarUsuarioAtual = null;

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET deve estar configurado com pelo menos 32 caracteres.');
  }
  return secret;
}

function configurarCarregadorUsuario(loader) {
  if (typeof loader !== 'function') throw new TypeError('Carregador de usuário inválido.');
  carregarUsuarioAtual = loader;
}

async function hashSenha(senha) {
  return bcrypt.hash(senha, 10);
}

async function verificarSenha(senha, hash) {
  return bcrypt.compare(senha, hash);
}

function gerarToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      nome: user.nome,
      tokenVersion: Number(user.token_version || 0),
    },
    getJwtSecret(),
    { expiresIn: JWT_EXPIRES }
  );
}

function verificarToken(token) {
  return jwt.verify(token, getJwtSecret());
}

async function middlewareAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido.' });
  }
  let decoded;
  try {
    decoded = verificarToken(authHeader.split(' ')[1]);
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }

  if (!carregarUsuarioAtual) {
    return res.status(503).json({ error: 'Validação de sessão indisponível.' });
  }

  try {
    const currentUser = await carregarUsuarioAtual(decoded.id);
    if (!currentUser) {
      return res.status(401).json({ error: 'Token inválido ou expirado.' });
    }
    if (Number(decoded.tokenVersion || 0) !== Number(currentUser.token_version || 0)) {
      return res.status(401).json({ error: 'Sessão encerrada. Entre novamente.' });
    }

    req.user = {
      id: Number(currentUser.id),
      nome: currentUser.nome,
      email: currentUser.email,
      role: currentUser.role,
      token_version: Number(currentUser.token_version || 0),
    };
    next();
  } catch (err) {
    console.error('Erro ao validar sessão no banco:', err.message || err);
    return res.status(503).json({ error: 'Validação de sessão indisponível.' });
  }
}

function middlewareRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acesso não autorizado.' });
    }
    next();
  };
}

module.exports = {
  hashSenha,
  verificarSenha,
  gerarToken,
  verificarToken,
  middlewareAuth,
  middlewareRole,
  configurarCarregadorUsuario,
};
