const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'ads-anhanguera-secret-2026';
const JWT_EXPIRES = '7d';

async function hashSenha(senha) {
  return bcrypt.hash(senha, 10);
}

async function verificarSenha(senha, hash) {
  return bcrypt.compare(senha, hash);
}

function gerarToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, nome: user.nome },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function verificarToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function middlewareAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido.' });
  }
  try {
    const decoded = verificarToken(authHeader.split(' ')[1]);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
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

module.exports = { hashSenha, verificarSenha, gerarToken, verificarToken, middlewareAuth, middlewareRole };
