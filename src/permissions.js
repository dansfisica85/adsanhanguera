const ROLES = Object.freeze({
  ADMIN: 'admin',
  COORDENADOR: 'coordenador',
  ALUNO: 'aluno',
  ESPECIAL: 'especial',
});

const KNOWN_ROLES = new Set(Object.values(ROLES));
const PLATFORM_OWNER_EMAIL = 'professordavi85@gmail.com';

function hasKnownRole(user) {
  return Boolean(user && KNOWN_ROLES.has(user.role));
}

function ownsResource(user, ownerId) {
  return Boolean(user) && Number(user.id) === Number(ownerId);
}

function isPlatformOwner(user) {
  return Boolean(user) && String(user.email || '').toLowerCase() === PLATFORM_OWNER_EMAIL;
}

function canViewAllProjects(user) {
  return hasKnownRole(user) && [ROLES.ADMIN, ROLES.COORDENADOR, ROLES.ESPECIAL].includes(user.role);
}

function canViewProject(user, ownerId) {
  if (!hasKnownRole(user)) return false;
  return canViewAllProjects(user) || (user.role === ROLES.ALUNO && ownsResource(user, ownerId));
}

function canCreateProject(user) {
  return hasKnownRole(user) && [ROLES.ADMIN, ROLES.ALUNO, ROLES.ESPECIAL].includes(user.role);
}

function canUpdateProject(user, ownerId) {
  if (!hasKnownRole(user)) return false;
  if (user.role === ROLES.ADMIN) return true;
  return [ROLES.ALUNO, ROLES.ESPECIAL].includes(user.role) && ownsResource(user, ownerId);
}

function canDeleteProject(user, ownerId) {
  return canUpdateProject(user, ownerId);
}

function canCreateResponse(user) {
  return hasKnownRole(user) && [ROLES.ADMIN, ROLES.ALUNO].includes(user.role);
}

function canMutateResponse(user, ownerId) {
  if (!hasKnownRole(user)) return false;
  if (user.role === ROLES.ADMIN) return true;
  return user.role === ROLES.ALUNO && ownsResource(user, ownerId);
}

module.exports = {
  ROLES,
  PLATFORM_OWNER_EMAIL,
  hasKnownRole,
  ownsResource,
  isPlatformOwner,
  canViewAllProjects,
  canViewProject,
  canCreateProject,
  canUpdateProject,
  canDeleteProject,
  canCreateResponse,
  canMutateResponse,
};
