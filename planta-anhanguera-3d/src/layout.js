export const CAMPUS = {
  name: 'Faculdade Anhanguera de Sertãozinho',
  address: 'Avenida Antônio Paschoal, 1954 — Jardim São José, Sertãozinho — SP, 14170-700',
  center: { lat: -21.14486, lng: -47.98716 },
  geofenceRadiusMeters: 180,
  entrance: { x: 25, z: 44, label: 'Entrada principal' },
};

export const categories = {
  sala: { label: 'Sala de aula', color: 0xd79a61, floor: '#d79a61' },
  laboratorio: { label: 'Laboratório', color: 0x5d9fb4, floor: '#5d9fb4' },
  administrativo: { label: 'Atendimento e administração', color: 0x8f78b2, floor: '#8f78b2' },
  apoio: { label: 'Apoio e serviço', color: 0xb3a266, floor: '#b3a266' },
  convivencia: { label: 'Convivência', color: 0x749459, floor: '#749459' },
  sanitarios: { label: 'Sanitários', color: 0x6f879f, floor: '#6f879f' },
};

const room = (name, category, x, z, w, d, extra = {}) => ({ name, category, x, z, w, d, h: 3.2, y: 0, ...extra });

export const rooms = [
  room('Sanitários — ala norte', 'sanitarios', -34, -30, 8, 7, { code: 'WC-N', description: 'Banheiros feminino, masculino e acessível na ala norte.' }),
  room('Sala 9', 'sala', -23.5, -30, 10, 7, { code: '09' }),
  room('Sala 8', 'sala', -12.5, -30, 10, 7, { code: '08' }),
  room('Sala 7', 'sala', -1.8, -30, 9, 7, { code: '07' }),
  room('Sala 6', 'sala', 8.2, -30, 9, 7, { code: '06' }),
  room('Laboratório de Agronomia', 'laboratorio', 19.5, -29.5, 10, 8, { code: '24', description: 'Bancadas didáticas e áreas de apoio para atividades de Agronomia.' }),
  room('Cantina', 'convivencia', 31.5, -28, 10, 10, { code: '23', description: 'Área de alimentação com balcão de atendimento, mesas e cadeiras.' }),
  room('Sala 19', 'sala', -47, -22, 7, 6, { code: '19' }),
  room('Sala 17', 'sala', -39, -22, 7, 6, { code: '17' }),
  room('Sala 16', 'sala', -31, -22, 7, 6, { code: '16' }),
  room('Sala 15', 'sala', -23, -22, 7, 6, { code: '15' }),
  room('Sala 23', 'sala', -47, -14.5, 7, 6, { code: '23' }),
  room('Sala 22', 'sala', -39, -14.5, 7, 6, { code: '22' }),
  room('Sala 21', 'sala', -31, -14.5, 7, 6, { code: '21' }),
  room('Sala 20', 'sala', -23, -14.5, 7, 6, { code: '20' }),
  room('Sala 10', 'sala', -10, -18, 10, 8, { code: '10' }),
  room('Sala 5', 'sala', 1.5, -18, 10, 8, { code: '05' }),
  room('Sala 11', 'sala', -10, -8.7, 10, 8, { code: '11' }),
  room('Sala 4', 'sala', 1.5, -8.7, 10, 8, { code: '04' }),
  room('Sala 12', 'sala', -10, 0.6, 10, 8, { code: '12' }),
  room('Sala 3', 'sala', 1.5, 0.6, 10, 8, { code: '03' }),
  room('Sala 13', 'sala', -24, -4, 8, 8, { code: '13' }),
  room('Sala 14', 'sala', -24, 5.4, 8, 8, { code: '14' }),
  room('Arquivo', 'apoio', -11.5, 10.5, 7, 5, { code: '27', description: 'Guarda e organização de documentos acadêmicos e administrativos.' }),
  room('Almoxarifado', 'apoio', -3.2, 10.5, 7, 5, { code: '28', description: 'Armazenamento de materiais e suprimentos da unidade.' }),
  room('Laboratório de Morfologia', 'laboratorio', -25, 21.5, 16, 14, { code: '31', description: 'Laboratório com bancadas centrais para aulas práticas de Morfologia.' }),
  room('Sala 2', 'sala', -7, 18.3, 10, 8, { code: '02' }),
  room('Sala 1', 'sala', -7, 28.2, 10, 8, { code: '01' }),
  room('NPI', 'administrativo', 14.2, -1, 6, 6, { code: '26', description: 'Núcleo de Práticas Integradas e atendimento acadêmico.' }),
  room('Sala CIEE', 'administrativo', 14.2, 6.2, 6, 6, { code: '27', description: 'Atendimento e orientação de estágios e empregabilidade.' }),
  room('Clínica de Psicologia', 'laboratorio', 24, 2.5, 12, 13, { code: '25', description: 'Ambiente de atendimento e práticas supervisionadas de Psicologia.' }),
  room('Biblioteca', 'convivencia', 37.5, 2.5, 12, 13, { code: '26', description: 'Acervo, mesas de estudo e estações de consulta.' }),
  room('Laboratório de Informática I', 'laboratorio', 49, 1, 10, 14, { code: '14', description: 'Estações de trabalho para aulas e atividades digitais.' }),
  room('Recepção e orientação', 'administrativo', 29.5, 11.4, 18, 5, { code: 'REC', description: 'Recepção principal, espera e orientação de visitantes.' }),
  room('Cozinha', 'apoio', 10.5, 15.5, 6, 6, { code: '30', description: 'Apoio interno para preparo e organização de alimentos.' }),
  room('Laboratório de Física', 'laboratorio', 19, 22.5, 12, 13, { code: '19', description: 'Bancadas e equipamentos para experimentos de Física.' }),
  room('Laboratório de Química', 'laboratorio', 32, 22.5, 12, 13, { code: '20', description: 'Bancadas didáticas para práticas de Química.' }),
  room('Laboratório de Informática II', 'laboratorio', 49, 17, 10, 14, { code: '15', description: 'Estações de trabalho para aulas e atividades digitais.' }),
  room('Laboratório de Informática III', 'laboratorio', 49, 30, 10, 10, { code: '16', description: 'Estações de trabalho para aulas e atividades digitais.' }),
  room('Comercial', 'administrativo', 39.5, 36, 8, 6, { code: '17', description: 'Atendimento comercial e apoio a novos alunos.' }),
  room('Secretaria', 'administrativo', 48, 36, 8, 6, { code: '18', description: 'Atendimento acadêmico, matrículas e documentação.' }),
  room('Depósito de limpeza', 'apoio', 2, 35, 8, 6, { code: '29', description: 'Guarda de materiais e equipamentos de limpeza.' }),
];

export const mezzanineRooms = [
  room('Mezanino — Diretoria', 'administrativo', 17, 21.5, 6, 5, { code: 'M1', y: 4.2, h: 2.8, description: 'Sala da direção da unidade.' }),
  room('Mezanino — D.P.', 'administrativo', 24, 21.5, 6, 5, { code: 'M2', y: 4.2, h: 2.8, description: 'Departamento Pessoal.' }),
  room('Mezanino — Sala de reunião', 'administrativo', 31, 21.5, 6, 5, { code: 'M3', y: 4.2, h: 2.8, description: 'Reuniões administrativas e pedagógicas.' }),
  room('Mezanino — Sala dos professores', 'administrativo', 24, 27.7, 13, 6, { code: 'M4', y: 4.2, h: 2.8, description: 'Convivência e preparação de aulas dos docentes.' }),
  room('Mezanino — Sanitários', 'sanitarios', 34, 27.7, 5, 6, { code: 'M5', y: 4.2, h: 2.8 }),
];

export function descriptionFor(roomData) {
  if (roomData.description) return roomData.description;
  if (roomData.category === 'sala') return `${roomData.name}, com carteiras para estudantes, mesa docente e quadro frontal.`;
  return `${categories[roomData.category]?.label || 'Ambiente'} identificado na planta de referência.`;
}
