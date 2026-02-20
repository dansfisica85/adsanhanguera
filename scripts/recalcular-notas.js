/**
 * Script para recalcular todas as notas existentes com os novos gabaritos.
 * Preserva todas as respostas existentes, apenas atualiza nota e feedback.
 * 
 * Uso: node scripts/recalcular-notas.js
 */
require('dotenv').config();
const { dbExecute, initDB } = require('../src/database');
const { avaliarResposta } = require('../src/avaliador');

async function recalcular() {
  console.log('🔄 Inicializando banco de dados...');
  await initDB();

  console.log('📊 Buscando todas as respostas existentes...');
  const result = await dbExecute('SELECT id, aluno_id, unidade, etapa, exercicio, resposta, nota FROM respostas ORDER BY id');
  const rows = result.rows;

  if (rows.length === 0) {
    console.log('ℹ️  Nenhuma resposta encontrada no banco de dados.');
    return;
  }

  console.log(`📝 ${rows.length} respostas encontradas. Recalculando...\n`);

  let atualizadas = 0;
  let melhoradas = 0;
  let pioradas = 0;
  let iguais = 0;

  for (const row of rows) {
    const notaAnterior = Number(row.nota);
    const avaliacao = avaliarResposta(Number(row.unidade), Number(row.etapa), Number(row.exercicio), row.resposta);
    const novaNota = avaliacao.nota;

    await dbExecute({
      sql: 'UPDATE respostas SET nota = ?, feedback = ? WHERE id = ?',
      args: [novaNota, JSON.stringify(avaliacao), row.id],
    });

    const diff = novaNota - notaAnterior;
    if (diff > 0) melhoradas++;
    else if (diff < 0) pioradas++;
    else iguais++;

    const seta = diff > 0 ? '⬆️' : diff < 0 ? '⬇️' : '➡️';
    console.log(`  ID ${row.id} | U${row.unidade} E${row.etapa} Ex${row.exercicio} | Nota: ${notaAnterior} → ${novaNota} ${seta} | Acerto: ${avaliacao.percentualAcerto}%`);
    atualizadas++;
  }

  console.log('\n' + '='.repeat(60));
  console.log(`✅ Recálculo concluído!`);
  console.log(`   Total: ${atualizadas} respostas processadas`);
  console.log(`   ⬆️  Melhoradas: ${melhoradas}`);
  console.log(`   ⬇️  Pioradas: ${pioradas}`);
  console.log(`   ➡️  Iguais: ${iguais}`);
  console.log('='.repeat(60));
}

recalcular()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('❌ Erro ao recalcular:', err);
    process.exit(1);
  });
