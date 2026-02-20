const gabaritos = require("./gabaritos");

function avaliarResposta(unidade, etapa, exercicio, respostaAluno) {
  const gab = gabaritos[unidade]?.etapas?.[etapa]?.exercicios?.[exercicio];
  if (!gab) return { nota: 0, feedback: "Exercício não encontrado.", acertos: [], sugestoes: [] };

  const respostaLower = respostaAluno.toLowerCase();
  const palavrasEncontradas = [];
  const palavrasAusentes = [];

  for (const palavra of gab.palavrasChave) {
    if (respostaLower.includes(palavra.toLowerCase())) {
      palavrasEncontradas.push(palavra);
    } else {
      palavrasAusentes.push(palavra);
    }
  }

  const totalPalavras = gab.palavrasChave.length;
  const qtdAcertos = palavrasEncontradas.length;
  const percentual = totalPalavras > 0 ? (qtdAcertos / totalPalavras) * 100 : 0;

  // Tabela fixa de notas por quantidade de palavras-chave acertadas:
  // 0 = nota 0, 1 = nota 1, 2 = nota 3, 3 = nota 5,
  // 4 = nota 7, 5 = nota 8, 6 = nota 9, 7+ = nota 10
  let nota;
  if (qtdAcertos >= 7) nota = 10;
  else if (qtdAcertos === 6) nota = 9;
  else if (qtdAcertos === 5) nota = 8;
  else if (qtdAcertos === 4) nota = 7;
  else if (qtdAcertos === 3) nota = 5;
  else if (qtdAcertos === 2) nota = 3;
  else if (qtdAcertos === 1) nota = 1;
  else nota = 0;

  // Gerar feedback detalhado
  let feedback = "";
  const acertos = [];
  const sugestoes = [];

  if (nota >= 8) {
    feedback = "Excelente! Sua resposta aborda os principais conceitos esperados.";
  } else if (nota >= 6) {
    feedback = "Bom trabalho! Sua resposta está no caminho certo, mas pode ser aprimorada.";
  } else if (nota >= 4) {
    feedback = "Sua resposta aborda alguns pontos, mas faltam conceitos importantes.";
  } else {
    feedback = "Sua resposta precisa de mais desenvolvimento. Revise os conceitos da unidade.";
  }

  for (const p of palavrasEncontradas) {
    acertos.push(`✅ Mencionou corretamente: "${p}"`);
  }

  if (palavrasAusentes.length > 0) {
    const top5 = palavrasAusentes.slice(0, 5);
    for (const p of top5) {
      sugestoes.push(`💡 Considere abordar: "${p}"`);
    }
  }

  // Adicionar conceitos que devem ser revisados
  if (nota < 8) {
    sugestoes.push("");
    sugestoes.push("📚 Conceitos importantes para revisão:");
    for (const c of gab.conceitos) {
      sugestoes.push(`   • ${c}`);
    }
  }

  return {
    nota,
    feedback,
    acertos,
    sugestoes,
    gabaritoResumo: gab.gabarito,
    percentualAcerto: Math.round(percentual),
  };
}

module.exports = { avaliarResposta };
