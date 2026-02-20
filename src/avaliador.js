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
  const percentual = totalPalavras > 0 ? (palavrasEncontradas.length / totalPalavras) * 100 : 0;

  // Nota de 0 a 10 com curva generosa para conjuntos expandidos de palavras-chave
  // 60% de acerto = nota 10 (fator de escala 1.67)
  let nota = Math.round((percentual * 10) / 60);
  nota = Math.min(10, Math.max(0, nota));

  // Verificar tamanho mínimo da resposta
  const palavrasResposta = respostaAluno.trim().split(/\s+/).length;
  if (palavrasResposta < 15) {
    nota = Math.max(0, nota - 2);
  }

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
