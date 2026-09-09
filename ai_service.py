from flask import Flask, request, jsonify, Response, stream_with_context
from groq import Groq
import os
import json

app = Flask(__name__)
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """Você é o ADS-AI, um assistente educacional especializado em programação para alunos e professores do curso de Análise e Desenvolvimento de Sistemas (ADS) da Anhanguera.

Suas responsabilidades:
- Explicar código HTML, CSS, JavaScript e Python de forma didática e clara
- Gerar e criar código completo e funcional quando solicitado
- Resolver problemas de programação passo a passo
- Identificar e corrigir erros no código
- Sugerir melhorias e boas práticas de desenvolvimento
- Responder dúvidas sobre desenvolvimento web, lógica de programação e algoritmos
- Adaptar a linguagem ao nível do usuário (do iniciante ao avançado)

Regras:
- Sempre responda em português brasileiro
- Ao gerar código, use blocos de código com a linguagem correta
- Seja didático, objetivo e amigável
- Para explicações complexas, use listas numeradas e exemplos práticos
"""

@app.post("/chat")
def chat():
    body = request.get_json(silent=True) or {}
    messages = body.get("messages", [])
    include_code = body.get("includeCode", False)
    codigo_contexto = body.get("codigoContexto", "")
    stream = body.get("stream", False)

    if not messages or not isinstance(messages, list):
        return jsonify({"error": "messages é obrigatório."}), 400

    final_messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if include_code and codigo_contexto:
        final_messages.append({
            "role": "system",
            "content": f"Código atual do aluno no editor (use como contexto ao responder):\n```\\n{str(codigo_contexto)[:8000]}\\n```"
        })

    final_messages.extend(messages[-20:])

    if stream:
        def generate():
            completion = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=final_messages,
                temperature=1,
                max_completion_tokens=2048,
                top_p=1,
                reasoning_effort="medium",
                stream=True,
                stop=None
            )

            for chunk in completion:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    yield f"data: {json.dumps({'token': delta}, ensure_ascii=False)}\\n\\n"
            yield "data: [DONE]\\n\\n"

        return Response(stream_with_context(generate()), mimetype="text/event-stream")

    completion = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=final_messages,
        temperature=1,
        max_completion_tokens=2048,
        top_p=1,
        reasoning_effort="medium",
        stream=False,
        stop=None
    )

    reply = completion.choices[0].message.content if completion.choices else ""
    return jsonify({"reply": reply})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
