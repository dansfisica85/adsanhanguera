# 🎓 ADS Anhanguera — Plataforma Educacional

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/Express-5.x-000000?logo=express&logoColor=white" alt="Express" />
  <img src="https://img.shields.io/badge/Turso-libSQL-4FF8D2?logo=turso&logoColor=white" alt="Turso" />
  <img src="https://img.shields.io/badge/Chart.js-4.x-FF6384?logo=chartdotjs&logoColor=white" alt="Chart.js" />
  <img src="https://img.shields.io/badge/Deploy-Vercel-000000?logo=vercel&logoColor=white" alt="Vercel" />
  <img src="https://img.shields.io/badge/Versão-2.0.0-F37021" alt="Versão" />
</p>

Plataforma educacional completa desenvolvida para o curso de **Análise e Desenvolvimento de Sistemas** da **Universidade Anhanguera**. O sistema oferece exercícios interativos com avaliação automática por palavras-chave, autenticação JWT com 3 níveis de acesso, painel administrativo com gráficos de evolução e biblioteca de documentos.

---

## 📋 Índice

- [Funcionalidades](#-funcionalidades)
- [Arquitetura](#-arquitetura)
- [Tecnologias](#-tecnologias)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Instalação Local](#-instalação-local)
- [Variáveis de Ambiente](#-variáveis-de-ambiente)
- [Deploy na Vercel](#-deploy-na-vercel)
- [Autenticação e Roles](#-autenticação-e-roles)
- [API Endpoints](#-api-endpoints)
- [Regras de Negócio](#-regras-de-negócio)
- [Conteúdo Acadêmico](#-conteúdo-acadêmico)
- [Desenvolvedor](#-desenvolvedor)

---

## ✨ Funcionalidades

### 🔐 Autenticação

- Login com e-mail e senha
- Tokens JWT com validade de 7 dias
- 3 níveis de acesso: **Admin**, **Coordenador** e **Aluno**
- Sessão persistente via `localStorage`

### 📚 Exercícios Interativos

- 4 unidades completas com exercícios de múltiplas etapas
- Avaliação automática por palavras-chave com nota de 0 a 10
- Feedback detalhado com acertos, sugestões e percentual
- Suporte a múltiplas tentativas por exercício
- Operações CRUD completas (criar, ler, editar, excluir respostas)

### 📊 Painel Administrativo

- Dashboard com estatísticas gerais (total de alunos, respostas, média)
- Gráfico de barras — média de notas por unidade (Chart.js)
- Gráfico de linha — evolução individual do aluno (Chart.js)
- Lista de alunos com médias e totais

### 📄 Biblioteca de Documentos

- Documentos organizados por unidade e categoria
- Suporte a PDF e imagens (PNG/JPG)
- Visualizador embutido via iframe
- Gabaritos protegidos (visíveis apenas para Admin/Coordenador)

### 🎨 Interface

- Tema laranja Anhanguera (#F37021) em fundo claro
- Design responsivo (desktop, tablet e mobile)
- SPA (Single Page Application) com navegação por abas
- Cards de conceitos expansíveis por unidade

---

## 🏗 Arquitetura

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   Frontend   │────▶│   Express 5  │────▶│  Turso/libSQL │
│  Vanilla JS  │◀────│   REST API   │◀────│   Cloud DB    │
│  Chart.js    │     │   JWT Auth   │     │   SQLite Edge  │
└─────────────┘     └──────────────┘     └───────────────┘
```

- **Frontend**: HTML5 + CSS3 + JavaScript vanilla (SPA)
- **Backend**: Node.js + Express 5 (API REST)
- **Banco de Dados**: Turso (libSQL) — SQLite distribuído na edge
- **Autenticação**: bcryptjs (hash) + jsonwebtoken (JWT)
- **Gráficos**: Chart.js via CDN
- **Deploy**: Vercel (serverless)

---

## 🛠 Tecnologias

| Tecnologia | Versão | Uso |
|-----------|--------|-----|
| Node.js | 18+ | Runtime do servidor |
| Express | 5.x | Framework HTTP / API REST |
| @libsql/client | 0.17+ | Cliente Turso/libSQL |
| bcryptjs | 2.4+ | Hash de senhas |
| jsonwebtoken | 9.0+ | Tokens JWT |
| dotenv | 17+ | Variáveis de ambiente |
| Chart.js | 4.x (CDN) | Gráficos no painel admin |

---

## 📁 Estrutura do Projeto

```
adsanhanguera/
├── server.js              # Servidor Express 5 (API + static files)
├── vercel.json            # Configuração de deploy Vercel
├── package.json           # Dependências e scripts
├── .env                   # Variáveis de ambiente (não versionado)
├── .gitignore
├── README.md
│
├── src/
│   ├── auth.js            # Módulo de autenticação (bcrypt + JWT)
│   ├── database.js        # Conexão Turso + schema + seed de usuários
│   ├── gabaritos.js       # Banco de exercícios (perguntas, respostas, palavras-chave)
│   └── avaliador.js       # Motor de avaliação por palavras-chave
│
├── public/
│   ├── index.html         # SPA completa (login, tabs, modals, footer)
│   ├── style.css          # Tema laranja Anhanguera (~800 linhas)
│   ├── app.js             # Lógica frontend (auth, CRUD, Charts, documentos)
│   └── docs/              # Biblioteca de documentos
│       ├── geral/         # Material geral (aulas, Scrum, Nutrientes)
│       ├── u1/            # Documentos Unidade 1
│       ├── u2/            # Documentos Unidade 2
│       ├── u3/            # Documentos Unidade 3
│       └── u4/            # Documentos Unidade 4
│
├── AULA (1-4).png         # Slides das aulas (originais)
└── *.pdf                  # PDFs acadêmicos (originais)
```

---

## 🚀 Instalação Local

### Pré-requisitos

- Node.js 18+ instalado
- Conta no [Turso](https://turso.tech) com banco criado

### Passos

```bash
# 1. Clonar o repositório
git clone https://github.com/dansfisica85/adsanhanguera.git
cd adsanhanguera

# 2. Instalar dependências
npm install

# 3. Configurar variáveis de ambiente
cp .env.example .env
# Editar .env com suas credenciais Turso

# 4. Iniciar o servidor
npm start
# 🚀 Servidor rodando em http://localhost:3000
```

O banco de dados é inicializado automaticamente ao iniciar (criação de tabelas + seed de usuários).

---

## 🔑 Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
TURSO_DATABASE_URL=libsql://seu-banco.turso.io
TURSO_AUTH_TOKEN=seu-token-turso
JWT_SECRET=sua-chave-secreta-jwt  # opcional, tem fallback
PORT=3000                          # opcional, padrão 3000
```

### Na Vercel

Configure as mesmas variáveis em **Settings → Environment Variables**.

---

## 🌐 Deploy na Vercel

### Via CLI

```bash
# 1. Instalar Vercel CLI
npm i -g vercel

# 2. Login
vercel login

# 3. Deploy
vercel --prod
```

### Via GitHub (recomendado)

1. Conecte o repositório no [Vercel Dashboard](https://vercel.com/dashboard)
2. Configure as variáveis de ambiente (`TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`)
3. O deploy é automático a cada push na branch `main`

O arquivo `vercel.json` já está configurado com as rotas corretas.

---

## 🔐 Autenticação e Roles

### Níveis de Acesso

| Role | Permissões |
|------|-----------|
| **admin** | Acesso total: CRUD de respostas, painel admin com gráficos, gabaritos, documentos |
| **coordenador** | Pode alternar entre "Visão Aluno" e "Visão Admin" (leitura). **Não pode** criar/editar/excluir respostas |
| **aluno** | Responder exercícios, ver notas, refazer, excluir próprias respostas |

### Fluxo de Autenticação

```
POST /api/auth/login
  → Verifica email + bcrypt hash
  → Retorna JWT (7 dias) + dados do usuário

Cada request autenticada envia:
  Authorization: Bearer <token>
```

---

## 📡 API Endpoints

### Autenticação

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| `POST` | `/api/auth/login` | ❌ | Login com email + senha |
| `GET` | `/api/auth/me` | ✅ | Verificar token / dados do usuário |

### Exercícios

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| `GET` | `/api/exercicios/:unidade` | ❌ | Listar exercícios (sem gabarito) |

### Respostas (CRUD)

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| `POST` | `/api/respostas` | ✅ | Enviar resposta + avaliação automática |
| `GET` | `/api/respostas` | ✅ | Listar respostas do usuário |
| `PUT` | `/api/respostas/:id` | ✅ | Editar resposta (reavaliar) |
| `DELETE` | `/api/respostas/:id` | ✅ | Excluir resposta |

### Gabarito

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| `GET` | `/api/gabarito/:u/:e/:ex` | ✅ | Ver gabarito (protegido por regra de negócio) |

### Administração

| Método | Rota | Auth | Role |
|--------|------|------|------|
| `GET` | `/api/admin/alunos` | ✅ | admin, coordenador |
| `GET` | `/api/admin/alunos/:id/evolucao` | ✅ | admin, coordenador |
| `GET` | `/api/admin/estatisticas` | ✅ | admin, coordenador |

### Outros

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| `GET` | `/api/documentos` | ❌ | Lista documentos por categoria |
| `GET` | `/api/readme` | ❌ | Conteúdo do README.md |

---

## 📏 Regras de Negócio

### Gabarito Protegido

- **Admin/Coordenador**: Sempre podem ver o gabarito
- **Aluno**: Precisa de **3 ou mais tentativas**, todas com **nota < 10**, para desbloquear o gabarito

### Coordenador — Visão Dupla

- Pode alternar entre "Visão Aluno" e "Visão Admin" via toggle
- Na Visão Admin: acesso de **leitura** ao painel com gráficos e estatísticas
- **Bloqueado** de criar, editar ou excluir respostas (retorna 403)

### Avaliação Automática

- Respostas avaliadas por correspondência de **palavras-chave**
- Nota calculada proporcionalmente ao número de palavras-chave encontradas
- Feedback inclui: nota, percentual de acerto, acertos, sugestões, gabarito resumido
- Mínimo recomendado: 15 palavras na resposta

### Tentativas

- Cada envio incrementa o contador de tentativa
- Todas as tentativas são salvas no banco de dados
- O frontend exibe a última tentativa por exercício

---

## 📖 Conteúdo Acadêmico

### Unidade 1 — Engenharia de Software

- Modelos de ciclo de vida (Cascata, Espiral, Incremental)
- Requisitos funcionais e não funcionais
- Estudo de caso: Nutrientes Delivery

### Unidade 2 — Resolução de Problemas

- Metodologias ágeis (Scrum, Kanban)
- Técnicas de elicitação de requisitos
- Decomposição de problemas complexos

### Unidade 3 — Simulação Profissional

- Situações reais de desenvolvimento
- Tomada de decisão técnica
- Comunicação com stakeholders

### Unidade 4 — Aprendizagem entre Pares

- Trabalho colaborativo
- Revisão de código e boas práticas
- Feedback construtivo e peer review

---

## 🗃 Banco de Dados

### Tabela `usuarios`

```sql
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  senha_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'aluno',
  criado_em TEXT DEFAULT (datetime('now'))
);
```

### Tabela `respostas`

```sql
CREATE TABLE respostas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aluno_id INTEGER NOT NULL,
  unidade INTEGER NOT NULL,
  etapa INTEGER NOT NULL,
  exercicio INTEGER NOT NULL,
  resposta TEXT NOT NULL,
  nota REAL DEFAULT 0,
  feedback TEXT DEFAULT '',
  tentativa INTEGER DEFAULT 1,
  enviado_em TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (aluno_id) REFERENCES usuarios(id)
);
```

---

## 👨‍💻 Desenvolvedor

**Davi Antonino Nunes da Silva**

| Canal | Contato |
|-------|---------|
| 📧 Email | [professordavi85@gmail.com](mailto:professordavi85@gmail.com) |
| 📱 WhatsApp | [(16) 99260-4315](https://wa.me/5516992604315) |
| 🎵 Spotify | [Artigli Notturni 🐾](https://open.spotify.com/artist/artiglinotturni) |
| 🐙 GitHub | [dansfisica85](https://github.com/dansfisica85) |

---

## 📄 Licença

ISC © 2026 — Davi Antonino Nunes da Silva
