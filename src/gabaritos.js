// Gabaritos estruturados para comparação com respostas dos alunos
const gabaritos = {
  1: {
    titulo: "Estudo de Caso – Gestão e Arquitetura",
    etapas: {
      1: {
        titulo: "Gestão de Projetos e Matriz de Responsabilidades",
        exercicios: {
          1: {
            pergunta:
              "Crie a Matriz de Responsabilidades (RACI) para a Equipe do Projeto Nutrientes Delivery, focando nas tarefas críticas: 'Definição de Requisitos do Cliente', 'Desenvolvimento do Módulo de Nutrição' e 'Decisão de Arquitetura'. Atribua os papéis R, A, C e I para cada membro da equipe.",
            gabarito:
              "A matriz deve listar as tarefas críticas e atribuir Responsável (R), Aprovador (A), Consultado (C) e Informado (I) de forma coerente com os papéis da equipe. O Product Owner deve ser A ou R na 'Definição de Requisitos do Cliente'. Os programadores juniores devem ser R no desenvolvimento. O Analista Sênior deve ser C ou R na Decisão de Arquitetura.",
            palavrasChave: [
              "RACI",
              "Responsável",
              "Aprovador",
              "Consultado",
              "Informado",
              "Product Owner",
              "Analista Sênior",
              "programadores",
              "requisitos",
              "arquitetura",
            ],
            conceitos: [
              "Matriz RACI",
              "Definição de papéis",
              "Responsabilidade em projetos",
            ],
          },
          2: {
            pergunta:
              "Identifique e analise o conflito principal entre o Analista Sênior (Preditivo) e o Product Owner/CEO (Adaptativo). Proponha uma estratégia de mitigação para garantir o andamento do projeto.",
            gabarito:
              "O estudante deve identificar o conflito de Metodologia (Analista Sênior – Preditivo vs. PO/CEO – Adaptativo). A estratégia de mitigação deve propor uma solução de consenso ou mediação, como a criação de um Comitê de Mudanças ou a adoção de uma abordagem híbrida (conectando com a Etapa 2).",
            palavrasChave: [
              "conflito",
              "preditivo",
              "adaptativo",
              "consenso",
              "mediação",
              "Comitê de Mudanças",
              "híbrido",
              "mitigação",
            ],
            conceitos: [
              "Gestão de conflitos",
              "Metodologia preditiva vs adaptativa",
              "Estratégia de mediação",
            ],
          },
        },
      },
      2: {
        titulo: "Ciclo de Vida e Processos",
        exercicios: {
          1: {
            pergunta:
              "Proponha um Ciclo de Vida Híbrido (combinando Preditivo e Adaptativo) para a Nutrientes Delivery. Justifique qual parte do sistema deve seguir cada abordagem.",
            gabarito:
              "O estudante deve propor um modelo híbrido. Módulo de Produção (integração com hardware/sensores, requisitos estáveis) utiliza abordagem Preditiva/Cascata (mais detalhamento no início). Módulo do Cliente (mudanças frequentes, feedback do CEO) utiliza abordagem Adaptativa/Ágil (entregas iterativas/incrementais).",
            palavrasChave: [
              "híbrido",
              "preditivo",
              "adaptativo",
              "Módulo de Produção",
              "Módulo do Cliente",
              "cascata",
              "ágil",
              "iterativo",
              "incremental",
              "sensores",
            ],
            conceitos: [
              "Ciclo de vida híbrido",
              "Abordagem preditiva para sistemas estáveis",
              "Abordagem ágil para requisitos voláteis",
            ],
          },
          2: {
            pergunta:
              "Descreva, em alto nível, as três atividades essenciais que devem ser realizadas durante o Processo de Planejamento deste projeto.",
            gabarito:
              "As três atividades essenciais devem focar em mitigação de riscos e alinhamento: 1. Detalhamento da Baseline do Módulo Preditivo (Produção); 2. Definição do Timebox e tamanho dos Sprints (Módulo Adaptativo); 3. Plano de Comunicação/Gerenciamento de Stakeholders (para gerenciar o CEO e os conflitos).",
            palavrasChave: [
              "baseline",
              "timebox",
              "sprint",
              "comunicação",
              "stakeholders",
              "planejamento",
              "riscos",
              "alinhamento",
            ],
            conceitos: [
              "Processo de planejamento",
              "Baseline de projeto",
              "Timebox e Sprints",
              "Gerenciamento de stakeholders",
            ],
          },
        },
      },
      3: {
        titulo: "Arquitetura de Software",
        exercicios: {
          1: {
            pergunta:
              "Proponha um Estilo Arquitetônico adequado para o Sistema Integrado da Nutrientes Delivery e justifique a escolha considerando escalabilidade e integração com sensores.",
            gabarito:
              "O estudante deve propor Microservices (mais adequado para escalabilidade e isolamento de módulos) ou Arquitetura Orientada a Serviços (SOA). A justificativa deve citar a necessidade de escalar os diferentes módulos de forma independente e a necessidade de integração com sistemas externos (sensores, roteirização).",
            palavrasChave: [
              "microservices",
              "SOA",
              "escalabilidade",
              "isolamento",
              "módulos",
              "integração",
              "sensores",
              "independente",
            ],
            conceitos: [
              "Arquitetura de Microservices",
              "SOA",
              "Escalabilidade horizontal",
              "Isolamento de falhas",
            ],
          },
          2: {
            pergunta:
              "Considerando a insistência do CEO em mudanças no Módulo do Cliente, qual Padrão Arquitetônico você aplicaria especificamente ao Módulo do Cliente para isolar as mudanças? Justifique.",
            gabarito:
              "O estudante deve propor o Padrão Arquitetônico MVC (Model-View-Controller) ou MVVM (Model-View-ViewModel) para o Módulo do Cliente. A justificativa deve focar na separação de interesses, isolando a interface (View) da lógica de negócio (Model). Isso permite que a View (onde o CEO exige mudanças) seja alterada sem impactar a regra de negócio central.",
            palavrasChave: [
              "MVC",
              "MVVM",
              "separação de interesses",
              "View",
              "Model",
              "Controller",
              "isolamento",
              "interface",
              "lógica de negócio",
            ],
            conceitos: [
              "Padrão MVC",
              "Separação de interesses",
              "Flexibilidade da camada de apresentação",
            ],
          },
        },
      },
    },
  },
  2: {
    titulo: "Resolução de Problemas – Scrum e Agilidade",
    etapas: {
      1: {
        titulo: "Análise Ágil e Valores",
        exercicios: {
          1: {
            pergunta:
              "Identifique e cite o Valor do Manifesto Ágil que está sendo violado pela exigência do CEO de mudanças no meio do Sprint. Justifique por que proteger o Sprint é mais importante.",
            gabarito:
              "O estudante deve citar o valor 'Software funcionando mais que documentação abrangente' e o princípio 'Entregar software funcionando frequentemente'. O argumento deve focar em proteger o Sprint para manter o ritmo sustentável do time, entregar a funcionalidade acordada (MVP), cumprir a promessa do Sprint Backlog e garantir transparência.",
            palavrasChave: [
              "Manifesto Ágil",
              "software funcionando",
              "ritmo sustentável",
              "Sprint",
              "transparência",
              "MVP",
              "Sprint Backlog",
            ],
            conceitos: [
              "Valores do Manifesto Ágil",
              "Proteção do Sprint",
              "Ritmo sustentável",
            ],
          },
          2: {
            pergunta:
              "Defina quais Artefatos do Scrum seriam diretamente impactados pela aceitação imediata das duas novas funcionalidades e qual é o papel do PO em protegê-los.",
            gabarito:
              "O estudante deve identificar que o Sprint Backlog e o Incremento (a meta do Sprint) seriam diretamente impactados. O papel do PO é proteger o Sprint Backlog, rejeitando mudanças que impeçam a entrega da meta definida na Sprint Planning.",
            palavrasChave: [
              "Sprint Backlog",
              "Incremento",
              "meta do Sprint",
              "Product Owner",
              "Sprint Planning",
              "proteger",
              "rejeitar",
            ],
            conceitos: [
              "Artefatos do Scrum",
              "Sprint Backlog",
              "Incremento",
              "Papel do Product Owner",
            ],
          },
        },
      },
      2: {
        titulo: "Priorização e Inovação",
        exercicios: {
          1: {
            pergunta:
              "Formule a resposta oficial do PO ao CEO, utilizando um Princípio Ágil para iniciar a negociação, e argumente por que as novas funcionalidades devem ser tratadas como futuras.",
            gabarito:
              "A resposta deve ser uma rejeição formal, mas respeitosa, utilizando o princípio 'Mudanças nos requisitos são bem-vindas, mesmo tardiamente no desenvolvimento'. O PO deve afirmar que as mudanças serão incluídas no Product Backlog, não no Sprint atual. O MVP deve ser entregue primeiro para obter máximo de aprendizado com menor esforço.",
            palavrasChave: [
              "rejeição formal",
              "mudanças bem-vindas",
              "Product Backlog",
              "MVP",
              "aprendizado",
              "menor esforço",
              "Lean",
            ],
            conceitos: [
              "Princípios Ágeis",
              "Negociação com Stakeholders",
              "MVP e Lean Startup",
            ],
          },
          2: {
            pergunta:
              "Proponha usar um ciclo de Design Thinking para validar a real necessidade dos novos recursos (Calculadora Nutricional e PIX Recorrente) antes de investir no desenvolvimento.",
            gabarito:
              "A proposta deve incluir uma etapa leve de Teste de Conceito ou entrevistas antes de priorizar o desenvolvimento, garantindo que as funcionalidades complexas resolvam problemas reais e não apenas desejos do CEO. As funcionalidades devem ser tratadas como riscos e hipóteses a serem validadas (abordagem Lean/Design Thinking).",
            palavrasChave: [
              "Design Thinking",
              "Teste de Conceito",
              "entrevistas",
              "validar",
              "hipóteses",
              "Lean",
              "problemas reais",
            ],
            conceitos: [
              "Design Thinking",
              "Validação de hipóteses",
              "Teste de conceito",
              "Abordagem Lean",
            ],
          },
        },
      },
      3: {
        titulo: "Plano de Ação",
        exercicios: {
          1: {
            pergunta:
              "Descreva o Plano de Ação que você, como PO, executaria imediatamente após a reunião para incorporar as novas funcionalidades ao processo Scrum.",
            gabarito:
              "O plano deve ser sequencial e aderente ao Scrum: 1. Transformar as exigências do CEO em novas User Stories; 2. Inserir essas Stories no Product Backlog (Artefato); 3. Agendar uma Reunião de Refinamento do Product Backlog (Evento), envolvendo o Time de Desenvolvimento para estimar o esforço e priorizar as novas Stories para o próximo Sprint.",
            palavrasChave: [
              "User Stories",
              "Product Backlog",
              "Refinamento",
              "estimar",
              "priorizar",
              "próximo Sprint",
              "Time de Desenvolvimento",
            ],
            conceitos: [
              "User Stories",
              "Product Backlog Refinement",
              "Estimativa de esforço",
              "Priorização",
            ],
          },
        },
      },
    },
  },
  3: {
    titulo: "Simulação Profissional – Riscos e Qualidade",
    etapas: {
      1: {
        titulo: "Gestão de Riscos",
        exercicios: {
          1: {
            pergunta:
              "Identifique a Natureza do Risco que se materializou na perda de R$ 15.000 (problema do Adaptador de Protocolo) e classifique-o.",
            gabarito:
              "O estudante deve identificar a Natureza do Risco como Técnico (falha no componente de software Adaptador e no protocolo) com forte impacto Financeiro (perda de R$ 15.000). A análise deve reconhecer que a falha técnica se materializou em perda financeira real.",
            palavrasChave: [
              "risco técnico",
              "financeiro",
              "adaptador",
              "protocolo",
              "materializado",
              "R$ 15.000",
              "falha",
            ],
            conceitos: [
              "Natureza de riscos",
              "Risco técnico",
              "Impacto financeiro",
              "Materialização de riscos",
            ],
          },
          2: {
            pergunta:
              "Crie uma Matriz de Risco bidimensional (Probabilidade x Impacto) e posicione o risco de 'Falha no Componente de Integração Crítico'. Defina a Ação de Contingência imediata.",
            gabarito:
              "O risco deve ser posicionado com Alto Impacto e Média/Alta Probabilidade. A Ação de Contingência deve incluir: implementação de um Mecanismo de Failover (emissor de alerta automático ou chaveamento para backup manual) ou Redundância de Sensores para comparar leituras antes de acionar alertas críticos.",
            palavrasChave: [
              "matriz de risco",
              "probabilidade",
              "impacto",
              "alto",
              "failover",
              "redundância",
              "alerta",
              "backup",
              "contingência",
            ],
            conceitos: [
              "Matriz de Risco",
              "Análise Probabilidade x Impacto",
              "Plano de Contingência",
              "Mecanismo de Failover",
            ],
          },
        },
      },
      2: {
        titulo: "Gestão da Qualidade e Métricas",
        exercicios: {
          1: {
            pergunta:
              "Calcule a Métrica de Esforço Perdido (MEP) causada pelo retrabalho do desenvolvedor júnior. Sprint tem 10 dias úteis e o desenvolvedor gastou 2 dias no retrabalho.",
            gabarito:
              "MEP = (Tempo Perdido / Duração Total do Sprint) x 100. Cálculo: (2 dias / 10 dias) × 100 = 20%. A interpretação deve ser que 20% do esforço planejado para o Sprint foi consumido por retrabalho não planejado.",
            palavrasChave: [
              "MEP",
              "20%",
              "retrabalho",
              "esforço perdido",
              "2 dias",
              "10 dias",
              "Sprint",
            ],
            conceitos: [
              "Métrica de Esforço Perdido",
              "Custo de retrabalho",
              "Impacto em Sprints",
            ],
          },
          2: {
            pergunta:
              "Proponha uma Métrica de Maturidade em Projeto de Software (SQS) para medir a qualidade dos processos de desenvolvimento e justifique como evitaria o problema de retrabalho.",
            gabarito:
              "O estudante deve propor: Métrica de Densidade de Defeitos (defeitos por mil linhas de código) ou Métrica de Aderência à Documentação (percentual de componentes documentados). A justificativa deve ligar a métrica ao problema: se o código fosse revisado sob uma métrica de Densidade de Defeitos, a falta de documentação seria considerada um defeito de qualidade.",
            palavrasChave: [
              "Densidade de Defeitos",
              "Aderência à Documentação",
              "componentes documentados",
              "qualidade",
              "maturidade",
              "SQS",
            ],
            conceitos: [
              "Sistema de Qualidade",
              "Densidade de Defeitos",
              "Aderência à documentação",
              "Métricas de qualidade",
            ],
          },
        },
      },
      3: {
        titulo: "Documentação e Plano de Prevenção",
        exercicios: {
          1: {
            pergunta:
              "Explique o custo do problema de retrabalho em termos de Riscos pela Ausência de Documentação.",
            gabarito:
              "A explicação deve citar: 1. Alto Risco de Bus Factor (dependência de um único desenvolvedor); 2. Aumento do Custo de Manutenção (Time-to-Market lento); 3. Risco de Segurança (erros de integração por falta de especificação).",
            palavrasChave: [
              "Bus Factor",
              "custo de manutenção",
              "Time-to-Market",
              "segurança",
              "dependência",
              "especificação",
            ],
            conceitos: [
              "Bus Factor",
              "Custo de manutenção",
              "Time-to-Market",
              "Riscos de segurança por falta de documentação",
            ],
          },
          2: {
            pergunta:
              "Proponha um Plano de Documentação Mínima Obrigatória para o Módulo de Nutrição, focando em três itens essenciais que teriam evitado o retrabalho.",
            gabarito:
              "Os três itens essenciais são: 1. Diagrama de Classes/Componentes (para entender a estrutura do código); 2. Especificação das Regras de Negócio do Cálculo (a lógica do Módulo de Nutrição); 3. Manual de Integração da API/Microservice (como consumir o componente sem olhar o código fonte).",
            palavrasChave: [
              "Diagrama de Classes",
              "Regras de Negócio",
              "Manual de Integração",
              "API",
              "documentação mínima",
              "estrutura do código",
            ],
            conceitos: [
              "Documentação técnica mínima",
              "Diagrama de Classes",
              "Regras de negócio",
              "Manual de integração de API",
            ],
          },
        },
      },
    },
  },
  4: {
    titulo: "Aprendizagem entre Pares – Governança e Evolução",
    etapas: {
      1: {
        titulo: "Revisão e Conexão",
        exercicios: {
          1: {
            pergunta:
              "Revise as soluções propostas nas atividades anteriores e identifique como CI/CD, ITIL/COBIT e ESG poderiam ter melhorado essas soluções para a Nutrientes Delivery.",
            gabarito:
              "O aluno deve demonstrar visão sistêmica: CI/CD permite entregas frequentes do Módulo Cliente (conexão com Scrum/Encontro 2); COBIT/ITIL traz governança para decisões (conexão com conflito Preditivo x Adaptativo/Encontro 1); ESG garante responsabilidade social e ambiental (otimização de rotas, LGPD, transparência).",
            palavrasChave: [
              "CI/CD",
              "ITIL",
              "COBIT",
              "ESG",
              "entregas frequentes",
              "governança",
              "LGPD",
              "responsabilidade social",
            ],
            conceitos: [
              "Integração Contínua (CI)",
              "Entrega Contínua (CD)",
              "ITIL",
              "COBIT",
              "ESG",
            ],
          },
        },
      },
      2: {
        titulo: "Mapa Mental Estratégico",
        exercicios: {
          1: {
            pergunta:
              "Para o Nó 1 (Gestão Inicial e Estrutura), correlacione o Projeto da Experiência do Usuário (UX) com a Análise de Requisitos do Módulo Cliente.",
            gabarito:
              "O aluno deve demonstrar que os requisitos do Módulo Cliente não são apenas funcionais, mas devem ser baseados em Elementos de UX, como usabilidade e acessibilidade, para garantir a retenção de usuários na plataforma de delivery.",
            palavrasChave: [
              "UX",
              "usabilidade",
              "acessibilidade",
              "requisitos",
              "retenção",
              "experiência do usuário",
            ],
            conceitos: [
              "UX Design",
              "Usabilidade",
              "Acessibilidade",
              "Requisitos não-funcionais",
            ],
          },
          2: {
            pergunta:
              "Para o Nó 2 (Execução e Agilidade), correlacione Evolução de Software (CI/CD) com a necessidade de Entrega Frequente do Módulo Cliente.",
            gabarito:
              "Para que o Módulo Cliente cumpra o princípio ágil de 'entregas frequentes', é necessária a implementação de CI (Integração Contínua) e CD (Entrega Contínua). Isso permite que as mudanças exigidas pelo CEO sejam testadas e implantadas automaticamente, reduzindo o risco de erros em produção.",
            palavrasChave: [
              "CI",
              "CD",
              "integração contínua",
              "entrega contínua",
              "automaticamente",
              "testes",
              "produção",
              "entregas frequentes",
            ],
            conceitos: [
              "CI/CD",
              "Automação de deploy",
              "Redução de risco em produção",
            ],
          },
          3: {
            pergunta:
              "Para o Nó 3 (Qualidade e Prevenção), correlacione Gerenciamento de Configuração (Controle de Versão) com a necessidade de Documentação.",
            gabarito:
              "A falha de documentação do Encontro 3 é resolvida pelo Controle de Versão. A documentação técnica e o código do Módulo de Produção devem ser rastreáveis e versionados (ex: via Git), garantindo que qualquer mudança na lógica de cálculo nutricional seja auditável e reversível.",
            palavrasChave: [
              "controle de versão",
              "Git",
              "rastreável",
              "versionado",
              "auditável",
              "reversível",
              "documentação",
            ],
            conceitos: [
              "Gerenciamento de Configuração",
              "Controle de Versão (Git)",
              "Rastreabilidade",
              "Auditabilidade",
            ],
          },
          4: {
            pergunta:
              "Para o Nó 4 (Evolução e Governança), correlacione o Paradigma ESG com a necessidade de Governança de TI (COBIT/ITIL).",
            gabarito:
              "O projeto deve ser governado por COBIT (alinhamento estratégico) e ITIL (gestão de serviços de TI). A Nutrientes Delivery deve aplicar ESG: Environmental (E): Otimização de rotas de entrega para reduzir emissão de carbono; Social (S): Proteção de dados sensíveis dos clientes (LGPD) e interface inclusiva; Governance (G): Transparência nos processos de decisão e auditoria de sistemas.",
            palavrasChave: [
              "ESG",
              "COBIT",
              "ITIL",
              "Environmental",
              "Social",
              "Governance",
              "LGPD",
              "carbono",
              "transparência",
              "auditoria",
            ],
            conceitos: [
              "ESG (Environmental, Social, Governance)",
              "COBIT",
              "ITIL",
              "LGPD",
              "Governança de TI",
            ],
          },
        },
      },
      3: {
        titulo: "Compartilhamento e Pitch",
        exercicios: {
          1: {
            pergunta:
              "Prepare um pitch de 5 minutos focando na visão de futuro da Nutrientes Delivery: como a adoção de CI/CD e Governança garantirá a qualidade do produto e a evolução sustentável do negócio.",
            gabarito:
              "O Pitch deve seguir: Início (1 min): Resumo do cenário híbrido e desafios superados; Desenvolvimento (3 min): Explicação de como Governança (COBIT/ITIL) traz ordem ao caos e CI/CD traz velocidade sem perder qualidade; Conclusão (1 min): Visão de futuro com ESG tornando a startup mais atraente para investidores e ética perante consumidores.",
            palavrasChave: [
              "pitch",
              "governança",
              "CI/CD",
              "qualidade",
              "evolução sustentável",
              "investidores",
              "ESG",
              "cenário híbrido",
            ],
            conceitos: [
              "Pitch de negócios",
              "Visão estratégica",
              "Governança como diferencial",
              "Sustentabilidade em TI",
            ],
          },
        },
      },
    },
  },
};

module.exports = gabaritos;
