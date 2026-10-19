# Servidor da aba VS Code

Serviço Node.js sem dependências npm, executado em um servidor Linux com Docker
28 ou superior. Ele inicia um `code-server` por usuário autenticado, com volume,
rede, processos e origem do navegador próprios. Não conecta ao Turso e não
recebe nomes, e-mails, senhas ou JWTs dos usuários.

O proprietário solicitou implantação sem nenhuma despesa nova. A preparação
específica para sua conta Oracle está em [Oracle Always Free](../../docs/oracle-always-free.md),
incluindo uma consulta de inventário que não cria nem altera recursos.

## Preparar o servidor

Use um servidor dedicado à IDE, Node.js 22+ e Docker 28+. Comece com recursos
compatíveis com a simultaneidade desejada: cada ambiente tem por padrão limite
de 1 GiB de RAM, uma CPU e 256 processos. O gateway limita dez ambientes ativos;
esses valores são configuráveis. Reserve espaço para imagens e volumes e
configure quotas/monitoramento de disco e backups conforme a demanda.

Na raiz deste repositório:

```bash
docker build -t ads-ide-workspace:4.141.0 services/ide-gateway
node --test services/ide-gateway/test/gateway.test.mjs
```

A base oficial está fixada por digest no Dockerfile. A imagem adiciona Node.js,
npm, Python, compiladores C/C++ e JDK, pelos repositórios assinados do Debian.
Git e code-server vêm da base. Não desative assinaturas ou TLS em caso de erro.
Em redes com proxy, passe os argumentos de build HTTP_PROXY/HTTPS_PROXY e
resolva o proxy no contexto do Docker; não grave credenciais no Dockerfile.

Crie a configuração **fora do checkout**, por exemplo `/etc/ads-ide.env`, com
permissão restrita ao serviço. Use `.env.example` como referência, substituindo
os domínios e gerando um token aleatório próprio de pelo menos 32 caracteres.
Configure o mesmo token como `IDE_GATEWAY_TOKEN` na plataforma, e a origem pública
do gateway como `IDE_GATEWAY_URL`. Não reutilize JWT_SECRET ou credenciais Turso.

```bash
cd /opt/adsanhanguera/services/ide-gateway
node --env-file=/etc/ads-ide.env server.mjs
```

Para manter o processo em execução, adapte `ads-ide.service` ao caminho e usuário
do servidor. O usuário do gateway precisa controlar o Docker; somente esse
serviço administrativo recebe essa permissão. O socket Docker, credenciais e
arquivos do host nunca são montados nos ambientes de alunos.

## DNS, HTTPS e navegador

Configure DNS e certificado TLS para **ambos** `ide.seudominio.com` e
`*.ide.seudominio.com`, apontando para o servidor. Cada conta usa uma origem como
`u42.ide.seudominio.com`: isso também separa cookies, localStorage e service
workers entre usuários. Apenas pastas separadas em uma mesma origem não seriam
suficientes para esse isolamento.

Adapte `nginx.conf.example` com o certificado que cobre o domínio e seu wildcard.
O gateway escuta somente em loopback, porta 3100. O proxy HTTPS deve preservar
Host e permitir WebSocket; não exponha as portas internas dos containers. Em
produção, o gateway exige HTTPS e cookies Secure/HttpOnly sem atributo Domain.
`PLATFORM_ORIGIN` deve ser a origem exata da plataforma. Para usar a IDE embutida,
configure plataforma e IDE no mesmo domínio principal (ex.: `app.exemplo.com`
e `ide.exemplo.com`). Em sites distintos, navegadores podem bloquear IndexedDB e
localStorage usados pelo VS Code, mesmo com cookies particionados. A interface
oferece abertura em nova aba como alternativa nesses casos.

O fluxo é: plataforma autenticada → ticket de uso único (60 s) → POST ao gateway
→ POST de uso único à origem pessoal → cookie de sessão (máximo 30 minutos).
Sair da plataforma revoga os tickets/cookies, fecha as conexões WebSocket e
solicita parada do container. Volumes não são apagados. Senhas e perfis da
plataforma não são alterados. Ao expirar a sessão, reabra a IDE pela plataforma.
Reiniciar o gateway invalida todas as sessões da IDE, preservando os arquivos.

## Rede, extensões e código executado

`IDE_NETWORK_MODE=isolated` é o padrão: uma rede interna por usuário, sem acesso
externo pelos terminais. Os compiladores da imagem funcionam offline. Para
baixar extensões Open VSX, pacotes e repositórios, o operador pode habilitar
`internet` em um servidor com política de saída que bloqueie redes internas,
metadados da nuvem e serviços administrativos. As redes de usuários continuam
separadas. Uma rede existente com política diferente não é reaproveitada
silenciosamente; pare o serviço e migre os containers/redes preservando volumes.

Não há garantia de compatibilidade com todas as extensões ou serviços
proprietários Microsoft. Estes ambientes usam code-server, não o produto
Microsoft VS Code comercial. Containers compartilham o kernel do host: para
executar código de terceiros em uma implantação pública, use um runtime de
sandbox compatível (por exemplo gVisor), host dedicado, atualizações e limites
operacionais. Não hospede banco de produção ou credenciais acadêmicas nesse host.

## Configuração

| Variável | Padrão / finalidade |
| --- | --- |
| `IDE_GATEWAY_TOKEN` | Obrigatório; segredo somente entre servidores. |
| `IDE_PUBLIC_URL` | Obrigatório; origem base HTTPS da IDE. |
| `PLATFORM_ORIGIN` | Obrigatório; origem HTTPS da plataforma. |
| `IDE_BIND_ADDRESS`, `IDE_PORT` | `127.0.0.1`, `3100`. |
| `IDE_WORKSPACE_IMAGE` | `ads-ide-workspace:4.141.0`. |
| `IDE_RESOURCE_PREFIX` | `ads-ide`; separa recursos de implantações. |
| `IDE_MAX_RUNNING_USERS` | `10`, até 100 ambientes simultâneos. |
| `IDE_MEMORY_MB`, `IDE_CPUS`, `IDE_PIDS_LIMIT` | `1024`, `1`, `256`. |
| `IDE_SESSION_MINUTES`, `IDE_IDLE_MINUTES` | `30`, `30`. |
| `IDE_NETWORK_MODE` | `isolated`; alternativa explícita `internet`. |

`GET /health` exige Docker e imagem disponíveis. O teste funcional também precisa
criar sessão e abrir a IDE: saúde do gateway sozinha não valida o workspace.
`npm test` na raiz inclui testes de autenticação, separação entre usuários,
tickets, logout, origens, proxy e frontend. `npm run test:docker` nesta pasta
executa um smoke real de containers, execução de código e persistência; ele
cria e remove somente recursos com um prefixo aleatório próprio.

Para desenvolvimento local, use `IDE_PUBLIC_URL=http://localhost:4100`,
`PLATFORM_ORIGIN=http://app.ide.localhost:3001` e `IDE_ALLOW_HTTP_LOOPBACK=true`.
Abra a plataforma no navegador com esse hostname. Workspaces usam
`u<ID>.ide.localhost`, resolvido em loopback pelos navegadores atuais, no mesmo
site da plataforma. Requisições de verificação pelo terminal podem usar localhost.
Essa exceção HTTP é restrita ao desenvolvimento local. Não publique localhost
como link para alunos e não use o banco de produção nos testes.

O volume `<prefix>-u<ID>-home` preserva arquivos e extensões. A manutenção para
apenas ambientes ociosos; nunca remove volumes. Para atualizar a imagem, pare e
recrie os containers administrativamente, preservando seus volumes e rótulos de
propriedade. Faça backup antes de operações de manutenção.
