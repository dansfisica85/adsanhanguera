# VS Code dentro da plataforma

A aba **VS Code** abre uma IDE baseada em `code-server`, dentro da plataforma,
para os quatro perfis autenticados: aluno, Aluna Especial, coordenador e admin.
Cada usuário recebe um container e armazenamento próprios. O editor de projetos
acadêmicos continua disponível, com suas permissões atuais.

## O que muda nos dados

- Não há migração, atualização de perfis, mudança de senha ou escrita nas tabelas
  acadêmicas para habilitar a IDE.
- A integração usa apenas o ID obtido pela autenticação existente. O navegador
  não pode escolher o usuário dono do ambiente.
- Arquivos, extensões e configurações do VS Code ficam em volumes separados no
  servidor de IDE. Projetos acadêmicos existentes não são importados nem
  sobrescritos automaticamente. É possível baixar arquivos pelo editor atual
  e enviá-los ao VS Code quando o próprio usuário desejar.
- O coordenador também pode programar em seu ambiente pessoal; isso não muda
  suas permissões de leitura nos projetos acadêmicos.

## Recursos e limites

O serviço oferece explorador de arquivos, editor, terminal Linux, Git, extensões
compatíveis, execução e depuração de código. As ferramentas de linguagem vêm da
imagem de workspace descrita na [documentação do servidor](../services/ide-gateway/README.md).
Compilar cada linguagem depende do compilador e das extensões instalados nesse
ambiente.

`code-server` usa o código aberto do VS Code e o catálogo Open VSX. Não é o produto
Microsoft VS Code hospedado pela Microsoft: algumas extensões proprietárias,
serviços e licenças Microsoft não estão disponíveis. Não se promete paridade
com todas as extensões do aplicativo desktop.

## Hospedagem

A aplicação atual pode continuar na Vercel. A IDE precisa de um servidor Linux
persistente com Docker, armazenamento e HTTPS. Funções serverless da Vercel não
mantêm terminais, servidores de linguagem e conexões WebSocket de longa duração.

Para a implantação com orçamento zero solicitada neste projeto, veja a
[preparação para Oracle Always Free](oracle-always-free.md). A conta, suas cotas e
a disponibilidade gratuita precisam ser conferidas antes de criar recursos.

1. Prepare o servidor seguindo [services/ide-gateway/README.md](../services/ide-gateway/README.md).
2. Defina o endereço HTTPS da IDE, seu DNS/certificado wildcard para as origens
   pessoais (`u<ID>.ide.seudominio.com`) e permita somente a origem HTTPS da
   plataforma no serviço. O proxy reverso deve suportar WebSocket. Para a IDE
   embutida, use o mesmo domínio principal da plataforma; isso permite o uso de
   cookies e armazenamento do navegador no iframe.
3. Gere um segredo aleatório de pelo menos 32 caracteres fora do repositório e
   configure o mesmo `IDE_GATEWAY_TOKEN` no serviço e na hospedagem da plataforma.
   Não use a chave JWT ou um token Turso como segredo da IDE.
4. Configure na plataforma:

   | Variável | Finalidade |
   | --- | --- |
   | `IDE_GATEWAY_URL` | Origem HTTPS pública do serviço, sem caminho ou query. |
   | `IDE_GATEWAY_TOKEN` | Segredo servidor a servidor, nunca enviado ao navegador. |

5. Faça uma nova publicação da plataforma após configurar as variáveis.

Sem essas duas variáveis válidas, a aba informa que o VS Code ainda não está
disponível e oferece acesso ao editor de projetos existente. A aplicação não
precisa delas para continuar funcionando.

## Sessões

O backend revalida a sessão do usuário pelas regras atuais e pede ao serviço uma
entrada para o seu ambiente. O navegador recebe um ticket curto, de uso único,
enviado por formulário POST e trocado na origem privada daquele usuário. O JWT da plataforma e o segredo do gateway não vão
para a URL da IDE. O serviço usa um cookie HttpOnly e expiração limitada; sair da
plataforma solicita a revogação da sessão da IDE.

Se o navegador bloquear cookies de terceiros, use **Abrir em nova aba**. A sessão
do serviço deve ser estabelecida novamente após expirar. Se o serviço estiver
indisponível durante o logout, a revogação imediata não pode ser confirmada; a
expiração do serviço limita a duração restante.

## Validação antes de disponibilizar aos usuários

Execute `npm test` na raiz e os testes/smoke do serviço descritos em seu README.
Em um banco de desenvolvimento separado, confirme o login de cada perfil, o
acesso ao VS Code, a criação de um arquivo, uso do terminal, persistência ao
reiniciar e isolamento entre dois usuários. Confirme que sair encerra o acesso
da sessão da IDE. Nenhum teste de infraestrutura precisa apontar ao Turso de
produção.

Dimensione CPU, memória, disco e política de acesso à rede conforme a quantidade
de usuários simultâneos. Volumes da IDE precisam de backup próprio; não fazem
parte do backup do banco acadêmico. A documentação do serviço descreve os
limites de isolamento e os requisitos para executar código de terceiros.
