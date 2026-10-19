# Oracle Always Free para a IDE

Esta implantação tem uma restrição do proprietário: **nenhuma despesa nova**.
O plano é usar somente recursos elegíveis ao Always Free, na região principal
da conta, sem upgrade para cobrança. Os créditos promocionais de 30 dias não
servem como base para manter a IDE disponível depois do período de teste.

O Turso continua guardando os dados acadêmicos. A Oracle hospedará apenas os
ambientes pessoais da IDE; não receberá cópia de usuários, senhas ou do banco.

## Cotas verificadas e proposta inicial

Em 19/10/2026, o [catálogo oficial usado pela página Free Tier](https://www.oracle.com/a/ocom/docs/oci-free-tier_v1.json)
informava **1.500 OCPU-horas e 9.000 GB-horas de memória por mês** para Ampere A1.
Isso permite planejar conservadoramente até 2 OCPUs e 12 GB continuamente num
mês de 31 dias: 1.488 OCPU-horas e 8.928 GB-horas. Não presuma a antiga oferta
de 4 OCPUs/24 GB sem verificar o direito efetivo da conta.

O mesmo catálogo informa 200 GB totais de armazenamento de boot/bloco, até dois
volumes de bloco, duas VCNs e até 10 TB mensais de saída. Esses recursos são
compartilhados com os recursos que a conta já utiliza; não são uma cota nova
para cada aplicação. O painel e os termos aplicáveis à conta precisam confirmar
a elegibilidade e o consumo antes de qualquer criação.

Proposta a verificar, ainda **não provisionada**:

| Item | Configuração proposta |
| --- | --- |
| Instância | `VM.Standard.A1.Flex`, 2 OCPUs e 12 GB de memória. |
| Sistema | Imagem oficial Ubuntu Linux ARM64, sem licença de marketplace. |
| Disco | Boot de 50 GB, sem expansão automática ou backups pagos. |
| Rede | Região principal da conta; uma VCN básica, sem NAT ou balanceador adicional. |
| IDE | Docker, code-server, volumes próprios por usuário e limites de simultaneidade. |
| Banco e site | Permanecem no Turso e na Vercel. |

O digest da imagem base do code-server já inclui `linux/arm64` e `linux/amd64`.
A imagem completa com compiladores e o funcionamento em uma VM ARM real ainda
precisam ser construídos e testados nessa arquitetura. A cota gratuita não
garante que uma turma inteira consiga usar a IDE simultaneamente.

## Conferência sem compartilhar chaves

Primeiro confirme no painel OCI a região principal e se a conta permanece no
Free Tier, sem upgrade para Pay As You Go. Uma conta em Trial pode criar recursos
Always Free, mas os recursos precisam ser identificados como Always Free antes
da criação. Não use o saldo de créditos para justificar recursos fora da cota.
Uma conta já convertida para cobrança exige avaliação separada: alertas de
orçamento não bloqueiam automaticamente gastos.

A ferramenta [oracle_preflight.py](../services/ide-gateway/deploy/oracle_preflight.py)
usa o OCI CLI autenticado no Cloud Shell. Ela lista a região principal, instâncias,
discos e redes de todos os compartimentos visíveis à consulta. Inclui discos
desanexados e instâncias paradas no planejamento. Falhas de acesso, informações
ausentes ou inventário incompleto interrompem a verificação.

No painel OCI, abra o **Cloud Shell** pelo ícone de terminal no topo. Para
consultar sem clonar o projeto, baixe o arquivo desta branch para uma pasta
temporária e execute-o:

```bash
ads_check_dir=$(mktemp -d)
curl --fail --show-error --location --proto '=https' \
  'https://raw.githubusercontent.com/dansfisica85/adsanhanguera/codex/vscode-private-ide/services/ide-gateway/deploy/oracle_preflight.py' \
  --output "$ads_check_dir/oracle_preflight.py" && \
python3 "$ads_check_dir/oracle_preflight.py"
```

Se já houver um checkout desta branch no Cloud Shell, basta:

```bash
python3 services/ide-gateway/deploy/oracle_preflight.py
```

Se `OCI_TENANCY` não estiver definido nesse Cloud Shell, informe o OCID da conta
por `--tenancy-id`. O OCID é um identificador, não uma senha. A ferramenta não
precisa receber chaves privadas, senhas ou tokens pelo chat.

O relatório expõe somente região, contagens e tamanhos. Não imprime nomes de
recursos, OCIDs, credenciais ou respostas de erro do CLI. A ferramenta só aceita
operações de listagem: não cria, modifica, exclui ou contrata recursos.

`fits_planning_ceilings: true` significa somente que a proposta cabe nos tetos
conservadores do relatório. **Não comprova custo zero, capacidade disponível ou
consumo mensal restante.** O relatório mantém `billing_verified` e
`capacity_verified` como `false`. Por prudência, o teto de dois volumes da
ferramenta inclui também os volumes de boot; ele pode ser mais restritivo que a
elegibilidade real da conta. Nenhum recurso existente deve ser removido para
abrir espaço sem uma solicitação específica do proprietário.

## O que falta para publicar

Após conferir a conta, as cotas e a marcação Always Free, ainda é necessário
criar a VM elegível, preparar Docker/IDE, configurar nome DNS e HTTPS gratuitos,
e adicionar `IDE_GATEWAY_URL`/`IDE_GATEWAY_TOKEN` à Vercel. Um domínio comprado
não faz parte deste plano; um subdomínio gratuito precisa ser escolhido e
verificado. Para a aba embutida, plataforma e IDE precisam estar no mesmo site,
como explicado no [guia da integração](vscode.md).

Se a Oracle indicar falta de capacidade gratuita, não troque para um shape pago,
outra região com cobrança ou upgrade da conta. A [FAQ oficial](https://www.oracle.com/cloud/free/faq/)
orienta tentar outro domínio de disponibilidade na região principal, quando
houver, ou aguardar capacidade. A Oracle também prevê retomada de recursos
gratuitos por inatividade e não oferece a mesma garantia de disponibilidade de
uma contratação paga.

## Testes da consulta

```bash
python3 -m unittest discover -s services/ide-gateway/test -p 'test_*.py' -v
```

Os testes verificam inventário entre compartimentos e domínios de disponibilidade,
uso da região principal, contagem de recursos parados, ausência de permissão e
rejeição de operações de criação. Não acessam uma conta Oracle real.
