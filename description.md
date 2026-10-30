# Hardening RedHat ATI - Documento Didático e Técnico do Projeto

Este documento reúne a visão completa da ferramenta de conformidade e hardening para **Red Hat Enterprise Linux 9 (RHEL 9)** desenvolvida para a disciplina de Sistemas Operacionais, atendendo às demandas da Agência Estadual de Tecnologia da Informação (ATI).

O objetivo deste material é servir como **guia de estudo e roteiro de apresentação** para a equipe, permitindo explicar de forma clara, técnica e fundamentada tanto para professores avaliadores quanto para clientes e gestores de segurança da informação o que foi desenvolvido, por que cada decisão foi tomada e qual o impacto real de cada controle no sistema operacional.

---

## 1. Visão Geral do Projeto

### O que é o projeto?
O projeto consiste em uma ferramenta de linha de comando (CLI) desenvolvida em **Python 3.9** (versão nativa do RHEL 9), com suporte a uma interface web visualizadora (React + Vite), voltada para **auditoria, aplicação automatizada e reversão (rollback) de configurações de segurança** em servidores RHEL 9.

A ferramenta opera sob o paradigma de **Infraestrutura e Configuração Declarativa**: em vez de aplicar comandos soltos e scripts ad-hoc (que geram inconsistências e risco de quebrar o servidor), as políticas são definidas em arquivos estruturados em YAML (`rules/*.yaml`). O motor de execução interpreta essas regras, avalia se o sistema está conforme o padrão do **CIS Benchmark** e os requisitos da ATI, corrige as divergências de forma atômica e registra backups pontuais para viabilizar restauração imediata.

### O que a ferramenta é (e o que ela NÃO é)
* **Ela é:** Uma ferramenta de conformidade de configuração do sistema operacional (OS Configuration Hardening & Compliance).
* **Ela NÃO é:** Um antivírus em tempo real (EDR) nem um scanner de vulnerabilidades externas (como Nessus ou OpenVAS). Ela foca em reduzir a **superfície de ataque** fechando portas, eliminando privilégios excessivos, restringindo execução e blindando o kernel e o sistema de arquivos.

---

## 2. As Dores da ATI e a Divisão em Trilhas

A ATI elencou seis grandes vetores de preocupação de segurança (as "Dores da ATI"). O escopo do projeto foi estruturado em três frentes de desenvolvimento cooperativo:

* **Dor 1: Prevenção contra Ransomware e Exploração de Kernel**
* **Dor 2: Proteção de Diretórios de Upload Web contra Shells e RCE**
* **Dor 3: Contenção de Movimentação Lateral na Rede Interna**
* **Dor 4: Gestão de Patches de Pacotes** *(Fora do escopo da entrega de SO)*
* **Dor 5: Revogação de Credenciais e Offboarding de Usuários**
* **Dor 6: Mínimo Privilégio e Controle de Acesso Administrativo**

### Divisão da Equipe:
* **Aluno A (Núcleo):** Arquitetura do motor (`Motor`), orquestração do CLI, gerenciador de backup transacional, rollback, geração de relatórios (stdout e JSON) e suite de testes.
* **Aluno B (Identidade e Privilégio - Dores 5 e 6):** Contas de usuário, sudoers restrito, SSH root login, permissões de autenticação (`/etc/passwd`, `/etc/shadow`), módulos PAM (`faillock`, `pwquality`) e offboarding automatizado.
* **Aluno C (Host, Rede e Dados - Dores 1, 2 e 3):** Opções restritivas de montagem de sistemas de arquivos, firewall local (`firewalld`), portas em escuta, parâmetros de rede e kernel via `sysctl`, diretórios de upload web seguros e confinamento via SELinux.

---

## 3. Arquitetura e Decisões de Engenharia

O projeto foi construído sob regras contratuais rígidas (`docs/CONTRATO.md` e `CLAUDE.md`), essenciais para segurança em ambientes de produção:

### 3.1. Princípio de Execução Segura e Sem Shell
* **Proibido `shell=True`:** Toda chamada a utilitários do sistema operacional é feita via `ctx.runner.executar(["comando", "arg1", "arg2"])`. Isso previne ataques clássicos de Command Injection (injeção de comandos) caso algum parâmetro contenha caracteres de escape como `;`, `&&` ou `|`.
* **Ambiente de Teste FakeRunner:** Todos os comandos externos e operações de sistema são simuláveis através da classe `FakeRunner` nos testes unitários com `pytest`, permitindo validar a lógica completa da ferramenta sem precisar de privilégios de `root` ou de uma máquina virtual dedicada durante o desenvolvimento.

### 3.2. Escrita Atômica de Arquivos
Quando a ferramenta altera arquivos críticos do sistema (como `/etc/fstab`, `/etc/selinux/config` ou `/etc/sysctl.d/99-hardener.conf`):
1. O arquivo original é salvo no diretório de backup da sessão antes de qualquer toque.
2. O novo conteúdo é gerado em um arquivo temporário na mesma partição (`.tmp`).
3. O modo de permissão octal correto é aplicado.
4. O arquivo temporário é movido para o destino final usando `os.replace`.
* **Por que isso importa?** `os.replace` é uma chamada de sistema atômica nos sistemas operacionais POSIX. Se o servidor perder energia ou o processo for interrompido no meio da escrita, o arquivo de configuração original nunca fica corrompido ou cortado pela metade.

### 3.3. Idempotência Rigorosa
Uma operação é dita **idempotente** quando executá-la uma vez produz o efeito desejado, e executá-la dezenas de vezes subsequentes não altera nada e mantém exatamente o mesmo estado estável.
* A ferramenta garante que executar `enforce --apply` duas vezes consecutivas não duplica linhas em arquivos, não refaz modificações e não gera backups redundantes.

### 3.4. Dry-Run por Padrão e Trava de Segurança da VM
* O comando `python3 -m hardener enforce` executa em modo **dry-run** (simulação): inspeciona o sistema, mostra o que seria modificado e os valores atuais vs esperados, sem alterar nenhum byte.
* Modificações reais exigem a flag explícita `--apply` com privilégios de `root` (`sudo python3 -m hardener enforce --apply`).
* **Trava da VM:** Para evitar execuções acidentais nas máquinas de trabalho dos desenvolvedores, o `--apply` exige a presença prévia do arquivo `/etc/hardener-vm`, que deve ser criado manualmente pelo operador na VM de testes.

### 3.5. Sistema de Backup e Rollback
A cada execução de `enforce --apply` que realize alguma alteração, é instanciada uma `SessaoBackup` em `/var/lib/hardener/backups/<timestamp>/`:
* Os arquivos prévios são copiados de forma íntegra para preservação.
* Um arquivo `manifest.json` mapeia quais regras alteraram quais caminhos.
* O comando `python3 -m hardener rollback` lê a última sessão pendente e restaura com precisão cirúrgica o estado anterior, recarregando os serviços afetados.

---

## 4. Catálogo das Primitivas Desenvolvidas (Trilha C)

As primitivas são os blocos construtores que herdam da classe abstrata `Primitiva` (`hardener/checks/base.py`) e implementam a lógica de `validar_parametros`, `verificar`, `descrever` e `corrigir`.

### 4.1. Primitiva `sysctl` (`hardener/checks/sysctl.py`)
* **Conceito:** O comando `sysctl` no Linux é a interface do espaço de usuário para ler e alterar parâmetros em tempo de execução dentro do diretório virtual `/proc/sys/`, controlando a pilha de rede, gerenciamento de memória e proteções do kernel.
* **O que faz:**
  - Consulta o valor ativo diretamente no kernel usando `sysctl -n <chave>`.
  - Verifica a persistência no arquivo dedicado `/etc/sysctl.d/99-hardener.conf`.
  - Na correção, preserva comentários e outras chaves existentes, grava o arquivo de forma atômica com permissão `0644` e aplica imediatamente no kernel com `sysctl -w <chave>=<valor>`.
* **Regras atendidas:** `NET-004`, `NET-005`, `NET-005b`, `NET-006`, `NET-006b`, `KRN-001`, `KRN-001b`, `KRN-001c`, `KRN-001d`.

### 4.2. Primitiva `montagem` (`hardener/checks/montagem.py`)
* **Conceito:** No Linux, o arquivo `/etc/fstab` (File Systems Table) define como as partições e sistemas de arquivos são montados durante a inicialização. Montar partições temporárias com flags restritivas impede que malwares consigam ser executados a partir de pastas públicas de escrita.
* **O que faz:**
  - Analisa a 2ª coluna (ponto de montagem) e a 4ª coluna (opções) do `/etc/fstab`.
  - Verifica o estado da montagem em execução via `findmnt -n -o OPTIONS <ponto>`.
  - Na correção, acrescenta apenas as opções faltantes sem duplicar as existentes. Se o ponto não existir, cria entradas `tmpfs` (para `/tmp` e `/dev/shm`) ou `bind mount` (para `/var/tmp` e `/var/www/uploads`).
  - Executa a remontagem imediata no sistema ativo com `mount -o remount <ponto>` ou `mount <ponto>`.
* **Regras atendidas:** `MNT-001`, `MNT-002`, `MNT-003`, `UPL-003`.

### 4.3. Primitiva `firewalld` (`hardener/checks/firewalld.py`)
* **Conceito:** O `firewalld` é o daemon padrão de firewall dinâmico do RHEL 9 que gerencia zonas de rede e tabelas de filtragem via `nftables`.
* **O que faz:**
  - Valida se o daemon está em execução ativa (`firewall-cmd --state`).
  - Lista serviços ativos (`--list-services`) e portas abertas (`--list-ports`).
  - Aplica o princípio da lista autorizada (allowlist): qualquer serviço ou porta em execução que não esteja expressamente autorizado na política é removido do runtime e da configuração permanente (`--permanent`), aplicando `--reload` ao final.
* **Regras atendidas:** `NET-001`.

### 4.4. Primitiva `portas_escuta` (`hardener/checks/portas_escuta.py`)
* **Conceito:** Portas em escuta (listening ports) em interfaces externas representam serviços de rede aguardando conexões. Portas desnecessárias expostas a redes externas são o principal vetor de invasão e movimentação lateral.
* **O que faz:**
  - Executa `ss -tulnH` para inspecionar sockets TCP e UDP locais.
  - Filtra e ignora por padrão o tráfego de loopback (`127.0.0.1`, `::1`), pois serviços escutando exclusivamente em loopback não são alcançáveis pela rede externa.
  - Compara as portas ativas externas com a lista homologada (ex.: porta 22 para SSH).
  - **Auditoria pura:** Não tenta matar processos às cegas no sistema (o que poderia derrubar aplicações essenciais em produção sem aviso). Em caso de desconformidade, aponta os números de porta e orienta o administrador a verificar com `ss -tulnp`.
* **Regras atendidas:** `NET-002`.

### 4.5. Primitiva `selinux` (`hardener/checks/selinux.py`)
* **Conceito:** O Security-Enhanced Linux (SELinux) implementa Controle de Acesso Mandatório (MAC) no kernel. Mesmo que o usuário invasor obtenha permissão de `root` ou comprometa o processo web, o SELinux restringe o que esse processo pode ler, escrever e executar de acordo com políticas rígidas de domínio e tipo.
* **O que faz:**
  - **Modo `estado`:** Verifica se o SELinux está ativo no kernel via `getenforce` (exigindo `Enforcing`) e assegura a persistência em `/etc/selinux/config` (`SELINUX=enforcing`). Na correção, ajusta o arquivo com backup e ativa no kernel com `setenforce 1`.
  - **Modo `contexto_caminho`:** Inspeciona o rótulo de segurança do arquivo/diretório via `stat -c %C` ou `ls -Zd` e corrige recursivamente via `chcon -R -t <tipo> <caminho>` (por exemplo, aplicando `httpd_sys_rw_content_t` para uploads web).
* **Regras atendidas:** `SYS-001`, `UPL-004`.

### 4.6. Primitiva `servico` (`hardener/checks/servico.py`)
* **Conceito:** Protocolos antigos e não criptografados (como Telnet, Rlogin e TFTP) transmitem dados e senhas em texto claro pela rede e possuem implementações vulneráveis.
* **O que faz:**
  - Consulta o estado de ativação e inicialização via `systemctl is-active` e `systemctl is-enabled` para uma lista de serviços e sockets proibidos.
  - Na correção, encerra e desabilita imediatamente cada unidade detectada com `systemctl disable --now <unidade>`.
* **Regras atendidas:** `SVC-001`.

### 4.7. Primitiva `permissao_arquivo` (Estendida para Trilha C)
* **O que foi acrescentado:**
  - Suporte a `criar_se_ausente` para diretórios que precisam ser garantidos no sistema com modo e proprietário estritos.
  - Suporte a `recursivo_arquivos: true` para varrer árvores de diretórios e assegurar que nenhum arquivo interno possua bits de execução ativos.
  - Suporte a `auditar_world_writable: true` para auditoria de arquivos e diretórios públicos sem sticky bit.
* **Regras atendidas na Trilha C:** `SYS-002`, `UPL-001`, `UPL-002`.

### 4.8. Primitiva `apache_upload` (`hardener/checks/apache_upload.py`)
* **Conceito:** Servidores web Apache costumam interpretar arquivos `.php`, `.cgi` ou `.sh` se colocados no diretório de conteúdo. Se uma aplicação aceitar uploads sem validação rígida, o invasor pode subir um script malicioso (web shell) e obter execução remota de código (RCE).
* **O que faz:**
  - Garante a presença do arquivo de configuração dedicado `/etc/httpd/conf.d/hardener-uploads.conf`.
  - Configura as diretivas `Options -ExecCGI -Indexes -Includes` e `AllowOverride None`, além de um bloco `<FilesMatch>` com `Require all denied` para bloquear a interpretação de qualquer script no diretório de uploads.
* **Regras atendidas:** `UPL-005`.

---

## 5. Mapeamento das 18 Regras da Trilha C e seu Impacto Real

Abaixo está o detalhamento de cada regra criada, o risco que mitiga e o comportamento no sistema:

| ID Regra | Dor ATI | Domínio | Descrição Técnica | Impacto Real de Segurança |
|---|:---:|---|---|---|
| **NET-001** | 3 | Firewall | Firewalld ativo com apenas serviço `ssh` autorizado | Impede que portas acidentalmente abertas por desenvolvedores ou softwares fiquem expostas para a rede corporativa. |
| **NET-002** | 3 | Rede | Auditoria de portas em escuta contra lista (porta 22) | Detecta backdoors, serviços adicionais ou listeners instalados por atacantes sem intervenção disruptiva cega. |
| **NET-003** | 3 | SSH | Restrição de acesso SSH via `AllowGroups wheel` | Garante que apenas usuários pertencentes ao grupo administrativo homologado consigam estabelecer sessões SSH no servidor. |
| **NET-004** | 3 | Kernel/Rede | `net.ipv4.ip_forward = "0"` | Impede que o servidor seja usado como roteador/gateway por um atacante para saltar entre diferentes segmentos de rede (pivot/movimentação lateral). |
| **NET-005** | 3 | Kernel/Rede | `net.ipv4.conf.all.accept_redirects = "0"` | Bloqueia ataques de manipulação de tabela de rotas via ICMP Redirect, prevenindo ataques de Man-in-the-Middle (MitM). |
| **NET-005b**| 3 | Kernel/Rede | `net.ipv4.conf.all.send_redirects = "0"` | Evita que o servidor envie redirects ICMP espúrios para outras máquinas da sub-rede. |
| **NET-006** | 3 | Kernel/Rede | `net.ipv4.conf.all.rp_filter = "1"` | Habilita a validação de rota reversa (Reverse Path Filtering). O kernel descarta pacotes cujos endereços de origem não seriam roteáveis pela mesma interface (proteção contra IP spoofing). |
| **NET-006b**| 3 | Kernel/Rede | `net.ipv4.conf.all.log_martians = "1"` | Registra no log do sistema (`dmesg`/`journald`) pacotes recebidos com endereços IP impossíveis ou forjados (martian packets). |
| **MNT-001** | 1 | Sistema | `/tmp` montado com `noexec,nosuid,nodev` | **Barreira anti-ransomware fundamental:** Impede a execução direta de binários ou scripts baixados na pasta `/tmp`, vetor predileto de instaladores maliciosos. |
| **MNT-002** | 1 | Sistema | `/var/tmp` montado com `noexec,nosuid,nodev` | Mesma proteção aplicada a `/var/tmp`, garantindo que arquivos temporários persistentes também não possam ser executados. |
| **MNT-003** | 1 | Sistema | `/dev/shm` montado com `noexec,nosuid,nodev` | Protege a área de memória compartilhada POSIX (`/dev/shm`) contra injeção e execução de código em memória. |
| **SYS-001** | 1 | Kernel | SELinux em modo `enforcing` no boot e runtime | Garante que as políticas de controle de acesso mandatório estejam ativas e bloqueando desvios de privilégio, mesmo se um serviço for explorado. |
| **SYS-002** | 1 | Sistema | Auditoria de arquivos world-writable sem sticky bit | Detecta arquivos onde qualquer usuário do sistema tem permissão de escrita, prevenindo sequestro de arquivos e sobrescrita de binários. |
| **SVC-001** | 1 | Serviços | Desativação de telnet, rsh, rlogin, tftp e vsftpd | Elimina portas de comunicação legadas que transmitem credenciais em texto claro e não possuem autenticação moderna robusta. |
| **KRN-001** | 1 | Kernel | `kernel.randomize_va_space = "2"` | Habilita ASLR (Address Space Layout Randomization) completo para heap, stack e bibliotecas compartilhadas, inviabilizando exploits de buffer overflow. |
| **KRN-001b**| 1 | Kernel | `kernel.kptr_restrict = "1"` | Oculta os endereços de memória dos ponteiros do kernel em `/proc/kallsyms`, dificultando a exploração de vulnerabilidades de kernel privilege escalation. |
| **KRN-001c**| 1 | Kernel | `kernel.dmesg_restrict = "1"` | Restringe a leitura dos logs de inicialização e kernel (`dmesg`) exclusivamente a usuários com capacidade `CAP_SYSLOG` ou `root`. |
| **KRN-001d**| 1 | Kernel | `fs.suid_dumpable = "0"` | Impede a geração de core dumps de programas com bit SUID/SGID, evitando vazamento de senhas e chaves armazenadas na memória para o disco. |
| **UPL-001** | 2 | Web/Upload | Arquivos internos em `/var/www/uploads` sem execução (`0640`) | Garante que arquivos enviados por usuários nunca possuam permissão de execução no sistema de arquivos. |
| **UPL-002** | 2 | Web/Upload | Diretório `/var/www/uploads` com `0750` e dono `root:apache` | O servidor web consegue salvar arquivos no diretório, mas usuários locais comuns não conseguem bisbilhotar nem alterar sua estrutura. |
| **UPL-003** | 2 | Web/Upload | Montagem dedicada em `/var/www/uploads` com `noexec,nosuid,nodev` | Mesmo se o atacante conseguir gravar um binário ELF ou script no diretório, o próprio sistema de arquivos rejeita a execução no nível do kernel (`Permission denied`). |
| **UPL-004** | 2 | SELinux | Contexto SELinux `httpd_sys_rw_content_t` em `/var/www/uploads` | Autoriza o Apache a escrever e ler arquivos no diretório, mas proíbe terminantemente o domínio do Apache de executar scripts sob esse contexto. |
| **UPL-005** | 2 | Apache | Diretivas `-ExecCGI -Indexes -Includes` e `AllowOverride None` | Configuração defensiva no servidor HTTP que instrui o Apache a tratar tudo dentro de uploads como arquivo estático não executável. |

---

## 6. Dicionário Didático de Termos e Jargões Técnicos

Para facilitar a explicação em apresentações e bancas avaliadoras:

* **Hardening:** Processo de fortalecimento e blindagem de um sistema operacional através da remoção de softwares desnecessários, fechamento de portas, aplicação de políticas estritas de autenticação e mitigação de fraquezas arquiteturais.
* **CIS Benchmark:** Guias de boas práticas e configurações de consenso internacional mantidos pelo *Center for Internet Security*, adotados globalmente como padrão de conformidade e auditoria de segurança.
* **Idempotência:** Capacidade de executar a mesma operação múltiplas vezes seguidas sem alterar o resultado final além da primeira aplicação, garantindo previsibilidade e ausência de efeitos colaterais.
* **Escrita Atômica:** Técnica onde um arquivo novo é criado em um local temporário e substituído sobre o original em uma única operação indivisível no sistema de arquivos (`rename`/`os.replace`). Se ocorrer uma falha, o arquivo antigo permanece intacto.
* **ASLR (Address Space Layout Randomization):** Mecanismo de segurança do kernel que sorteia as posições de memória da pilha (stack), da área de alocação dinâmica (heap) e das bibliotecas na execução de cada processo, impedindo que um atacante preveja onde injetar código malicioso.
* **Flags de Montagem (`noexec`, `nosuid`, `nodev`):**
  - `noexec`: O kernel proíbe a execução de qualquer binário ou script localizado naquele sistema de arquivos.
  - `nosuid`: O kernel ignora os bits SUID e SGID dos arquivos, impedindo que executáveis assumam privilégios de `root`.
  - `nodev`: O kernel não interpreta dispositivos de bloco ou caracteres especiais dentro daquela partição.
* **Reverse Path Filtering (`rp_filter`):** Checagem de integridade de rede no kernel que valida se o pacote IP recebido por uma interface teria sua resposta enviada pela mesma interface, evitando falsificação de endereço de origem (IP Spoofing).
* **SELinux (Enforcing vs Permissive vs Disabled):**
  - `Enforcing`: As políticas de segurança são ativamente aplicadas e violações são bloqueadas e registradas em log.
  - `Permissive`: Violações geram alertas e registros de log (`audit.log`), mas as ações não são bloqueadas (ideal para diagnóstico).
  - `Disabled`: O subsistema de segurança está completamente descarregado do kernel.
* **Sticky Bit (em diretórios):** Permissão especial (bit `1000` em octal) que garante que, em uma pasta pública de gravação (como `/tmp`), apenas o dono do arquivo ou o `root` consiga apagar ou renomear seu respectivo arquivo, mesmo que todos tenham permissão de escrita no diretório.
* **Web Shell / RCE (Remote Code Execution):** Script malicioso (em PHP, Python ou Bash) carregado por invasores em diretórios de servidores web com a finalidade de executar comandos remotamente através do navegador.

---

## 7. Roteiro Prático para a Demonstração na VM RHEL 9

Para apresentar o projeto para o professor e clientes na máquina virtual de testes:

### Passo 1: Preparação da VM Limpa
1. Inicie a máquina virtual RHEL 9 limpa com snapshot `base-limpa` criado.
2. Certifique-se de que a trava de segurança existe:
   ```bash
   sudo touch /etc/hardener-vm
   ```

### Passo 2: "Sujar" o Servidor com as Violações de Teste
Execute o script fornecido no repositório:
```bash
sudo bash demo/sujar_servidor.sh
```
*O script criará de forma controlada as falhas de segurança das Trilhas A, B e C: afrouxará o firewall liberando a porta 8080, desligará o ASLR e proteções de rede via sysctl, colocará o SELinux em Permissive, criará scripts executáveis dentro de `/var/www/uploads`, adicionará usuários e acessos indevidos no sudoers e SSH.*

### Passo 3: Executar a Auditoria (Modo Somente Leitura)
```bash
sudo python3 -m hardener audit
```
* **O que mostrar:** O relatório apresentará diversas regras em status `NAO_CONFORME`, listando com exatidão o que está irregular, o valor atual do sistema e o valor esperado. Nenhuma modificação é feita no sistema.

### Passo 4: Executar o Enforce em Modo Simulação (Dry-Run)
```bash
sudo python3 -m hardener enforce
```
* **O que mostrar:** O status das regras não conformes mudará para `SERIA_CORRIGIDO`, detalhando a ação planejada sem tocar em nenhum arquivo.

### Passo 5: Aplicar as Correções de Hardening
```bash
sudo python3 -m hardener enforce --apply
```
* **O que mostrar:**
  - O motor gera uma sessão de backup em `/var/lib/hardener/backups/<timestamp>/`.
  - Todas as regras aplicadas mudam para `CORRIGIDO`.
  - O firewalld fecha a porta 8080 e recarrega.
  - O SELinux volta a `Enforcing` e o arquivo `/etc/selinux/config` é blindado.
  - O arquivo `/etc/fstab` recebe as restrições `noexec,nosuid,nodev` e as montagens são remontadas.
  - O Apache ganha as restrições anti-script em `/etc/httpd/conf.d/hardener-uploads.conf`.

### Passo 6: Provar a Idempotência
Execute o comando novamente:
```bash
sudo python3 -m hardener enforce --apply
```
* **O que mostrar:** Todas as regras reportam `CONFORME`, nenhuma nova sessão de backup é criada e nenhuma recarga de serviço desnecessária é disparada.

### Passo 7: Prova Real de Segurança (Demonstração de Bloqueio)
1. Tente executar um script dentro de `/tmp` ou `/var/www/uploads`:
   ```bash
   cd /var/www/uploads
   echo 'echo "ataque"' > teste.sh
   chmod +x teste.sh
   ./teste.sh
   ```
   **Resultado:** O shell do sistema operacional retornará imediatamente:
   `bash: ./teste.sh: Permission denied` (bloqueado diretamente no kernel pelo `noexec` da montagem).
2. Tente verificar o status do SELinux:
   ```bash
   getenforce
   ```
   **Resultado:** `Enforcing`.

### Passo 8: Demonstrar a Reversão Segura (Rollback)
```bash
sudo python3 -m hardener rollback
```
* **O que mostrar:** O motor lê o manifesto da sessão de backup, restaura fielmente os arquivos prévios na ordem inversa e remove arquivos novos criados, retornando a máquina ao estado exato pré-enforce.

---

## 8. Status dos Testes Automatizados no Repositório

O projeto conta com suíte abrangente de testes unitários sem dependência externa além do `PyYAML`:

```bash
$ python3 -m hardener validar
36 regra(s) válida(s) em /app/applet/rules
36 regra(s) com referência CIS ainda A CONFIRMAR

$ pytest
============================= 114 passed in 0.50s ==============================
```

* **114 testes unitários cobrindo:** Validação de esquemas, idempotência, escrita atômica, integridade de backups, recarga de serviços e tratamento de erros inesperados.

---

## 9. Próximos Passos e Recomendações

1. **Validação na VM Física/Virtual (Checklist `VALIDAR_NA_VM.md`):**
   - Executar a lista de validações marcando cada caixa de teste na máquina virtual com a versão oficial do RHEL 9.
2. **Conferência das Referências do CIS Benchmark:**
   - Abrir o PDF oficial do *CIS Red Hat Enterprise Linux 9 Benchmark* e substituir os marcadores temporários `"(A CONFIRMAR o item no benchmark)"` pelos números oficiais das seções (ex.: `1.1.2`, `3.1.2`, `5.2.1`).
3. **Integração com a Interface Web:**
   - O repositório já inclui a base visualizadora em React + Vite para carregar e exibir relatórios de auditoria exportados em JSON (`--json relatorio.json`).
