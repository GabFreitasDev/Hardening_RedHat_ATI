# Hardening RedHat ATI - Documento Arquitetural, Didático e Operacional

---

## Sumário
1. [Visão Geral do Projeto e Propósito](#1-visão-geral-do-projeto-e-propósito)
2. [O Conceito Central: O que é uma "Primitiva" e por que essa palavra?](#2-o-conceito-central-o-que-é-uma-primitiva-e-por-que-essa-palavra)
3. [Arquitetura de Engenharia e Princípios de Design](#3-arquitetura-de-engenharia-e-princípios-de-design)
4. [Estrutura Completa de Arquivos e Módulos do Repositório](#4-estrutura-completa-de-arquivos-e-módulos-do-repositório)
5. [Catálogo Completo das 13 Primitivas de Hardening](#5-catálogo-completo-das-13-primitivas-de-hardening)
6. [Tabela Completa das 36 Regras de Segurança e Impacto Real](#6-tabela-completa-das-36-regras-de-segurança-e-impacto-real)
7. [Módulo Especializado de Offboarding e Higienização de Contas (Dor 5)](#7-módulo-especializado-de-offboarding-e-higienização-de-contas-dor-5)
8. [Roteiro Prático de Demonstração (Para Bancas e Apresentações)](#8-roteiro-prático-de-demonstração-para-bancas-e-apresentações)
9. [Dicionário de Termos e Jargões Técnicos](#9-dicionário-de-termos-e-jargões-técnicos)
10. [Conclusão e Próximos Passos](#10-conclusão-e-próximos-passos)

---

## 1. Visão Geral do Projeto e Propósito

### 1.1. Contexto e Motivação
Em ambientes de computação corporativa e infraestrutura governamental — como o ecossistema atendido pela **Agência Estadual de Tecnologia da Informação (ATI)** —, servidores executando distribuições Linux como o **Red Hat Enterprise Linux 9 (RHEL 9)** sustentam bases de dados, portais de serviços públicos e APIs críticas.

Por padrão de instalação, sistemas operacionais modernos priorizam a interoperabilidade e a facilidade de configuração inicial em detrimento de uma postura defensiva restritiva. Isso significa que serviços de rede secundários podem permanecer ativos, partições temporárias como `/tmp` permitem a execução arbitrária de binários compilados, privilégios administrativos podem ser concedidos sem rastreabilidade e parâmetros de kernel podem tolerar roteamento indevido de pacotes.

A ferramenta **Hardening RedHat ATI** foi desenvolvida como uma solução unificada de engenharia de software para **auditar, aplicar e reverter configurações de segurança de forma automatizada, determinística e declarativa**, fundamentada no benchmark internacional do **Center for Internet Security (CIS Benchmark for RHEL 9)** e nas necessidades reais de defesa da ATI.

### 1.2. O que a Ferramenta É e o que NÃO É
* **O que ela é:** Um motor de conformidade e aplicação de estado de configuração (Configuration Compliance & Hardening Engine). Ela analisa o sistema contra uma política declarativa em YAML, aponta desvios e os corrige de forma atômica e idempotente.
* **O que ela NÃO é:**
  - Não é um antivírus em tempo real (EDR): ela não monitora memória nem intercepta chamadas de sistema de processos de terceiros em runtime.
  - Não é um scanner externo de portas ou vulnerabilidades de rede (como Nmap ou Nessus): ela opera a partir de dentro do sistema operacional (*in-host*).
  - Não é uma ferramenta de gestão de patches/atualizações de pacotes (Dor 4 da ATI): o escopo foca exclusivamente na **configuração interna do sistema operacional**.

---

## 2. O Conceito Central: O que é uma "Primitiva" e por que essa palavra?

Uma das dúvidas mais comuns de quem analisa o código da ferramenta é: **"Por que vocês chamam os módulos de verificação de 'primitivas'?"**

### 2.1. Origem e Significado do Termo
Na ciência da computação e na arquitetura de software, uma **primitiva** (do latim *primitivus*, o primeiro de seu tipo, fundamental) é a **menor unidade elementar e indivisível de operação** fornecida por um sistema, a partir da qual comportamentos mais complexos podem ser construídos.

Por exemplo:
- Na física, as partículas fundamentais (quarks, elétrons) são as primitivas da matéria.
- Na geometria, o ponto e a reta são primitivas.
- Em sistemas operacionais, chamadas como `fork()`, `read()` e `write()` são primitivas de sistema (syscalls).
- Em criptografia, funções de hash (`SHA-256`) e cifras de bloco (`AES`) são primitivas criptográficas.

No nosso projeto, **uma Primitiva é a menor unidade reutilizável de controle de configuração do sistema operacional**.

### 2.2. Por que não usar apenas scripts em Shell (`.sh`) cheios de `sed`, `awk` e `systemctl`?
A abordagem ingênua para hardening costuma ser escrever um script Bash de 500 linhas com sequências de comandos como:
```bash
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl disable telnet.socket
sysctl -w net.ipv4.ip_forward=0
```
Essa abordagem de "script solto" possui falhas fatais em servidores de produção:
1. **Falta de Testabilidade:** Para saber se o script funciona, você é obrigado a executá-lo em uma máquina real como `root`. Não há como rodar testes unitários em pipeline de CI/CD.
2. **Ausência de Reversibilidade (Rollback):** Se o script quebrar o acesso ao servidor (por exemplo, corrompendo a sintaxe do SSH ou do sudoers), não há registro do estado anterior nem mecanismo automático para desfazer as alterações.
3. **Não-Idempotência:** Rodar o script duas vezes pode duplicar linhas, apagar configurações legítimas ou gerar comportamentos imprevisíveis.
4. **Vulnerabilidade a Injeção de Comandos:** Shell scripts frequentemente concatenam strings com variáveis, criando brechas de segurança.

### 2.3. O Padrão Arquitetural de Primitiva
Para superar isso, o projeto implementa o padrão de **Separação entre Política e Mecanismo**:
* **A Política (YAML):** Declara **O QUE** deve ser o estado desejado do sistema (dados puros, legíveis por humanos e auditores).
* **A Primitiva (Python):** Implementa **COMO** inspecionar e alterar esse tipo específico de recurso no Linux.

Cada Primitiva herda da classe base `Primitiva` (`hardener/checks/base.py`) e cumpre um contrato estrito de quatro métodos:

```python
class Primitiva:
    nome: str

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        """Garante que a regra YAML passou todos os dados obrigatórios e válidos."""

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        """INSPEÇÃO PURA: NUNCA altera o sistema. Retorna (conforme, atual, esperado, detalhe)."""

    def descrever(self, params: Dict[str, Any]) -> str:
        """Explica em português claro o que será feito durante o modo de simulação (dry-run)."""

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        """AÇÃO CONTROLADA: Salva backup antes de alterar, aplica a mudança e garante idempotência."""
```

**Resultado:** Uma única primitiva (como `sysctl`) atende dezenas de regras diferentes (`net.ipv4.ip_forward`, `kernel.randomize_va_space`, `log_martians`) sem duplicar uma única linha de código de backup, leitura atômica ou tratamento de erro.

---

## 3. Arquitetura de Engenharia e Princípios de Design

A ferramenta foi projetada seguindo as melhores práticas de confiabilidade para sistemas críticos:

### 3.1. Compatibilidade Estrita com Python 3.9
O RHEL 9 é fornecido por padrão com o interpretador **Python 3.9**. Para garantir que a ferramenta execute nativamente em qualquer servidor RHEL 9 limpo sem exigir compilação de novas versões de Python ou repositórios extras, o código:
* Utiliza `from __future__ import annotations` no topo de todos os módulos.
* Não utiliza sintaxes de versões posteriores (como `match/case` ou anotações `int | None` avaliadas em runtime).
* Possui como **única dependência externa o PyYAML** (para leitura dos manifestos de política).

### 3.2. Proibição de Execução em Shell (`shell=False`)
Chamadas ao sistema operacional nunca utilizam interpretador de shell (`subprocess.run(..., shell=True)`). Todas as execuções passam por `ctx.runner.executar(["comando", "arg1", "arg2"])`.
* **Benefício de Segurança:** Elimina vetores de injeção de comandos através de espaços em branco, ponto e vírgula ou pipes.
* **Benefício de Testabilidade:** Permite injetar um `FakeRunner` em testes unitários, interceptando comandos e simulando saídas sem precisar de root.

### 3.3. Escrita Atômica no Sistema de Arquivos
Quando uma primitiva altera um arquivo de configuração do sistema operacional:
1. Registra o arquivo original no backup via `ctx.salvar_antes_de_alterar("/caminho")`.
2. Escreve o novo conteúdo em um arquivo temporário no mesmo diretório (`.tmp`).
3. Define as permissões octais corretas (`os.chmod`).
4. Substitui o arquivo original usando a chamada de sistema `os.replace`.
* **Garantia:** Em sistemas operacionais POSIX, a renomeação/substituição de arquivos dentro do mesmo sistema de arquivos é uma operação atômica. Se faltar energia ou o processo for abortado exatamente no momento da escrita, o arquivo de configuração original nunca fica truncado ou corrompido.

### 3.4. Idempotência em Duplo Nível
Executar `enforce --apply` uma vez corrige o sistema. Executar `enforce --apply` imediatamente após deve:
- Reportar todas as regras como `CONFORME`.
- Não alterar nenhum byte em disco.
- Não disparar recargas desnecessárias de serviços.
- Não gerar pastas redundantes de backup.

### 3.5. Trava Operacional de Segurança (`/etc/hardener-vm`)
Por exigência de segurança contra execuções inadvertidas nas máquinas de desenvolvimento dos engenheiros, o subcomando de aplicação real (`enforce --apply`) recusa a execução caso não encontre o arquivo sentinela `/etc/hardener-vm`. Este arquivo deve ser criado conscientemente pelo operador na VM de testes (`sudo touch /etc/hardener-vm`).

### 3.6. Sistema Transacional de Backup e Rollback
A cada execução de `enforce --apply`, o `GerenciadorBackup` cria uma sessão em `/var/lib/hardener/backups/<timestamp>/`:
- `manifest.json`: Registra o identificador da sessão, quais arquivos foram alterados, se existiam previamente e quais serviços devem ser validados/recarregados.
- `arquivos/0001, 0002...`: Cópias idênticas e intocadas dos arquivos originais pré-modificação.
- `python3 -m hardener rollback` lê a última sessão pendente e restaura todos os arquivos no sentido inverso, recarregando os daemons de forma segura.

---

## 4. Estrutura Completa de Arquivos e Módulos do Repositório

O repositório é organizado de forma modular, permitindo a separação limpa entre interface CLI, lógica de motor, primitivas de verificação, definições declarativas em YAML e testes automatizados:

```
Hardening_RedHat_ATI/
├── CLAUDE.md                   # Diretrizes contratuais e convenções para assistentes e equipe
├── description.md              # Este guia arquitetural, didático e operacional do projeto
├── VALIDAR_NA_VM.md            # Checklist prático de testes reais na VM RHEL 9
├── README.md                   # Apresentação do repositório, comandos rápidos e status
│
├── hardener/                   # PACOTE PYTHON PRINCIPAL
│   ├── __init__.py             # Metadados do pacote e versão da ferramenta (0.1.0)
│   ├── cli.py                  # Ponto de entrada CLI (argparse), comandos audit, enforce, rollback...
│   ├── engine.py               # Motor central: orquestra a auditoria, aplicação e rollback
│   ├── models.py               # Estruturas de dados: Regra, Verificacao, Resultado, Contexto, Status
│   ├── policy.py               # Carregador e validador sintático dos arquivos YAML em rules/
│   ├── backup.py               # Gerenciador de sessões de backup pré-alteração e restauração
│   ├── runner.py               # Interface de execução segura de comandos de SO sem shell
│   ├── rhel.py                 # Funções específicas do RHEL (detecção de OS, visudo -c, sshd -t)
│   ├── report.py               # Gerador de relatórios visuais no terminal e exportador JSON
│   ├── offboarding.py          # Lógica completa de revogação de acessos e contas locais (Dor 5)
│   ├── relatorios_contas.py    # Relatórios forenses de contas inativas, senhas sem expiração e chaves órfãs
│   └── checks/                 # CATÁLOGO DAS 13 PRIMITIVAS DE CONFIGURAÇÃO
│       ├── __init__.py         # Dicionário REGISTRO mapeando o nome da primitiva à sua instância
│       ├── base.py             # Classe abstrata Primitiva definindo o contrato de 4 métodos
│       ├── sshd_config.py      # Primitiva de diretivas do daemon SSH
│       ├── sudoers.py          # Primitiva de controle de privilégios sudoers e sudoers.d
│       ├── conta_usuario.py    # Primitiva de auditoria e ajuste de contas e grupos (UID 0, wheel)
│       ├── permissao_arquivo.py# Primitiva de modos octais, donos, recursão e world-writable
│       ├── suid_sgid.py        # Primitiva de auditoria de binários com bits SUID/SGID
│       ├── arquivo_chave_valor.py # Primitiva genérica para arquivos de chave-valor (PAM, login.defs)
│       ├── sysctl.py           # Primitiva de parâmetros do kernel e rede em tempo real e persistente
│       ├── montagem.py         # Primitiva de opções no fstab e remontagem de partições
│       ├── firewalld.py        # Primitiva de gerenciamento de serviços e portas no firewall
│       ├── portas_escuta.py    # Primitiva de auditoria de sockets em escuta na rede externa
│       ├── selinux.py          # Primitiva de estado Enforcing e rotulagem de contexto MAC
│       ├── servico.py          # Primitiva de desativação de serviços e sockets inseguros
│       └── apache_upload.py    # Primitiva de bloqueio de scripts web em uploads no Apache
│
├── rules/                      # POLÍTICA DE SEGURANÇA DECLARATIVA (36 REGRAS EM YAML)
│   ├── accounts.yaml           # Contas locais, permissões de passwd/shadow, PAM e sudoers
│   ├── ssh.yaml                # Diretivas de SSH (PermitRootLogin, AllowGroups, permissão sshd_config)
│   ├── mounts.yaml             # Restrições de montagem no fstab (/tmp, /var/tmp, /dev/shm, uploads)
│   ├── network.yaml            # Firewall, auditoria de portas e parâmetros sysctl de rede
│   ├── kernel.yaml             # Parâmetros sysctl de proteção do kernel e ASLR
│   ├── system.yaml             # SELinux enforcing, auditoria world-writable e serviços proibidos
│   └── uploads.yaml            # Proteção integrada para diretórios de upload web
│
├── demo/                       # SCRIPTS E DADOS PARA DEMONSTRAÇÃO
│   ├── sujar_servidor.sh       # Script para criar intencionalmente todas as 36 violações na VM
│   └── dados/
│       └── autorizados.csv     # Lista oficial de usuários homologados para o teste de offboarding
│
└── tests/                      # SUÍTE DE TESTES UNITÁRIOS COM PYTEST (114 TESTES)
    ├── conftest.py             # Fixtures compartilhadas: FakeRunner, raiz temporária, estado
    ├── test_cli.py             # Testes dos comandos do terminal e tratamento de argumentos
    ├── test_backup.py          # Testes de integridade da sessão de backup e rollback
    ├── test_sysctl.py          # Testes da primitiva sysctl
    ├── test_montagem.py        # Testes da primitiva montagem
    ├── test_firewalld.py       # Testes da primitiva firewalld
    ├── test_portas_escuta.py   # Testes da primitiva portas_escuta
    ├── test_selinux.py         # Testes da primitiva selinux
    ├── test_servico.py         # Testes da primitiva servico
    ├── test_uploads.py         # Testes das regras e primitivas de uploads web
    ├── test_permissao_arquivo.py # Testes de permissões e propriedade
    ├── test_arquivo_chave_valor.py # Testes da primitiva arquivo_chave_valor
    ├── test_sudoers.py         # Testes das regras de sudoers
    ├── test_conta_usuario.py   # Testes de usuários e grupos
    ├── test_suid_sgid.py       # Testes de binários SUID
    ├── test_offboarding.py     # Testes da lógica de revogação de acessos
    ├── test_offboarding_interface.py # Testes de CLI do comando offboarding
    └── test_offboarding_relatorios.py # Testes dos relatórios forenses de contas
```

---

## 5. Catálogo Completo das 13 Primitivas de Hardening

Abaixo, detalhamos cada uma das 13 primitivas registradas em `hardener/checks/__init__.py`:

### 1. `sysctl`
* **Finalidade:** Gerenciamento de parâmetros do subsistema de rede e proteção de memória do kernel.
* **Arquivo gerenciado:** `/etc/sysctl.d/99-hardener.conf`.
* **Como verifica:** Lê o valor ativo no kernel com `sysctl -n <chave>` e confirma a persistência na última linha não comentada do arquivo.
* **Como corrige:** Salva backup, atualiza a chave atomicamente preservando outras configurações existentes e injeta imediatamente no runtime com `sysctl -w <chave>=<valor>`.

### 2. `montagem`
* **Finalidade:** Blindagem de sistemas de arquivos e diretórios compartilhados.
* **Arquivo gerenciado:** `/etc/fstab`.
* **Como verifica:** Confere a presença das opções restritivas na 4ª coluna do `/etc/fstab` e inspeciona o runtime através de `findmnt -n -o OPTIONS <ponto>`.
* **Como corrige:** Salva backup do `/etc/fstab`, adiciona as opções faltantes sem duplicar; cria novas entradas (`tmpfs` para `/tmp` e `/dev/shm` ou `bind` para pastas regulares) e executa `mount -o remount <ponto>` ou `mount <ponto>`.

### 3. `firewalld`
* **Finalidade:** Política de menor exposição de rede no firewall local.
* **Comandos utilizados:** `firewall-cmd --state`, `--list-services`, `--list-ports`.
* **Como verifica:** Confere se o daemon está em execução e se não há portas ou serviços ativos além dos explicitamente declarados.
* **Como corrige:** Remove portas e serviços excedentes com `--remove-service` e `--remove-port` (tanto no runtime quanto com `--permanent`), assegura que os serviços permitidos estejam ativos e aplica `--reload`.

### 4. `portas_escuta`
* **Finalidade:** Auditoria passiva de sockets abertos em interfaces de rede externas.
* **Comandos utilizados:** `ss -tulnH`.
* **Como verifica:** Mapeia todos os sockets TCP/UDP em escuta, descarta conexões restritas a loopback (`127.0.0.1`, `::1`) e valida se há alguma porta desconhecida aberta.
* **Como corrige:** Por ser uma regra de auditoria passiva, recusa modificações cegas (`ErroPrimitiva`), instruindo o analista a inspecionar processos via `ss -tulnp`.

### 5. `selinux`
* **Finalidade:** Controle de Acesso Mandatório (MAC) e confinamento de privilégios.
* **Arquivos/Comandos:** `/etc/selinux/config`, `getenforce`, `setenforce`, `chcon`, `stat -c %C`.
* **Como verifica:**
  - *Modo estado:* Valida se o kernel está em `Enforcing` e se a inicialização está configurada para `SELINUX=enforcing`.
  - *Modo contexto_caminho:* Inspeciona o rótulo de tipo SELinux do diretório alvo.
* **Como corrige:** Grava `SELINUX=enforcing` com backup, executa `setenforce 1` e aplica rótulos via `chcon -R -t <tipo> <caminho>`.

### 6. `servico`
* **Finalidade:** Extinção de daemons e sockets inseguros legados.
* **Comandos utilizados:** `systemctl is-active`, `systemctl is-enabled`, `systemctl disable --now`.
* **Como verifica:** Percorre a lista de serviços proibidos e checa se algum está ativo ou programado para inicializar com o sistema.
* **Como corrige:** Executa `systemctl disable --now <unidade>` para interromper e desabilitar instantaneamente.

### 7. `permissao_arquivo`
* **Finalidade:** Auditoria e aplicação de permissões octais e propriedade `dono:grupo`.
* **Recursos:** Suporte a verificação pontual, criação de diretórios (`criar_se_ausente`), varredura recursiva de arquivos internos (`recursivo_arquivos`) e identificação de diretórios world-writable sem sticky bit (`auditar_world_writable`).
* **Como corrige:** Salva no backup arquivos regulares antes de alterar, aplica `os.chmod` sem nunca elevar permissões além da máscara, e ajusta donos com `os.chown`.

### 8. `apache_upload`
* **Finalidade:** Blindagem de servidores web contra execução remota de código em uploads.
* **Arquivo gerenciado:** `/etc/httpd/conf.d/hardener-uploads.conf`.
* **Como verifica:** Checa se o arquivo existe e contém as diretivas de restrição `<Directory>`, `Options -ExecCGI -Indexes -Includes` e `AllowOverride None`.
* **Como corrige:** Gera atomicamente o arquivo de configuração contendo o bloqueio explícito de interpretação de scripts (`.php`, `.sh`, `.cgi`, etc.).

### 9. `sshd_config`
* **Finalidade:** Configuração segura de parâmetros de acesso remoto OpenSSH.
* **Arquivo gerenciado:** `/etc/ssh/sshd_config.d/00-hardener.conf`.
* **Como verifica:** Executa `sshd -T` para obter os valores consolidados em memória do daemon.
* **Como corrige:** Salva backup, atualiza a diretiva no arquivo com modo `0600` e programa a validação de sintaxe (`sshd -t`) e recarga (`systemctl reload sshd`).

### 10. `sudoers`
* **Finalidade:** Erradicação de acessos administrativos irrestritos sem senha.
* **Arquivos gerenciados:** `/etc/sudoers` e arquivos em `/etc/sudoers.d/*`.
* **Como verifica:** Analisa a gramática dos arquivos de sudoers identificando cláusulas `NOPASSWD` indevidas ou diretivas `ALL` concedidas a usuários não homologados.
* **Como corrige:** Comenta as linhas irregulares com `# hardener: desativado: <linha>`, valida a sintaxe com `visudo -c` e preserva o acesso administrativo legítimo do `%wheel`.

### 11. `conta_usuario`
* **Finalidade:** Integridade de contas locais e governança do grupo administrativo `wheel`.
* **Arquivos/Comandos:** `/etc/passwd`, `/etc/group`, `gpasswd -d`.
* **Como verifica:** Identifica UIDs duplicados com 0 (além do root) e audita os membros do grupo `wheel` contra a lista autorizada.
* **Como corrige:** Remove membros clandestinos do grupo `wheel` via `gpasswd -d <usuario> wheel`.

### 12. `suid_sgid`
* **Finalidade:** Auditoria de arquivos binários com privilégios especiais SUID/SGID.
* **Como verifica:** Realiza varredura local nos pontos de montagem (`find / -xdev`) procurando binários com bits `4000` ou `2000` que não constem na baseline autorizada do sistema operacional.
* **Como corrige:** Regra de auditoria passiva: alerta a equipe de segurança para investigação forense de binários suspeitos.

### 13. `arquivo_chave_valor`
* **Finalidade:** Manipulação idempotente de arquivos de configuração em formato `chave = valor`.
* **Arquivos típicos:** `/etc/security/faillock.conf`, `/etc/security/pwquality.conf`, `/etc/login.defs`.
* **Como verifica:** Lê o arquivo com separador customizável e confere se a última ocorrência bate com o valor exigido.
* **Como corrige:** Salva backup, substitui ou anexa a chave no arquivo atomicamente mantendo comentários intactos.

---

## 6. Tabela Completa das 36 Regras de Segurança e Impacto Real

Abaixo está a totalidade das **36 regras declaradas no repositório**, organizadas por objetivo de segurança e vetor de risco da ATI:

| ID Regra | Arquivo YAML | Primitiva | Severidade | Parâmetros Chave | O que o Atacante Tenta Fazer | Impacto Real da Regra no SO |
|---|---|---|---|---|---|---|
| **KRN-001** | `kernel.yaml` | `sysctl` | Alta | `kernel.randomize_va_space = "2"` | Prever endereços de memória para explorar vulnerabilidades de estouro de pilha/buffer overflow. | Sorteia a base da stack, heap e bibliotecas na inicialização de cada processo, inviabilizando exploits de memória (ASLR total). |
| **KRN-001b**| `kernel.yaml` | `sysctl` | Alta | `kernel.kptr_restrict = "1"` | Ler ponteiros internos do kernel em `/proc/kallsyms` para montar exploits de escalonamento de privilégio. | Oculta os endereços de ponteiros do kernel para usuários comuns, impedindo a preparação de rootkits. |
| **KRN-001c**| `kernel.yaml` | `sysctl` | Média | `kernel.dmesg_restrict = "1"` | Inspecionar mensagens de hardware e logs de inicialização (`dmesg`) para identificar dados sensíveis ou falhas. | Restringe o acesso ao buffer de mensagens do kernel exclusivamente a processos com `CAP_SYSLOG` ou `root`. |
| **KRN-001d**| `kernel.yaml` | `sysctl` | Alta | `fs.suid_dumpable = "0"` | Forçar a falha (crash) de um binário SUID para despejar a memória do processo no disco e ler credenciais. | Proíbe a gravação de core dumps para processos privilegiados, evitando vazamento de memória para disco. |
| **MNT-001** | `mounts.yaml` | `montagem` | Alta | `/tmp`: `noexec, nosuid, nodev` | Baixar e executar um script malicioso ou instalador de ransomware diretamente em `/tmp`. | O kernel bloqueia qualquer tentativa de execução em `/tmp` com `Permission denied`, quebrando a cadeia do ataque. |
| **MNT-002** | `mounts.yaml` | `montagem` | Alta | `/var/tmp`: `noexec, nosuid, nodev` | Utilizar `/var/tmp` como alternativa para armazenar e rodar binários de ataque persistentes entre reboots. | Aplica a mesma restrição do `/tmp`, eliminando áreas temporárias executáveis. |
| **MNT-003** | `mounts.yaml` | `montagem` | Alta | `/dev/shm`: `noexec, nosuid, nodev` | Escrever binários na memória compartilhada (`/dev/shm`) para rodar programas sem tocar no disco físico. | Impede a execução de programas a partir da memória compartilhada POSIX. |
| **UPL-003** | `mounts.yaml` | `montagem` | Alta | `/var/www/uploads`: `noexec, nosuid, nodev` | Executar scripts ou binários enviados por falha na aplicação web através do sistema de arquivos local. | Garante no nível do sistema de arquivos que a pasta de uploads seja uma partição estática sem execução. |
| **NET-001** | `network.yaml` | `firewalld` | Alta | `servicos: [ssh]`, `portas: []` | Acessar serviços internos esquecidos abertos em portas secundárias (ex.: Cockpit na 9090, APIs de teste na 8080). | Fecha todas as portas e serviços não declarados explicitamente no firewall do host. |
| **NET-002** | `network.yaml` | `portas_escuta` | Alta | `portas_autorizadas: [22]` | Subir um listener de backdoor ou comando e controle (C2) em uma porta alta não monitorada. | Audita a pilha TCP/UDP do host e alerta sobre qualquer socket externo fora da lista de conformidade. |
| **NET-004** | `network.yaml` | `sysctl` | Alta | `net.ipv4.ip_forward = "0"` | Usar o servidor comprometido como roteador para atingir outras sub-redes corporativas isoladas (pivot). | Desativa o encaminhamento de pacotes no kernel; o servidor só processa tráfego destinado a si próprio. |
| **NET-005** | `network.yaml` | `sysctl` | Média | `net.ipv4.conf.all.accept_redirects = "0"` | Enviar pacotes ICMP Redirect falsos para alterar a tabela de roteamento do servidor e interceptar dados (MitM). | O kernel rejeita avisos externos de redirecionamento de rotas. |
| **NET-005b**| `network.yaml` | `sysctl` | Média | `net.ipv4.conf.all.send_redirects = "0"` | Forjar o envio de redirects ICMP a partir do host para desestabilizar a rede local. | Proíbe o envio de pacotes ICMP Redirect para a rede. |
| **NET-006** | `network.yaml` | `sysctl` | Média | `net.ipv4.conf.all.rp_filter = "1"` | Enviar pacotes com endereço de IP de origem forjado (IP Spoofing) para burlar listas de controle de acesso. | Descarta pacotes cuja rota de retorno não corresponda à mesma interface de entrada (Reverse Path Filtering). |
| **NET-006b**| `network.yaml` | `sysctl` | Média | `net.ipv4.conf.all.log_martians = "1"` | Enviar pacotes forjados esperando que passem sem deixar rastros nos registros de segurança. | Registra no log do kernel qualquer pacote com endereço de origem impossível na topologia de rede. |
| **SSH-001** | `ssh.yaml` | `sshd_config` | Alta | `PermitRootLogin: "no"` | Realizar ataques de força bruta diretamente contra a conta `root` via SSH na rede. | Obriga administradores a efetuarem login com credenciais nominais e rastreáveis antes de usar sudo. |
| **SSH-002** | `ssh.yaml` | `permissao_arquivo` | Alta | `/etc/ssh/sshd_config`: `0600` root:root | Usuários comuns lerem a configuração do SSH ou tentarem adulterar parâmetros caso a permissão esteja frouxa. | Apenas o `root` tem permissão de leitura e escrita nas configurações principais do daemon SSH. |
| **NET-003** | `ssh.yaml` | `sshd_config` | Alta | `AllowGroups: "wheel"` | Qualquer usuário com login no sistema conseguir abrir uma sessão remota interativa via SSH. | O daemon SSH recusa a conexão imediatamente se o usuário não pertencer ao grupo homologado `wheel`. |
| **SYS-001** | `system.yaml` | `selinux` | Crítica | `modo: estado`, `esperado: enforcing` | Desabilitar o SELinux para facilitar a execução de comandos maliciosos caso comprometa um processo daemon. | Garante que o SELinux permaneça em modo `Enforcing` no kernel e gravado no arquivo `/etc/selinux/config`. |
| **SYS-002** | `system.yaml` | `permissao_arquivo` | Média | `/tmp`: `auditar_world_writable: true` | Apagar, renomear ou adulterar arquivos criados por outros usuários em diretórios compartilhados de gravação pública. | Exige a presença do Sticky Bit em diretórios públicos e audita arquivos órfãos sem proprietário válido. |
| **SVC-001** | `system.yaml` | `servico` | Alta | Desativar `telnet, rsh, rlogin, tftp, vsftpd` | Capturar senhas e dados não criptografados trafegando na rede ou explorar vulnerabilidades em daemons obsoletos. | Desabilita e encerra permanentemente todos os sockets e serviços legados e inseguros (`disable --now`). |
| **UPL-001** | `uploads.yaml` | `permissao_arquivo` | Alta | `/var/www/uploads`: `modo_max: "0640"` recursivo | Fazer upload de um script malicioso com permissão de execução e invocá-lo pelo shell do servidor. | Remove qualquer bit de execução (`0111`) em todos os arquivos armazenados dentro do diretório de uploads. |
| **UPL-002** | `uploads.yaml` | `permissao_arquivo` | Alta | `/var/www/uploads`: `0750` root:apache | Usuários comuns lerem ou alterarem o conteúdo dos uploads enviados para as aplicações web. | Isola o diretório: o Apache consegue escrever/ler dados, mas usuários comuns não possuem acesso de leitura. |
| **UPL-004** | `uploads.yaml` | `selinux` | Alta | `/var/www/uploads`: `httpd_sys_rw_content_t` | Fazer o Apache executar código ou invocar interpretadores dentro do diretório de uploads. | Concede ao Apache permissão de leitura e escrita, mas o kernel SELinux bloqueia qualquer execução de scripts. |
| **UPL-005** | `uploads.yaml` | `apache_upload` | Alta | `/etc/httpd/conf.d/hardener-uploads.conf` | Fazer o Apache interpretar um arquivo `.php` ou `.cgi` enviado por um usuário na pasta pública. | O Apache desativa CGI e bloqueia requisições para extensões executáveis dentro de `/var/www/uploads`. |
| **PERM-002**| `accounts.yaml`| `permissao_arquivo` | Alta | `/etc/passwd`: `0644` root:root | Injetar usuários ou alterar shells diretamente no banco de dados de contas do sistema. | Garante permissão estrita de leitura pública e escrita exclusiva para o `root`. |
| **PERM-003**| `accounts.yaml`| `permissao_arquivo` | Alta | `/etc/shadow`: `0000` root:root | Usuários sem privilégio lerem os hashes de senhas criptografadas para ataques de força bruta offline. | Bloqueia qualquer permissão padrão para usuários comuns; apenas ferramentas autorizadas via setuid o leem. |
| **PAM-001** | `accounts.yaml`| `arquivo_chave_valor`| Alta | `deny = 5` em `faillock.conf` | Realizar ataques de força bruta de senha contínuos contra contas locais até descobrir a credencial. | Bloqueia automaticamente a conta após 5 tentativas consecutivas de senha inválida. |
| **PAM-001b**| `accounts.yaml`| `arquivo_chave_valor`| Alta | `unlock_time = 900` em `faillock.conf` | Tentar novas senhas imediatamente após o bloqueio de uma conta. | Mantém a conta bloqueada por 15 minutos (900 segundos) antes de permitir novas tentativas. |
| **PAM-002** | `accounts.yaml`| `arquivo_chave_valor`| Alta | `minlen = 14` em `pwquality.conf` | Usuários cadastrarem senhas curtas, fracas e previsíveis que possam ser quebradas por dicionário. | Impõe tamanho mínimo de 14 caracteres para qualquer alteração de senha no sistema. |
| **ACC-002** | `accounts.yaml`| `arquivo_chave_valor`| Alta | `UMASK 027` em `login.defs` | Novos arquivos criados por usuários nascerem com permissão de leitura e execução para todos os usuários (`022`). | Define que arquivos novos criados não concedem nenhuma permissão a terceiros (`outros = 0`). |
| **SUDO-001**| `accounts.yaml`| `sudoers` | Crítica| Proibir `NOPASSWD` em `sudoers` e `sudoers.d` | Um atacante que comprometa uma conta comum conseguir virar `root` instantaneamente sem pedir senha. | Exige obrigatoriamente a senha do operador para qualquer escalonamento administrativo via sudo. |
| **SUDO-002**| `accounts.yaml`| `sudoers` | Alta | Proibir `ALL` amplo para quem não for `root`/`wheel` | Conceder privilégios sudo desmedidos para contas temporárias ou contas de serviço. | Limita a capacidade de execução irrestrita exclusivamente às contas explicitamente homologadas. |
| **SUDO-003**| `accounts.yaml`| `conta_usuario` | Alta | Membros do grupo `wheel` restritos à lista | Manter colaboradores desligados ou contas não autorizadas no grupo administrativo `wheel`. | Remove membros clandestinos do grupo `wheel` usando utilitários seguros do shadow. |
| **ACC-001** | `accounts.yaml`| `conta_usuario` | Crítica| UID 0 exclusivo para a conta `root` | Criar contas secundárias com UID 0 (ex.: `toor`, `admin0`) para obter privilégios de superusuário furtivamente. | Audita o `/etc/passwd` e reprova qualquer conta além do `root` que possua identificador UID 0. |
| **PERM-001**| `accounts.yaml`| `suid_sgid` | Média | Auditoria de binários SUID/SGID | Instalar binários maliciosos com bit SUID para permitir que usuários comuns executem código como `root`. | Compara todos os binários privilegiados do sistema contra a baseline oficial homologada no RHEL 9. |

---

## 7. Módulo Especializado de Offboarding e Higienização de Contas (Dor 5)

Além do ciclo padrão de regras, a ferramenta inclui um subsistema completo de **Offboarding e Revogação de Acessos** (`hardener/offboarding.py`), invocado pelo subcomando:

```bash
sudo python3 -m hardener offboarding --autorizados demo/dados/autorizados.csv [--apply]
```

### O que o Offboarding faz na prática?
1. **Leitura da Base Homologada:** Recebe um arquivo CSV estruturado (`usuario,departamento...`) contendo a lista oficial dos funcionários que possuem vínculo ativo.
2. **Identificação de Contas Clandestinas:** Localiza contas normais no `/etc/passwd` (UID >= 1000) que não estejam presentes no CSV e que não sejam usuários reservados de sistema (`nobody`, `nfsnobody`).
3. **Salvaguarda do Operador:** Identifica automaticamente quem está executando a ferramenta (via `SUDO_USER` ou `os.geteuid()`) e **nunca bloqueia a própria conta do operador**, prevenindo incidentes de auto-lockout.
4. **Cinco Ações Defensivas Imediatas:**
   - **Bloqueio e Expiração:** Executa `usermod -L` (trava a senha no `/etc/shadow`) e `chage -E 0` (expira a conta no sistema).
   - **Shell Inerte:** Altera o interpretador de login da conta para `/sbin/nologin`.
   - **Revogação de Chaves SSH:** Move recursivamente o arquivo `~/.ssh/authorized_keys` da conta para `/var/backups/revoked_ssh_keys/`, impedindo logins por chave pública.
   - **Remoção de Privilégios:** Remove a conta do grupo administrativo `wheel`.
   - **Encerramento de Sessões:** Finaliza sessões ativas com `loginctl terminate-user <usuario>` (ou `pkill -9 -u`).
5. **Relatórios Forenses Complementares:**
   - Contas inativas há mais de 90 dias (via `lastlog`).
   - Contas com senhas que nunca expiram no `/etc/shadow`.
   - Arquivos `authorized_keys` órfãos sem proprietário no sistema.

---

## 8. Roteiro Prático de Demonstração (Para Bancas e Apresentações)

Este roteiro passo a passo foi construído para apresentar o projeto a professores avaliadores ou clientes corporativos, evidenciando robustez e segurança em cada etapa:

### Etapa 1: Apresentar a Estrutura do Código e Testes Unitários
Antes de ir para a VM, mostre que o código é maduro, robusto e testável em qualquer máquina:
```bash
# 1. Validar a sintaxe de todas as 36 regras YAML
python3 -m hardener validar

# 2. Executar a suíte de testes automatizados (114 testes unitários)
PYTHONPATH=. pytest
```
*Destaque que todos os 114 testes rodam em menos de 1 segundo sem precisar de VM nem de privilégios de root, graças ao padrão de Primitiva e FakeRunner.*

### Etapa 2: Acessar a VM RHEL 9 e "Sujar" o Servidor
Na VM de testes (com snapshot prévio criado):
```bash
# 1. Garantir o marcador de proteção operacional
sudo touch /etc/hardener-vm

# 2. Executar o script de infecção controlada
sudo bash demo/sujar_servidor.sh
```
*Explique para a banca: "O script deliberadamente abriu portas no firewall, desligou o ASLR, colocou o SELinux em Permissive, criou scripts executáveis dentro de `/var/www/uploads` e afrouxou o sudoers."*

### Etapa 3: Executar a Auditoria (Modo Não-Destrutivo)
```bash
sudo python3 -m hardener audit
```
*Mostre que a ferramenta detectou instantaneamente todas as não-conformidades, apresentando o status `NAO_CONFORME`, o valor real encontrado e o valor esperado pela política, sem alterar absolutamente nada no servidor.*

### Etapa 4: Demonstrar o Modo Dry-Run (Simulação)
```bash
sudo python3 -m hardener enforce
```
*Mostre que o comando `enforce` sem parâmetros é seguro por padrão: ele não aplica alterações, mas muda os status para `SERIA_CORRIGIDO`, listando exatamente quais ações serão tomadas.*

### Etapa 5: Aplicar o Hardening Real
```bash
sudo python3 -m hardener enforce --apply
```
*Mostre que:*
- Uma sessão de backup atômico foi criada em `/var/lib/hardener/backups/`.
- Todas as regras foram ajustadas e validadas, retornando `CORRIGIDO`.
- Os serviços afetados (como o firewalld e sshd) foram validados e recarregados.

### Etapa 6: Provar a Idempotência
Execute o comando novamente:
```bash
sudo python3 -m hardener enforce --apply
```
*Mostre que 100% das regras agora retornam `CONFORME`, nenhum arquivo foi alterado e nenhuma nova pasta de backup foi criada.*

### Etapa 7: Prova Real de Segurança no Terminal
Provar na prática para os avaliadores que as proteções estão ativas no kernel:
```bash
# 1. Tentar executar um script em /tmp ou em /var/www/uploads
cd /var/www/uploads
echo 'echo "teste de invasão"' > script.sh
chmod +x script.sh
./script.sh
```
**Resultado esperado:** O shell exibe `bash: ./script.sh: Permission denied`, pois a montagem `noexec` impede a execução diretamente no nível do kernel.

```bash
# 2. Conferir o modo do SELinux
getenforce
```
**Resultado esperado:** `Enforcing`.

### Etapa 8: Demonstrar o Rollback Automatizado
```bash
sudo python3 -m hardener rollback
```
*Mostre que a ferramenta lê o manifesto da sessão anterior e restaura com precisão cirúrgica todos os arquivos para o estado exato anterior.*

---

## 9. Dicionário de Termos e Jargões Técnicos

* **Hardening:** Fortalecimento e blindagem da configuração do sistema operacional reduzindo sua superfície de vulnerabilidades.
* **CIS Benchmark:** Padrão global de recomendações técnicas mantido pelo *Center for Internet Security* para configuração segura de sistemas.
* **Idempotência:** Propriedade de uma operação de poder ser executada múltiplas vezes sem alterar o resultado além da primeira execução.
* **Escrita Atômica:** Substituição indivisível de arquivos no disco (`.tmp` + `os.replace`), prevenindo corrupção por falhas súbitas.
* **ASLR (Address Space Layout Randomization):** Técnica do kernel que sorteia as posições de memória de processos para inviabilizar ataques de estouro de buffer.
* **Controle de Acesso Mandatório (MAC / SELinux):** Mecanismo de segurança onde o kernel impõe regras restritivas a processos independentemente da permissão de usuário (`root`).
* **Flags de Montagem (`noexec, nosuid, nodev`):**
  - `noexec`: Proíbe a execução de binários e scripts na partição.
  - `nosuid`: Desativa a herança de privilégios via bits SUID/SGID.
  - `nodev`: Impede a criação de arquivos de dispositivo especiais.
* **Reverse Path Filtering (`rp_filter`):** Checagem de integridade de rede no kernel que valida se o pacote IP recebido por uma interface seria respondido pela mesma rota, impedindo falsificação de IP (Spoofing).
* **Sticky Bit:** Permissão octal (`1000`) em pastas compartilhadas que impede que um usuário apague arquivos de outro usuário.
* **Web Shell / RCE:** Script malicioso enviado para uma aplicação web com o objetivo de executar comandos remotos no servidor.

---

## 10. Conclusão e Próximos Passos

A ferramenta **Hardening RedHat ATI** atinge plenamente os objetivos propostos de engenharia de software para sistemas operacionais:
* Código 100% aderente aos padrões de compatibilidade do **RHEL 9 (Python 3.9)**.
* **36 regras de segurança** cobrindo integridade de contas, sudoers, sshd, firewall, portas, montagens, kernel e uploads web.
* **114 testes unitários automatizados** com execução rápida e independente de ambiente com privilégios.
* Mecanismos robustos de **backup transacional, escrita atômica e rollback**.

O projeto está pronto para a validação na máquina virtual oficial e demonstração prática para a banca avaliadora.
