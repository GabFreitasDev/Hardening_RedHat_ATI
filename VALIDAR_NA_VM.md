# Fila de validação na VM

O que depende do sistema real não pode ser provado pelos testes unitários. Quem escreve a regra
acrescenta o item aqui; quem hospeda a VM executa em lote, marca o resultado e commita.

Antes de começar: snapshot `base-limpa` feito, segunda sessão SSH aberta, `/etc/hardener-vm` criado
(ver `docs/AMBIENTE_VM.md`).

## Pendentes: núcleo e SSH-001

- [ ] `python3 --version` na VM é 3.9.x e `python3 -c "import yaml"` funciona.
- [ ] `sudo python3 -m hardener validar` passa na VM.
- [ ] `/etc/os-release` do Rocky/Alma/RHEL 9 é reconhecido: o relatório mostra `plataforma: rhel9`.
- [ ] `sudo sshd -T` funciona e imprime `permitrootlogin yes` (ou o valor padrão da VM).
- [ ] `grep -n Include /etc/ssh/sshd_config` mostra `Include /etc/ssh/sshd_config.d/*.conf` **antes** de
      qualquer `PermitRootLogin` no arquivo. Se não mostrar, o `00-hardener.conf` não tem efeito.
- [ ] Depois do `enforce --apply`: `sudo sshd -T | grep -i permitrootlogin` mostra `no`, mesmo com
      `50-redhat.conf` (e `50-cloud-init.conf`, se existir) presentes em `/etc/ssh/sshd_config.d/`.
- [ ] `sudo systemctl reload sshd` funciona com esse nome de unidade; a sessão SSH aberta sobrevive.
- [ ] Sintaxe quebrada de propósito (ex.: linha inválida em `00-hardener.conf`): `enforce --apply` reverte
      e **não** recarrega (testar o caminho de falha).
- [ ] `sudo python3 -m hardener rollback` remove `00-hardener.conf` (que não existia antes) e o
      `sshd -T` volta ao valor anterior.
- [ ] Segundo `enforce --apply` seguido: tudo `CONFORME`, sem nova pasta em `/var/lib/hardener/backups/`.
- [ ] Sem o arquivo `/etc/hardener-vm`, `enforce --apply` é recusado; como usuário comum (sem `sudo`), também.
- [ ] OpenSCAP: confirmar o arquivo de conteúdo e o id do perfil CIS com `oscap info` e anotar abaixo.

## Pendentes: permissões de arquivos (SSH-002, PERM-002, PERM-003)

- [ ] SSH-002 audit reprova na VM suja (ex.: `/etc/ssh/sshd_config` com modo 0644)
- [ ] SSH-002 enforce --apply corrige (relatório mostra CORRIGIDO, modo 0600 root:root)
- [ ] SSH-002 segundo enforce --apply não altera nada
- [ ] SSH-002 rollback restaura o estado anterior
- [ ] SSH-002 sshd continua aceitando conexões normalmente depois do enforce
- [ ] SSH-002 nenhum serviço legítimo quebrou (SELinux/audit.log, sessão SSH, firewall)

- [ ] PERM-002 audit reprova na VM suja (ex.: `/etc/passwd` com permissão de escrita indevida)
- [ ] PERM-002 enforce --apply corrige (relatório mostra CORRIGIDO, modo 0644 root:root)
- [ ] PERM-002 segundo enforce --apply não altera nada
- [ ] PERM-002 rollback restaura o estado anterior
- [ ] PERM-002 nenhum serviço legítimo quebrou (resolução de usuários via getent passwd, login, sudo)

- [ ] PERM-003 audit reprova na VM suja (ex.: `/etc/shadow` com modo 0640 ou superior)
- [ ] PERM-003 enforce --apply corrige (relatório mostra CORRIGIDO, modo 0000 root:root)
- [ ] PERM-003 segundo enforce --apply não altera nada
- [ ] PERM-003 rollback restaura o estado anterior
- [ ] PERM-003 autenticação de usuários e sudo continuam funcionando após o enforce

## Pendentes: parâmetros de autenticação e contas (PAM-001, PAM-001b, PAM-002, ACC-002)

- [ ] Confirmar com `authselect current` se o faillock está ativo na pilha PAM do RHEL 9 (ex.: feature `with-faillock`).
- [ ] Testar com uma segunda sessão SSH aberta durante todo o processo de enforce e rollback para garantir que o acesso administrativo não seja bloqueado acidentalmente.
- [ ] Confirmar que a ordem de leitura (última ocorrência vale) é a adotada pelos módulos PAM (`pam_faillock`, `pam_pwquality`) e utilitários do shadow (`login.defs`).

### PAM-001: Limite de tentativas de autenticação inválidas (deny) no faillock

- [ ] PAM-001 audit reprova na VM suja com `deny = 0` ou sem configuração em `/etc/security/faillock.conf`
- [ ] PAM-001 enforce --apply corrige e o relatório mostra CORRIGIDO (`deny = 5`)
- [ ] PAM-001 segundo enforce --apply não altera nada
- [ ] PAM-001 rollback restaura o estado anterior
- [ ] PAM-001 nenhum serviço legítimo quebrou: login SSH com senha correta continua funcionando e o operador não fica bloqueado (testar com uma segunda sessão aberta)

### PAM-001b: Tempo de bloqueio de conta (unlock_time) no faillock

- [ ] PAM-001b audit reprova na VM suja com `unlock_time = 0` ou sem configuração em `/etc/security/faillock.conf`
- [ ] PAM-001b enforce --apply corrige e o relatório mostra CORRIGIDO (`unlock_time = 900`)
- [ ] PAM-001b segundo enforce --apply não altera nada
- [ ] PAM-001b rollback restaura o estado anterior
- [ ] PAM-001b nenhum serviço legítimo quebrou: login SSH com senha correta continua funcionando e o operador não fica bloqueado (testar com uma segunda sessão aberta)

### PAM-002: Tamanho mínimo de senha (minlen) no pwquality

- [ ] PAM-002 audit reprova na VM suja com `minlen = 6` em `/etc/security/pwquality.conf`
- [ ] PAM-002 enforce --apply corrige e o relatório mostra CORRIGIDO (`minlen = 14`)
- [ ] PAM-002 segundo enforce --apply não altera nada
- [ ] PAM-002 rollback restaura o estado anterior
- [ ] PAM-002 nenhum serviço legítimo quebrou: o comando `passwd` continua funcionando

### ACC-002: Máscara padrão de criação de arquivos (UMASK) em login.defs

- [ ] ACC-002 audit reprova na VM suja com `UMASK 022` em `/etc/login.defs`
- [ ] ACC-002 enforce --apply corrige e o relatório mostra CORRIGIDO (`UMASK 027`)
- [ ] ACC-002 segundo enforce --apply não altera nada
- [ ] ACC-002 rollback restaura o estado anterior
- [ ] ACC-002 nenhum serviço legítimo quebrou: arquivos criados por um usuário novo saem com o umask esperado

## Pendentes: regras de sudoers (SUDO-001, SUDO-002)

- [ ] Testar sempre com duas sessões SSH/root abertas antes de rodar enforce em regras de sudoers para prevenir lockout.
- [ ] Garantir que o enforce não removeu a única forma de virar root na máquina (ex.: `%wheel` preservado com acesso via senha).
- [ ] Testar caminho de falha: com o arquivo quebrado de propósito, o motor reverte alterações (depende do ajuste do Aluno A em `engine.py` e `rhel.py` para validar via `visudo -c` sem chamar `systemctl reload sudoers`).

### SUDO-001: Proibir NOPASSWD indevido em sudoers e sudoers.d

- [ ] SUDO-001 audit reprova na VM suja com as regras de `demo/sujar_servidor.sh` (`/etc/sudoers.d/99-inseguro-ati`)
- [ ] SUDO-001 enforce --apply corrige e o relatório mostra CORRIGIDO (comenta a linha com `# hardener: desativado: ` e modo 0440)
- [ ] SUDO-001 segundo enforce --apply não altera nada
- [ ] SUDO-001 rollback restaura o estado anterior
- [ ] SUDO-001 nenhum serviço legítimo quebrou: `sudo -l` continua funcionando para o usuário de teste e `sudo visudo -c` passa

### SUDO-002: Proibir ALL indevido para quem não for root ou wheel em sudoers

- [ ] SUDO-002 audit não reprova `%wheel ALL=(ALL) ALL`, mas reprova `estagiario ALL=(ALL) ALL` na VM suja (`99-inseguro-ati`)
- [ ] SUDO-002 enforce --apply corrige e o relatório mostra CORRIGIDO (comenta a linha com `# hardener: desativado: ` e modo 0440)
- [ ] SUDO-002 segundo enforce --apply não altera nada
- [ ] SUDO-002 rollback restaura o estado anterior
- [ ] SUDO-002 nenhum serviço legítimo quebrou: `sudo -l` continua funcionando para o usuário de teste e `sudo visudo -c` passa

## Pendentes: contas e privilégios (ACC-001, SUDO-003, PERM-001)

- [ ] `demo/sujar_servidor.sh` executa apenas em ambiente com snapshot, emite aviso se `/etc/hardener-vm` não existir e NÃO cria o arquivo automaticamente.

### ACC-001: UID 0 atribuído exclusivamente à conta root

- [ ] ACC-001 audit reprova na VM se houver conta secundária com UID 0 (ex.: `toor_demo` criado por `demo/sujar_servidor.sh` em `/etc/passwd`)
Nota: regra somente auditoria: os itens 2 a 5 não se aplicam, a correção é manual.

### SUDO-003: Restringir membros do grupo wheel aos administradores autorizados

- [ ] SUDO-003 audit reprova se usuário não homologado estiver em `wheel` (ex.: `ex_funcionario` colocado em `wheel` por `demo/sujar_servidor.sh`)
- [ ] SUDO-003 enforce --apply corrige e o relatório mostra CORRIGIDO (remove membros indevidos via `gpasswd -d`)
- [ ] SUDO-003 segundo enforce --apply não altera nada
- [ ] SUDO-003 rollback restaura o estado anterior (`/etc/group` e `/etc/gshadow`)
- [ ] SUDO-003 nenhum serviço legítimo quebrou: os administradores legítimos continuam com acesso ao sudo

### PERM-001: Arquivos com bits SUID/SGID auditados contra lista de referência

- [ ] PERM-001 audit resulta em CONFORME na VM limpa (snapshot base-limpa) e NAO_CONFORME após a execução de `demo/sujar_servidor.sh`, listando o binário de teste (`/usr/local/bin/suid_teste`)
- [ ] PERM-001 tempo do audit aceitável (varredura com os.walk/xdev sem travar o sistema)
- [ ] PERM-001 a lista de permitidos bate com a saída de `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) | sort` no RHEL 9.8 limpo
- [ ] PERM-001 enforce mostra auditoria manual (regra sem correção automática) e não altera nada
- [ ] PERM-001 nenhum serviço legítimo quebrou
Nota: auditoria e lista de referência válidas para a VM RHEL 9.8 do Aluno C (regerar se mudar a plataforma ou pacotes instalados).

## Pendentes: offboarding e revogação de acessos (OFF-001 a OFF-008)

### OFF-001: Contas locais fora da lista bloqueadas e expiradas

- [ ] OFF-001 audit reprova na VM suja com conta não autorizada ativa (`ex_funcionario`)
- [ ] OFF-001 enforce --apply corrige e o relatório mostra CORRIGIDO (`usermod -L` e `chage -E 0`)
- [ ] OFF-001 segundo enforce --apply não altera nada
- [ ] OFF-001 rollback restaura o estado anterior
- [ ] OFF-001 nenhum serviço legítimo quebrou: a conta do operador nunca é bloqueada

### OFF-002: Shell nologin nas contas bloqueadas

- [ ] OFF-002 audit reprova na VM suja com conta não autorizada possuindo shell interativo
- [ ] OFF-002 enforce --apply corrige e o relatório mostra CORRIGIDO (`usermod -s /sbin/nologin`)
- [ ] OFF-002 segundo enforce --apply não altera nada
- [ ] OFF-002 rollback restaura o estado anterior
- [ ] OFF-002 nenhum serviço legítimo quebrou: a conta do operador nunca é bloqueada

### OFF-003: authorized_keys das contas bloqueadas arquivado

- [ ] OFF-003 audit reprova na VM suja com arquivo `~/.ssh/authorized_keys` existente para conta não autorizada
- [ ] OFF-003 enforce --apply corrige e o relatório mostra CORRIGIDO (chaves movidas para `/var/backups/revoked_ssh_keys/`)
- [ ] OFF-003 segundo enforce --apply não altera nada
- [ ] OFF-003 rollback restaura o estado anterior
- [ ] OFF-003 nenhum serviço legítimo quebrou: SSH com chave real é recusado depois do offboarding (`ssh -i /root/ex_funcionario_demo_key ex_funcionario@localhost`) e a conta do operador nunca é bloqueada

### OFF-004: Contas bloqueadas removidas do grupo wheel

- [ ] OFF-004 audit reprova na VM suja com conta não autorizada presente no grupo `wheel`
- [ ] OFF-004 enforce --apply corrige e o relatório mostra CORRIGIDO (`gpasswd -d wheel`)
- [ ] OFF-004 segundo enforce --apply não altera nada
- [ ] OFF-004 rollback restaura o estado anterior
- [ ] OFF-004 nenhum serviço legítimo quebrou: a conta do operador nunca é bloqueada e administradores autorizados mantêm acesso ao sudo

### OFF-005: Sessões ativas das contas bloqueadas encerradas

- [ ] OFF-005 audit reprova na VM suja se houver sessão ativa da conta não autorizada no `loginctl`
- [ ] OFF-005 enforce --apply corrige e o relatório mostra CORRIGIDO (`loginctl terminate-user` / fallback `pkill -9 -u`)
- [ ] OFF-005 segundo enforce --apply não altera nada
- [ ] OFF-005 rollback restaura o estado anterior
- [ ] OFF-005 nenhum serviço legítimo quebrou: a sessão do operador nunca é encerrada nem bloqueada

### OFF-006: Relatório de contas inativas

- [ ] OFF-006 audit identifica contas regulares (UID >= 1000) inativas há mais de 90 dias ou que nunca logaram
Nota: regra somente auditoria: os itens 2 a 5 não se aplicam, a correção é manual.
- [ ] Conferir o formato de data do utilitário `lastlog` no RHEL 9 e confirmar compatibilidade com `relatorio_contas_inativas`

### OFF-007: Relatório de senhas sem expiração

- [ ] OFF-007 audit identifica contas com senha real sem expiração máxima configurada (campo 5 vazio ou 99999 em `/etc/shadow`)
Nota: regra somente auditoria: os itens 2 a 5 não se aplicam, a correção é manual.

### OFF-008: Relatório de chaves SSH sem dono

- [ ] OFF-008 audit identifica arquivos `authorized_keys` de contas inexistentes, bloqueadas ou com shell nologin
Nota: regra somente auditoria: os itens 2 a 5 não se aplicam, a correção é manual.
- [ ] Conferir o valor de `AuthorizedKeysFile` em `sshd -T` para assegurar que está no padrão `.ssh/authorized_keys`

## Pendentes: Trilha C - Acesso SSH restrito (NET-003)

- [ ] NET-003 audit reprova na VM suja sem AllowGroups configurado em sshd
- [ ] NET-003 enforce --apply corrige e o relatório mostra CORRIGIDO (AllowGroups wheel em 00-hardener.conf)
- [ ] NET-003 segundo enforce --apply não altera nada
- [ ] NET-003 rollback restaura o estado anterior
- [ ] NET-003 usuários do grupo wheel continuam acessando via SSH e usuários fora de wheel são rejeitados

## Pendentes: Trilha C - Parâmetros de rede e kernel via sysctl (NET-004 a NET-006, KRN-001)

### NET-004 a NET-006: Sysctl de Rede
- [ ] NET-004 audit reprova na VM suja com `net.ipv4.ip_forward = 1`
- [ ] NET-004 enforce --apply corrige (relatório mostra CORRIGIDO, valor 0 persistido em `/etc/sysctl.d/99-hardener.conf` e aplicado via `sysctl -w`)
- [ ] NET-004 segundo enforce --apply não altera nada
- [ ] NET-004 rollback restaura o estado anterior
- [ ] NET-005 / NET-005b audit reprova com redirects habilitados (`accept_redirects = 1`, `send_redirects = 1`)
- [ ] NET-005 / NET-005b enforce --apply corrige (`accept_redirects = 0`, `send_redirects = 0`)
- [ ] NET-005 / NET-005b segundo enforce --apply não altera nada
- [ ] NET-005 / NET-005b rollback restaura o estado anterior
- [ ] NET-006 / NET-006b audit reprova com rp_filter e log_martians desabilitados (valor 0)
- [ ] NET-006 / NET-006b enforce --apply corrige (valor 1)
- [ ] NET-006 / NET-006b segundo enforce --apply não altera nada
- [ ] NET-006 / NET-006b rollback restaura o estado anterior
- [ ] Nenhuma quebra de conectividade de rede legítima após aplicação das regras

### KRN-001 a KRN-001d: Sysctl de Kernel
- [ ] KRN-001 audit reprova na VM suja com `kernel.randomize_va_space < 2`
- [ ] KRN-001 enforce --apply corrige (`kernel.randomize_va_space = 2`)
- [ ] KRN-001b audit reprova na VM suja com `kernel.kptr_restrict = 0`
- [ ] KRN-001b enforce --apply corrige (`kernel.kptr_restrict = 1`)
- [ ] KRN-001c audit reprova com `kernel.dmesg_restrict = 0` e enforce corrige para 1
- [ ] KRN-001d audit reprova com `fs.suid_dumpable != 0` e enforce corrige para 0
- [ ] KRN-001 (todos) segundo enforce --apply não altera nada
- [ ] KRN-001 (todos) rollback restaura o estado anterior

## Pendentes: Trilha C - Opções de montagem (MNT-001 a MNT-003, UPL-003)

- [ ] MNT-001 audit reprova se `/tmp` estiver montado sem `noexec,nosuid,nodev` ou ausente no `/etc/fstab`
- [ ] MNT-001 enforce --apply adiciona entrada tmpfs ou opções no `/etc/fstab` e remonta com sucesso
- [ ] MNT-001 segundo enforce --apply não altera nada
- [ ] MNT-001 rollback restaura o `/etc/fstab` anterior
- [ ] MNT-002 audit reprova se `/var/tmp` estiver sem `noexec,nosuid,nodev` e enforce --apply corrige
- [ ] MNT-003 audit reprova se `/dev/shm` estiver sem `noexec,nosuid,nodev` e enforce --apply corrige
- [ ] UPL-003 audit reprova se diretório `/var/www/uploads` não possuir montagem dedicada com `noexec,nosuid,nodev`
- [ ] UPL-003 enforce --apply cria o diretório (se inexistente), insere bind mount com opções restritivas no `/etc/fstab` e remonta
- [ ] Testar na VM: criar script em `/tmp` ou `/var/www/uploads`, dar `chmod +x` e tentar executar; deve retornar `Permission denied` devido a `noexec`
- [ ] Nenhum serviço essencial do sistema (ex.: dnf, systemd, sshd) quebrou com as restrições de montagem

## Pendentes: Trilha C - Firewall e Portas (NET-001, NET-002)

- [ ] NET-001 audit reprova na VM suja com porta 8080/tcp ou serviço cockpit abertos
- [ ] NET-001 enforce --apply remove portas e serviços não autorizados no firewalld e recarrega
- [ ] NET-001 segundo enforce --apply não altera nada
- [ ] NET-001 portas autorizadas (ex.: SSH) continuam acessíveis
- [ ] NET-002 audit identifica processos e portas em escuta na rede externa (ex.: 8080/tcp)
Nota: regra somente auditoria: correção é manual encerrando o serviço excedente.

## Pendentes: Trilha C - SELinux, Serviços e Permissões Críticas (SYS-001, SYS-002, SVC-001)

- [ ] SYS-001 audit reprova na VM suja com `SELinux em Permissive`
- [ ] SYS-001 enforce --apply corrige (`setenforce 1` e `SELINUX=enforcing` em `/etc/selinux/config`)
- [ ] SYS-001 segundo enforce --apply não altera nada
- [ ] SYS-001 rollback restaura o estado anterior
- [ ] SYS-002 audit identifica arquivos world-writable sem sticky bit ou sem dono em `/tmp`
Nota: regra somente auditoria: correção é manual.
- [ ] SVC-001 audit reprova se telnet, rsh ou vsftpd estiverem ativos ou habilitados
- [ ] SVC-001 enforce --apply desabilita e encerra os serviços (`systemctl disable --now`)
- [ ] SVC-001 segundo enforce --apply não altera nada

## Pendentes: Trilha C - Proteção de Uploads Web (UPL-001, UPL-002, UPL-004, UPL-005)

- [ ] UPL-001 audit reprova na VM suja se arquivos em `/var/www/uploads` possuírem bit de execução (ex.: `0755`)
- [ ] UPL-001 enforce --apply remove os bits de execução recursivamente (aplicando modo `0640`)
- [ ] UPL-001 segundo enforce --apply não altera nada
- [ ] UPL-002 audit reprova se `/var/www/uploads` tiver permissão `0777` ou dono incorreto
- [ ] UPL-002 enforce --apply ajusta para modo `0750` e dono/grupo `root:apache`
- [ ] UPL-002 segundo enforce --apply não altera nada
- [ ] UPL-004 audit reprova se contexto SELinux não for `httpd_sys_rw_content_t`
- [ ] UPL-004 enforce --apply aplica `chcon -R -t httpd_sys_rw_content_t /var/www/uploads`
- [ ] UPL-004 segundo enforce --apply não altera nada
- [ ] UPL-005 audit reprova se `/etc/httpd/conf.d/hardener-uploads.conf` estiver ausente
- [ ] UPL-005 enforce --apply cria a configuração do Apache com `-ExecCGI -Indexes -Includes` e `AllowOverride None`
- [ ] UPL-005 segundo enforce --apply não altera nada
- [ ] UPL-005 rollback restaura ou remove o arquivo de configuração

## Modelo para cada regra nova

```
- [ ] <ID> audit reprova na VM suja
- [ ] <ID> enforce --apply corrige (relatório mostra CORRIGIDO)
- [ ] <ID> segundo enforce --apply não altera nada
- [ ] <ID> rollback restaura o estado anterior
- [ ] <ID> nenhum serviço legítimo quebrou (SELinux/audit.log, sessão SSH, firewall)
```

## Anotações da VM

- Distribuição e versão: _
- Arquivo/perfil OpenSCAP confirmado: _
- Problemas encontrados: _
