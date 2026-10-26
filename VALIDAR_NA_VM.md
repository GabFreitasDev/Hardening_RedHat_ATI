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
- [ ] PAM-001 / PAM-001b audit reprova na VM com `faillock.conf` padrão/desconfigurado.
- [ ] PAM-001 / PAM-001b enforce --apply corrige `deny = 5` e `unlock_time = 900` em `/etc/security/faillock.conf`.
- [ ] PAM-001 / PAM-001b segundo enforce --apply não altera nada (idempotência).
- [ ] PAM-001 / PAM-001b rollback restaura `/etc/security/faillock.conf` anterior.
- [ ] PAM-002 audit, enforce --apply (`minlen = 14` em `/etc/security/pwquality.conf`) e rollback funcionam na VM.
- [ ] ACC-002 audit, enforce --apply (`UMASK 027` em `/etc/login.defs`) e rollback funcionam na VM.

## Pendentes: regras de sudoers (SUDO-001, SUDO-002)

- [ ] Testar sempre com duas sessões SSH/root abertas antes de rodar enforce em regras de sudoers para prevenir lockout.
- [ ] Confirmar que `sudo -l` continua funcionando normalmente para o usuário administrador de teste.
- [ ] Garantir que o enforce não removeu a única forma de virar root na máquina (ex.: `%wheel` preservado com acesso via senha).
- [ ] Depois do `enforce --apply`, rodar `sudo visudo -c` e confirmar que passa sem alertas ou erros.
- [ ] Testar caminho de falha: com o arquivo quebrado de propósito, o motor reverte alterações (depende do ajuste do Aluno A em `engine.py` e `rhel.py` para validar via `visudo -c` sem chamar `systemctl reload sudoers`).
- [ ] SUDO-001 audit reprova na VM suja com as regras de `demo/sujar_servidor.sh` (`/etc/sudoers.d/99-inseguro-ati`).
- [ ] SUDO-001 enforce --apply comenta a linha com `# hardener: desativado: `, preserva permissão `0440` e segundo enforce não altera nada.
- [ ] SUDO-002 audit não reprova `%wheel ALL=(ALL) ALL`, mas reprova `estagiario ALL=(ALL) ALL`.
- [ ] SUDO-001 e SUDO-002 rollback restauram o arquivo original perfeitamente.

## Pendentes: contas e privilégios (ACC-001, SUDO-003)

- [ ] ACC-001 audit reprova na VM se houver conta secundária com UID 0 (ex.: `toor:x:0:0:...` adicionado em `/etc/passwd`).
- [ ] ACC-001 audit é somente auditoria: não tenta remoção automática e instrui revisão manual do administrador.
- [ ] SUDO-003 audit reprova se usuário não homologado estiver em `wheel` (ex.: `ex_funcionario`).
- [ ] SUDO-003 enforce --apply remove membro indevido via `gpasswd -d` mantendo `admin_ati` e `root`.
- [ ] SUDO-003 segundo enforce --apply é idempotente e rollback restaura `/etc/group` e `/etc/gshadow`.

## Pendentes: offboarding e revogação de acessos (OFF-001 a OFF-008)

- [ ] A conta do operador (usuário em `SUDO_USER`) NUNCA é bloqueada; se não constar na lista de autorizados, o modo `--apply` recusa com `ErroOffboarding`.
- [ ] SSH com chave autorizada real é RECUSADO após o offboarding da conta desligada (chave movida de `~/.ssh/authorized_keys` para `/var/backups/revoked_ssh_keys/`).
- [ ] Conferir o formato de data do utilitário `lastlog` no RHEL 9 e confirmar compatibilidade com `relatorio_contas_inativas`.
- [ ] Conferir o valor de `AuthorizedKeysFile` em `sshd -T` para assegurar que está no padrão `.ssh/authorized_keys`.
- [ ] `loginctl terminate-user` encerra a sessão ativa do usuário desligado imediatamente; se falhar, o fallback via `pkill -9 -u` finaliza os processos.
- [ ] OFF-001 a OFF-005 enforce --apply bloqueia a conta (`usermod -L`, `chage -E 0`), ajusta shell para `/sbin/nologin` e arquiva as chaves.
- [ ] Segundo enforce --apply de offboarding não executa nenhuma ação nem cria nova pasta de backup.
- [ ] OFF-006, OFF-007 e OFF-008 emitem relatórios detalhados sem alterar o estado do sistema.

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
