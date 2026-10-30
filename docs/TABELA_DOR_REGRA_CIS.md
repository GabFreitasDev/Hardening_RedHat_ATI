# Tabela dor / regra / item CIS

Lista de trabalho derivada do escopo (seção 5). Os ids são **propostos** e a lista é aproximada
(~30 regras no MVP): cortem ou juntem regras conforme o checkpoint de 28/10.

A coluna **CIS** fica `A CONFIRMAR` até alguém abrir o CIS Benchmark oficial do RHEL 9 e anotar o
item e o nome exatos. Não preencher de memória.

Dores da ATI: 1 Ransomware · 2 Uploads · 3 Movimentação lateral · 4 Patches (fora da entrega) ·
5 Revogação de credenciais · 6 Mínimo privilégio.

## Trilha B: identidade e privilégio (dores 5 e 6)

| ID | Dor | Regra | Primitiva | CIS | Status |
|---|---|---|---|---|---|
| SSH-001 | 6 | `PermitRootLogin no` | `sshd_config` | A CONFIRMAR | implementada (exemplo) |
| SSH-002 | 6 | permissões de `/etc/ssh/sshd_config` | `permissao_arquivo` | A CONFIRMAR | implementada |
| SUDO-001 | 6 | sem `NOPASSWD` indevido em sudoers e `sudoers.d` | `sudoers` | A CONFIRMAR | implementada |
| SUDO-002 | 6 | sem `ALL` indevido em sudoers e `sudoers.d` | `sudoers` | A CONFIRMAR | implementada |
| SUDO-003 | 6 | grupo `wheel` igual à lista autorizada | `conta_usuario` | A CONFIRMAR | implementada |
| ACC-001 | 6 | UID 0 único | `conta_usuario` | A CONFIRMAR | implementada |
| PERM-001 | 6 | SUID/SGID comparados com lista permitida | `suid_sgid` | A CONFIRMAR | implementada |
| PERM-002 | 6 | permissões de `/etc/passwd` | `permissao_arquivo` | A CONFIRMAR | implementada |
| PERM-003 | 6 | permissões de `/etc/shadow` | `permissao_arquivo` | A CONFIRMAR | implementada |
| ACC-002 | 6 | umask padrão | `arquivo_chave_valor` | A CONFIRMAR | implementada |
| PAM-001 | 6 | `faillock` configurado | `arquivo_chave_valor` | A CONFIRMAR | implementada |
| PAM-001b | 6 | `faillock` tempo de desbloqueio (`unlock_time`) | `arquivo_chave_valor` | A CONFIRMAR | implementada |
| PAM-002 | 6 | `pwquality` configurado | `arquivo_chave_valor` | A CONFIRMAR | implementada |
| OFF-001 | 5 | contas locais fora da lista bloqueadas (`usermod -L`, `chage -E 0`) | `offboarding` | n/a (requisito da ATI) | implementada |
| OFF-002 | 5 | shell `nologin` nas contas bloqueadas | `offboarding` | n/a | implementada |
| OFF-003 | 5 | `authorized_keys` das contas bloqueadas arquivado | `offboarding` | n/a | implementada |
| OFF-004 | 5 | contas bloqueadas removidas de `wheel` | `offboarding` | n/a | implementada |
| OFF-005 | 5 | sessões ativas das contas bloqueadas encerradas | `offboarding` | n/a | implementada |
| OFF-006 | 5 | relatório de contas inativas | `offboarding` | A CONFIRMAR | implementada |
| OFF-007 | 5 | relatório de senhas sem expiração | `offboarding` | A CONFIRMAR | implementada |
| OFF-008 | 5 | relatório de chaves SSH sem dono | `offboarding` | n/a | implementada |

Limite declarado: identidades em AD/LDAP são revogadas no diretório, não no host.

## Trilha C: host, rede e dados (dores 1, 2 e 3)

| ID | Dor | Regra | Primitiva | CIS | Status |
|---|---|---|---|---|---|
| NET-001 | 3 | firewalld com zona restritiva e só os serviços declarados | `firewalld` | A CONFIRMAR | pendente |
| NET-002 | 3 | portas em escuta comparadas com a lista autorizada | `portas_escuta` | A CONFIRMAR | pendente |
| NET-003 | 3 | `AllowGroups` no SSH | `sshd_config` | A CONFIRMAR | implementada |
| NET-004 | 3 | `net.ipv4.ip_forward` | `sysctl` | A CONFIRMAR | implementada |
| NET-005 | 3 | redirects (`accept_redirects`, `send_redirects`) | `sysctl` | A CONFIRMAR | implementada |
| NET-006 | 3 | `rp_filter` e `log_martians` | `sysctl` | A CONFIRMAR | implementada |
| MNT-001 | 1 | `/tmp` com `noexec,nosuid,nodev` | `montagem` | A CONFIRMAR | implementada |
| MNT-002 | 1 | `/var/tmp` com `noexec,nosuid,nodev` | `montagem` | A CONFIRMAR | implementada |
| MNT-003 | 1 | `/dev/shm` com `noexec,nosuid,nodev` | `montagem` | A CONFIRMAR | implementada |
| SYS-001 | 1 | SELinux em `enforcing` | `selinux` | A CONFIRMAR | pendente |
| SYS-002 | 1 | arquivos world-writable sem sticky bit e sem dono | `permissao_arquivo` | A CONFIRMAR | pendente |
| SVC-001 | 1 | serviços inseguros desativados (telnet, rsh, tftp...) | `servico` | A CONFIRMAR | pendente |
| KRN-001 | 1 | sysctl de kernel (`randomize_va_space`, `kptr_restrict`, `dmesg_restrict`, `fs.suid_dumpable`) | `sysctl` | A CONFIRMAR | implementada |
| UPL-001 | 2 | diretórios de upload sem bit de execução | `permissao_arquivo` | n/a (requisito da ATI) | pendente |
| UPL-002 | 2 | dono e modo corretos nos diretórios de upload | `permissao_arquivo` | n/a | pendente |
| UPL-003 | 2 | montagem separada `noexec,nosuid,nodev` (ou fora do webroot) | `montagem` | n/a (requisito da ATI) | implementada |
| UPL-004 | 2 | contexto SELinux sem permissão de execução | `selinux` | n/a | pendente |
| UPL-005 | 2 | Apache sem executar scripts no caminho (desejável) | a definir | n/a | pendente |

Os diretórios de upload são **declarados na política** (ainda não existe o formato; propor em `rules/uploads.yaml`).
Limites declarados: nenhuma configuração bloqueia ransomware sozinha, e a ferramenta não inspeciona o
conteúdo dos arquivos enviados.
