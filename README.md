# Hardening RedHat ATI (React & TypeScript)

Aplicação web interativa para **auditoria, aplicação e reversão de regras de hardening em Red Hat Enterprise Linux 9** (e derivados Rocky/AlmaLinux 9), baseada em políticas declarativas em YAML alinhadas ao **CIS Benchmark** e mapeadas às 6 dores operacionais da **ATI** (Agência Estadual de Tecnologia da Informação, Recife/PE).

Projeto reescrito em **React, TypeScript, Vite e Tailwind CSS**, preservando rigorosamente todo o contrato, a lógica de negócio do motor, a trava de segurança da VM (`/etc/hardener-vm`), backups atômicos (`manifest.json`) e o formato exato da CLI e relatórios.

---

## Funcionalidades Principais

1. **Dashboard & Matriz de Regras CIS / ATI**:
   - Índice de conformidade em tempo real (0 a 100%) e cálculo de código de saída (`0` tudo conforme, `1` pendências, `2` falha/erro).
   - Classificação e filtragem pelas **6 Dores da ATI**:
     - **Dor 1: Ransomware** (`/tmp`, `/var/tmp`, `/dev/shm` com `noexec,nosuid,nodev`, SELinux em `enforcing`, kernel ASLR/sysctl).
     - **Dor 2: Uploads de arquivos** (diretórios de upload sem permissão de execução, dono/grupo restrito, contexto SELinux).
     - **Dor 3: Movimentação lateral** (firewalld zona `drop`, portas restritas, SSH `AllowGroups`, desativação de `ip_forward` e redirects ICMP).
     - **Dor 4: Patches** (controle e auditoria de vulnerabilidades).
     - **Dor 5: Revogação de credenciais** (offboarding, bloqueio de contas inativas com `usermod -L` e `chage -E 0`, `nologin`, arquivamento de `authorized_keys`, limpeza de `wheel`).
     - **Dor 6: Mínimo privilégio** (`PermitRootLogin no`, permissões de `sshd_config`, proibição de `NOPASSWD` e `ALL` em sudoers, UID 0 exclusivo para root, `umask 027`, `pam_faillock`, `pam_pwquality`).

2. **Motor de Execução (Audit, Enforce & Rollback)**:
   - **Audit (`audit`)**: verifica o estado do sistema sem realizar alterações.
   - **Enforce Dry-Run (`enforce`)**: simula detalhadamente o que seria corrigido (`SERIA_CORRIGIDO`).
   - **Enforce Apply (`enforce --apply`)**:
     - Trava de segurança ativa: exige RHEL 9, privilégio root (EUID 0) e presença do marcador `/etc/hardener-vm`.
     - Gravação atômica de drop-in em `/etc/ssh/sshd_config.d/00-hardener.conf` e arquivos do sistema.
     - Validação prévia de sintaxe do serviço (`sshd -t`, `visudo -c`) e recarga controlada (`systemctl reload`). Se houver falha, as alterações daquele serviço são revertidas automaticamente para manter a disponibilidade.
     - Total idempotência: execuções repetidas mantêm `CONFORME` sem criar sessões adicionais de backup nem recargas desnecessárias.
   - **Rollback (`rollback`)**:
     - Desfaz a última sessão de enforce pendente em ordem inversa, restaura arquivos originais (ou remove drop-ins criados que não existiam) e recarrega os serviços afetados.

3. **Terminal CLI Interativo**:
   - Emulador de terminal shell para execução de comandos (`python -m hardener audit`, `enforce`, `enforce --apply`, `rollback`, `report --formato json`, `validar`).
   - Botões de atalho rápido e visualização idêntica à saída em texto e JSON da ferramenta.

4. **Editor de Políticas Declarativas (YAML)**:
   - Leitura e edição de `rules/*.yaml` com validação de campos obrigatórios (`id`, `descricao`, `referencia`, `dor_ati`, `severidade`, `plataforma`, `primitiva`) e detecção de itens CIS pendentes de confirmação ("A CONFIRMAR").

5. **Gerenciador de Backups & Ponto de Restauração**:
   - Inspeção de cada sessão em `/var/lib/hardener/backups/<id>/manifest.json` com diff de arquivos salvos e status de reversão.

6. **Laboratório de Sistema RHEL 9 Virtual**:
   - Visualizador de arquivos de configuração do sistema (`/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/sysctl.d/99-sysctl.conf`, `/etc/fstab`, etc.).
   - Alternadores para simular falha em `sshd -t` e `systemctl reload` para testar reversões de segurança.

---

## Desenvolvimento e Execução

```bash
npm install
npm run dev
```

A aplicação roda em `http://localhost:3000`.
Para build de produção:

```bash
npm run build
```
