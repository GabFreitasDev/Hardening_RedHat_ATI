# Documento de Arquitetura: Guarda de Patches (Dor 4 da ATI)

**Status:** Documentado como trabalho futuro (conforme Seção 5 e 7 do Escopo)  
**Autor:** Aluno A (Trilha Núcleo e Arquitetura)  
**Referência:** Escopo do Projeto Hardening ATI · Requisito Dor 4  

---

## 1. Contexto e Problema Relatado pela ATI

> *"Ao aplicar patches, é comum a aplicação parar de funcionar e precisar de correções."* — Relato da gerência da ATI (Recife/PE).

Em ambientes corporativos de infraestrutura crítica, a atualização de pacotes (`dnf update` / `yum update`) é essencial para correção de CVEs de segurança. No entanto, atualizações frequentemente introduzem quebras operacionais decorrentes de:
- Alterações em bibliotecas compartilhadas (ABI/API incompatível);
- Atualizações de arquivos de configuração com sobrescrita silenciosa (`.rpmnew` ou substituição);
- Depreciação de cifras criptográficas no OpenSSH/OpenSSL;
- Mudanças em comportamentos padrão de serviços de rede e banco de dados.

Por causa do prazo de 16 dias do projeto acadêmico, a implementação automatizada da Dor 4 foi deliberadamente definida como **trabalho futuro**. Este documento registra o design arquitetural completo para orientar a implementação na próxima versão do Hardener.

---

## 2. Princípios de Solução

1. **Snapshot Leve sem Necessidade de LVM:**  
   Não depender de snapshots de bloco ou LVM snapshot para permitir execução em qualquer máquina virtual ou container com armazenamento padrão.
2. **Uso Nativo do Gerenciador DNF:**  
   Aproveitar o banco transacional nativo do Red Hat Enterprise Linux 9 (`dnf history`).
3. **Idempotência e Não-Destrutividade:**  
   Qualquer teste de atualização que falhe deve deixar o host exatamente no estado funcional anterior.
4. **Relatório de Diferença (Diff):**  
   O operador deve ver exatamente o que mudou (pacotes alterados, portas abertas que sumiram, serviços que deixaram de subir).

---

## 3. Fluxo de Execução Proposto (`patch-guard`)

O comando proposto para a CLI será:

```bash
# Executa a rotina de atualização com snapshot prévio e testes automáticos
sudo python3 -m hardener patch-guard --check-health "curl -f http://localhost:8080/health"
```

### Passo a Passo do Ciclo de Vida:

```
[1. Snapshot Pré-Patch] 
       │
       ▼
[2. Execução Transacional DNF] 
       │
       ▼
[3. Health Checks & Diff]
       ├── Se Sucesso ──► [4. Finalização & Evidência]
       └── Se Falha   ──► [5. Rollback Automático (dnf history undo)]
```

### 3.1. Fase 1: Snapshot Pré-Patch (Baseline de Saúde)
Antes de qualquer comando `dnf update`, o Hardener coleta em `<estado_dir>/patch-snapshots/<timestamp>/`:
1. **Lista Completa de Pacotes e Versões:**  
   Executa: `rpm -qa --qf "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n" > pacotes.txt`
2. **Serviços Ativos no Systemd:**  
   Executa: `systemctl list-units --type=service --state=running --no-pager --plain > servicos.txt`
3. **Matriz de Portas em Escuta:**  
   Executa: `ss -tuln > portas.txt`
4. **Árvore de Hashes de Configuração (`/etc`):**  
   Calcula hash SHA-256 de todos os arquivos monitorados gerenciados pelo Hardener.
5. **ID da Transação DNF Atual:**  
   Lê o último ID em `dnf history list`.

### 3.2. Fase 2: Execução da Atualização
O motor invoca a atualização de forma controlada:
```bash
dnf update -y --setopt=install_weak_deps=False
```
O DNF registra uma nova transação com ID `N`.

### 3.3. Fase 3: Health Checks Pós-Patch
O Hardener aguarda a reinicialização dos daemons e avalia os critérios de aceite:
1. **Verificação de Serviços:** Todos os serviços da lista `servicos.txt` continuam ativos?
2. **Verificação de Portas:** Todas as portas da lista `portas.txt` continuam em escuta?
3. **Sintaxe de Daemons Críticos:** Validações de sintaxe (`sshd -t`, `visudo -c`, `named-checkconf`).
4. **Probe Customizado da Aplicação:** Executa o comando de teste configurado pelo administrador (ex.: `curl -f http://localhost/status`).

### 3.4. Fase 4: Rollback Automático em Caso de Falha
Se qualquer health check falhar:
1. O Hardener emite aviso crítico no stdout e no log;
2. Executa a reversão da transação do DNF:
   ```bash
   dnf history undo <id_da_transacao> -y
   ```
3. Restaura os arquivos de configuração gerenciados a partir da sessão de backup do Hardener;
4. Reinicia os serviços afetados;
5. Reexecuta os health checks para confirmar o retorno ao estado estável.

---

## 4. Integração com o Relatório da ATI

O relatório gerado pela rotina de patch integrará o formato JSON padrão do Hardener:

```json
{
  "ferramenta": "hardener",
  "modo": "patch-guard",
  "dor_ati": 4,
  "transacao_dnf": 42,
  "status": "ROLLBACK_EXECUTADO",
  "motivo_falha": "Servico 'httpd.service' falhou ao reiniciar apos atualizacao do mod_ssl",
  "pacotes_revertidos": [
    "httpd-2.4.57-8.el9 -> httpd-2.4.57-5.el9",
    "mod_ssl-2.4.57-8.el9 -> mod_ssl-2.4.57-5.el9"
  ],
  "tempo_recuperacao_segundos": 14.2
}
```

---

## 5. Limites Declarados e Riscos

- **Atualização de Kernel:** Patches de kernel exigem reboot para entrar em vigor e não podem ser revertidos apenas com `dnf history undo` sem reiniciar o host.
- **Banco de Dados (Migrations):** Se a atualização de um software disparou alterações em esquema de banco de dados no disco (ex.: PostgreSQL / MySQL), o rollback de binários via DNF não desfaz alterações nas tabelas; o backup lógico da base continua sob responsabilidade do DBA.
