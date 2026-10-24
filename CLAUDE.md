# Contexto do projeto (para assistentes de IA e para a equipe)

Ferramenta CLI em Python de conformidade de hardening para **RHEL 9** (disciplina de Sistemas
Operacionais). Escopo completo em `demo/docs/Escopo_Projeto_Hardening_ATI.pdf`; contrato em
`docs/CONTRATO.md`. Entrega: **09/11/2026**. Congelamento do código: **05/11/2026**
(nenhuma funcionalidade nova depois disso).

## O que a ferramenta é (e não é)

- Verifica, aplica e reverte **configuração** (estado de hardening). Não é antivírus nem
  scanner de vulnerabilidades.
- Prioridade (MVP): dores 5, 6 e 3 da ATI, mais a parte de SO das dores 1 e 2 (~30 regras).
  Dor 4 (patches) está **fora da entrega**.
- Alvo: RHEL 9 / Rocky 9 / AlmaLinux 9. Ubuntu e CentOS estão fora do escopo.

## Convenções obrigatórias

- **Python 3.9** (o do RHEL 9). Sem `match`, sem `X | Y` em anotações avaliadas em runtime, sem
  recursos de 3.10+. Use `from __future__ import annotations`.
- **Única dependência de execução: PyYAML.** Não adicione bibliotecas sem combinar com a equipe.
- **Dry-run por padrão.** `enforce` só altera algo com `--apply`.
- **Nada de shell.** Comandos só via `hardener/runner.py` (lista de argumentos, sem `shell=True`).
  Código específico de RHEL (systemctl, validadores) fica em `hardener/rhel.py`.
- **Toda E/S em arquivos usa `ctx.caminho("/etc/...")`** e chama `ctx.salvar_antes_de_alterar(...)`
  antes de escrever. É isso que permite testar em diretório temporário e fazer rollback.
- **Idempotência:** rodar `enforce --apply` duas vezes não altera nada na segunda.
- **Referências CIS:** nunca escreva número de item do CIS de memória. Use
  `"... (A CONFIRMAR o item no benchmark)"` até conferir no benchmark oficial.
- No YAML, `"no"` e `"yes"` **sempre entre aspas** (sem aspas viram booleano).
- Não rode `enforce --apply` fora da VM. Não execute como root nada que não tenha sido revisado.
- Revise todo diff gerado por IA antes de rodar na VM; todos devem saber explicar o código.
  Registre as partes feitas com apoio de IA conforme a política da disciplina.

## Comandos

```bash
pytest                         # testes (qualquer máquina)
python -m hardener validar     # valida rules/*.yaml (qualquer máquina)
sudo python3 -m hardener audit | enforce [--apply] | rollback | report   # só na VM
```

## Como adicionar uma regra

1. Se já existe primitiva para o tipo de configuração: acrescente a regra no YAML do domínio
   (`rules/ssh.yaml`, `rules/accounts.yaml`, `rules/mounts.yaml`...), siga o formato de
   `docs/CONTRATO.md`, rode `python -m hardener validar`.
2. Se não existe: crie `hardener/checks/<nome>.py` herdando de `Primitiva`, registre em
   `hardener/checks/__init__.py` e escreva testes em `tests/` (use o `FakeRunner` de
   `tests/conftest.py`).
3. Ciclo por regra na VM: `audit` reprova na VM suja -> `enforce --apply` corrige -> segundo
   `enforce --apply` não altera nada -> `rollback` restaura -> commit.
   Itens que dependem do sistema real vão para `VALIDAR_NA_VM.md`.

## Divisão da equipe

- Aluno A: núcleo (CLI, política, backup/rollback, relatório, testes), depois demo e documentação.
- Aluno B: identidade e privilégio (dores 5 e 6): offboarding, sudoers, SSH, contas, PAM, SUID/SGID.
- Aluno C: host, rede e dados (dores 1, 2 e 3): montagens, firewalld, portas, sysctl, uploads, SELinux.
