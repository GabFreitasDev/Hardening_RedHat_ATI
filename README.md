# Hardening_RedHat_ATI

Ferramenta de linha de comando que **verifica, aplica e reverte** regras de hardening em
Red Hat Enterprise Linux 9 (e equivalentes Rocky/AlmaLinux 9), a partir de uma política
declarativa em YAML. Projeto da disciplina de Sistemas Operacionais, motivado por dores
relatadas pela ATI (Agência Estadual de Tecnologia da Informação, Recife/PE).

- Escopo completo: [`demo/docs/Escopo_Projeto_Hardening_ATI.pdf`](demo/docs/Escopo_Projeto_Hardening_ATI.pdf)
- Contrato entre módulos: [`docs/CONTRATO.md`](docs/CONTRATO.md)
- Montar a VM de testes: [`docs/AMBIENTE_VM.md`](docs/AMBIENTE_VM.md)
- Regras planejadas (dor / regra / CIS): [`docs/TABELA_DOR_REGRA_CIS.md`](docs/TABELA_DOR_REGRA_CIS.md)
- Fila de validação no sistema real: [`VALIDAR_NA_VM.md`](VALIDAR_NA_VM.md)

> **Regra de segurança:** o `enforce --apply` só deve rodar na VM de testes, nunca nas máquinas
> pessoais. A CLI recusa rodar sem root, fora de RHEL 9 ou sem o marcador `/etc/hardener-vm`.

## Preparar o ambiente de desenvolvimento (máquina pessoal)

Com o repositório aberto no VS Code e o `.venv` criado:

```powershell
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

```bash
# Linux / macOS
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Depois, confira que está tudo certo:

```bash
pytest                      # testes unitários (usam mocks e diretórios temporários)
python -m hardener validar  # confere os YAML de rules/
```

Na máquina pessoal você escreve código, YAML e testes. O que depende do sistema real (SELinux,
firewalld, sysctl, montagens, contas) é validado na VM: veja `VALIDAR_NA_VM.md`.

## Uso (na VM)

```bash
sudo python3 -m hardener audit                   # só verifica; gera relatório "antes"
sudo python3 -m hardener enforce                 # dry-run (padrão): mostra o que mudaria
sudo python3 -m hardener enforce --apply         # aplica, com backup, validação e recarga
sudo python3 -m hardener rollback                # desfaz a última sessão de enforce
python3 -m hardener report [--formato json]      # reexibe o último relatório salvo
```

Filtros: `--regra SSH-001` (repetível), `--dor 6` (repetível), `--json arquivo.json`.
Códigos de saída: `0` tudo conforme, `1` há pendências, `2` houve erro/falha.

## Estrutura

```
hardener/
  cli.py        interface de linha de comando (audit, enforce, rollback, report, validar)
  engine.py     motor: orquestra verificar -> corrigir -> reverificar -> validar -> recarregar
  policy.py     leitura e validação dos YAML
  backup.py     backup antes de alterar e rollback
  report.py     relatório por regra e por dor da ATI (texto e JSON)
  runner.py     único ponto que executa comandos do sistema
  rhel.py       tudo que é específico de RHEL (validadores, systemctl, detecção de plataforma)
  models.py     tipos compartilhados (Regra, Resultado, Contexto)
  checks/       primitivas reutilizáveis (uma por tipo de configuração)
rules/          política em YAML, um arquivo por domínio (ssh, accounts, mounts, ...)
tests/          pytest
demo/           script de demonstração e documentos de apoio
docs/           contrato, ambiente, tabela dor/regra/CIS
```

## Status

Já funciona ponta a ponta com a regra de exemplo `SSH-001` (audit, dry-run, enforce, idempotência,
rollback, relatório). O restante das ~30 regras está listado em `docs/TABELA_DOR_REGRA_CIS.md`.
