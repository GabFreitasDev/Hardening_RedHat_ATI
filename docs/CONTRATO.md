# Contrato entre módulos (rascunho v0.1)

Este documento é a proposta para a reunião de sábado (24/10). O escopo pede que os três fechem o
contrato **antes** de gerar código; o que está aqui já está implementado e testado, mas qualquer
ponto pode mudar se a equipe decidir diferente. Mudou algo? Atualize este arquivo no mesmo commit.

## 1. Regra YAML

Um arquivo por domínio em `rules/`; cada arquivo é uma **lista** de regras.

```yaml
- id: SSH-001
  descricao: Desabilitar login direto como root
  referencia: "CIS RHEL 9 - SSH PermitRootLogin (A CONFIRMAR o item no benchmark)"
  dor_ati: [6]            # ao menos uma dor, inteiros de 1 a 6
  severidade: alta        # baixa | media | alta | critica
  plataforma: rhel9
  primitiva: sshd_config  # nome registrado em hardener/checks/__init__.py
  parametros:             # específicos de cada primitiva
    chave: PermitRootLogin
    valor: "no"           # SEMPRE entre aspas
  recarregar: sshd        # opcional: serviço a validar e recarregar após corrigir
```

Obrigatórios: `id, descricao, referencia, dor_ati, severidade, plataforma, primitiva`.
Opcionais: `parametros, recarregar`. Campos desconhecidos são rejeitados por
`python -m hardener validar`. Os ids são únicos e usam prefixo por domínio (SSH-, SUDO-, MNT-...).
A `referencia` só deixa de conter "A CONFIRMAR" depois de conferida no benchmark oficial.

## 2. Primitiva (`hardener/checks/base.py`)

```python
class MinhaPrimitiva(Primitiva):
    nome = "minha_primitiva"                       # usado em `primitiva:` no YAML
    def validar_parametros(self, params) -> List[str]   # erros de parâmetros (vazio = ok)
    def verificar(self, params, ctx) -> Verificacao     # NUNCA altera o sistema
    def corrigir(self, params, ctx) -> List[str]        # idempotente; devolve o que alterou
    def descrever(self, params) -> str                  # texto do dry-run
```

- `Verificacao(conforme, atual, esperado, detalhe)`.
- Erro inesperado: levante `ErroPrimitiva("mensagem")`. O motor registra ERRO e segue para a próxima regra.
- Arquivos: `ctx.caminho("/etc/x")` para ler/escrever; `ctx.salvar_antes_de_alterar("/etc/x")`
  **antes** de escrever (habilita o rollback).
- Comandos: `ctx.runner.executar([...])` (lista de argumentos, sem shell).
- Validação/recarga de serviço não é da primitiva: ela só declara `recarregar:` na regra e o motor
  chama `rhel.validar_servico` (ex.: `sshd -t`, `visudo -c`) e depois `rhel.recarregar_servico`.
  Para um serviço novo, registre o validador em `hardener/rhel.py` (`VALIDADORES`).

Primitivas previstas (todas pendentes, exceto `sshd_config`):
`sudoers`, `conta_usuario`, `permissao_arquivo`, `suid_sgid`, `pam_faillock`, `pam_pwquality`,
`sysctl`, `montagem`, `firewalld`, `portas_escuta`, `selinux`, `servico`, `pacote`.

## 3. Fluxo do motor (`enforce --apply`)

1. Verifica cada regra. `CONFORME`, `PULADO` (outra plataforma) e `ERRO` seguem sem alteração.
2. `NAO_CONFORME`: `corrigir` -> reverifica. Conforme = `CORRIGIDO`; senão `FALHOU` (alteração mantida,
   rollback disponível).
3. Por serviço com `recarregar:`, uma vez só no fim: valida sintaxe; se ok, recarrega; se falhar,
   restaura os arquivos daquele serviço e marca as regras como `FALHOU` ("alterações revertidas").
4. Segunda execução: tudo `CONFORME`, nenhuma sessão de backup nova, nenhuma recarga.

`enforce` sem `--apply` (ou com `--dry-run`) nunca altera nada e devolve `SERIA_CORRIGIDO`.

## 4. Backup e rollback

`<estado-dir>/backups/<AAAAMMDD-HHMMSS>/manifest.json` + `arquivos/NNNN` (cópias originais).
Uma sessão por execução que altera algo; cada arquivo é salvo **uma vez** (estado original).
`rollback` restaura (ou remove o que não existia), na ordem inversa, valida e recarrega os serviços
envolvidos, e marca a sessão como revertida. Estado padrão: `/var/lib/hardener` (`--estado-dir` ou
`HARDENER_ESTADO_DIR` mudam).

## 5. Relatório

Texto (stdout) e JSON (`--json arquivo`; também salvo em `<estado-dir>/relatorios/`).
Campos do JSON: `ferramenta, versao, modo, gerado_em, host, plataforma, resumo, por_dor, regras[], avisos[]`.
Cada item de `regras`: `id, descricao, referencia, dor_ati, severidade, status, atual, esperado, detalhe, mudancas`.
Status: `CONFORME, NAO_CONFORME, SERIA_CORRIGIDO, CORRIGIDO, FALHOU, PULADO, ERRO`.
Códigos de saída: `0` tudo conforme · `1` há `NAO_CONFORME`/`SERIA_CORRIGIDO` · `2` há `ERRO`/`FALHOU` ou uso inválido.

## 6. Decisões em aberto (precisam de OK da equipe)

1. **Formato da regra.** O exemplo do escopo usa comandos de shell em `verificar:`/`corrigir:`
   (`sshd -T | grep ...`). Aqui a regra escolhe uma **primitiva** e passa `parametros`. Motivo: testável
   sem a VM, sem `shell=True`, backup e idempotência garantidos num só lugar. Custo: cada tipo novo de
   configuração exige uma primitiva (mas uma primitiva atende dezenas de regras).
2. **`enforce` e dry-run.** O escopo lista `enforce --dry-run` e `enforce`, e também diz "dry-run por
   padrão". Resolvido assim: `enforce` sozinho é dry-run; aplicar exige `--apply`. O roteiro de
   demonstração passa a usar `enforce --apply`.
3. **Trava da VM.** `--apply` recusa rodar sem root, fora de RHEL 9 ou sem o arquivo `/etc/hardener-vm`
   (criado à mão na VM). Garante a regra "enforce só na VM".
4. **Arquivo do SSH.** As correções vão para `/etc/ssh/sshd_config.d/00-hardener.conf`. O prefixo `00-`
   existe porque o sshd usa o primeiro valor lido; confirmar na VM (ver `VALIDAR_NA_VM.md`).
5. **Offboarding.** O comando `offboarding --autorizados lista.csv` (Aluno B) ainda não existe na CLI.
   Proposta: subcomando próprio que reaproveita backup e relatório do motor.
