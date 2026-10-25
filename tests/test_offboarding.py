"""Testes unitários para o módulo de offboarding (Dor 5 da ATI)."""

from pathlib import Path
import pytest

from hardener.offboarding import (
    carregar_autorizados_csv,
    executar_offboarding,
    listar_usuarios_locais,
)


def test_carregar_autorizados_csv_com_cabecalho(tmp_path):
    arq = tmp_path / "lista.csv"
    arq.write_text("usuario,setor\nroot,TI\nadmin_ati,SecOps\njoao,RH\n", encoding="utf-8")
    autorizados = carregar_autorizados_csv(arq)
    assert "root" in autorizados
    assert "admin_ati" in autorizados
    assert "joao" in autorizados
    assert len(autorizados) == 3


def test_carregar_autorizados_csv_com_ponto_e_virgula(tmp_path):
    arq = tmp_path / "lista_pv.csv"
    arq.write_text("user;departamento\nadmin_ati;Infra\nmaria;Financeiro\n", encoding="utf-8")
    autorizados = carregar_autorizados_csv(arq)
    assert "admin_ati" in autorizados
    assert "maria" in autorizados
    assert "root" in autorizados  # root sempre mantido


def test_listar_usuarios_locais_filtra_sistema(raiz):
    usuarios = listar_usuarios_locais(raiz)
    nomes = [u["username"] for u in usuarios]
    assert "root" in nomes
    assert "admin_ati" in nomes
    assert "ex_funcionario" in nomes
    assert "estagiario" in nomes


def test_offboarding_dry_run_identifica_contas_sem_alterar(raiz, estado, runner, csv_autorizados):
    relatorio = executar_offboarding(
        caminho_csv=csv_autorizados,
        raiz=raiz,
        estado_dir=estado,
        aplicar=False,
        runner=runner,
    )

    assert relatorio["modo"] == "enforce --dry-run"
    assert "ex_funcionario" in relatorio["contas_nao_autorizadas"]
    assert "estagiario" in relatorio["contas_nao_autorizadas"]
    assert "admin_ati" not in relatorio["contas_nao_autorizadas"]
    assert len(relatorio["mudancas"]) == 0
    assert any("[SERIA_CORRIGIDO]" in a for a in relatorio["acoes"])
    assert not runner.chamadas  # nenhum comando executado no sistema em dry-run


def test_offboarding_apply_executa_comandos_e_cria_backup(raiz, estado, runner, csv_autorizados):
    relatorio = executar_offboarding(
        caminho_csv=csv_autorizados,
        raiz=raiz,
        estado_dir=estado,
        aplicar=True,
        runner=runner,
    )

    assert relatorio["modo"] == "enforce --apply"
    assert len(relatorio["mudancas"]) > 0
    # Verifica que chamou usermod e chage para ex_funcionario e estagiario
    assert runner.chamou("usermod", "-L", "ex_funcionario")
    assert runner.chamou("chage", "-E", "0", "ex_funcionario")
    assert runner.chamou("usermod", "-L", "estagiario")
    assert runner.chamou("chage", "-E", "0", "estagiario")
    # Sessão de backup criada
    assert (estado / "backups").exists()
    assert "sessao_backup" in relatorio


def test_offboarding_todos_autorizados_nao_gera_acoes(raiz, estado, runner, tmp_path):
    c = tmp_path / "todos.csv"
    c.write_text("usuario\nroot\nadmin_ati\nex_funcionario\nestagiario\n", encoding="utf-8")
    relatorio = executar_offboarding(c, raiz, estado, aplicar=False, runner=runner)
    assert len(relatorio["contas_nao_autorizadas"]) == 0
    assert "Nenhuma conta não autorizada" in relatorio["acoes"][0]
