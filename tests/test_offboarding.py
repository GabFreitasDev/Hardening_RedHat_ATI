"""Testes unitários para o módulo de offboarding (Dor 5 da ATI)."""

import json
from pathlib import Path
import pytest

from hardener.offboarding import (
    ErroOffboarding,
    carregar_autorizados_csv,
    executar_offboarding,
    listar_usuarios_locais,
)
from hardener.runner import ResultadoComando


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


def test_status_desligado_no_csv(tmp_path):
    """Contas com status 'desligado', 'inativo' ou 'desativado' não são autorizadas."""
    arq = tmp_path / "lista_status.csv"
    arq.write_text(
        "usuario,status\n"
        "root,ativo\n"
        "admin_ati,ativo\n"
        "ex_funcionario,desligado\n"
        "estagiario,inativo\n"
        "terceiro,desativado\n",
        encoding="utf-8"
    )
    autorizados = carregar_autorizados_csv(arq)
    assert "root" in autorizados
    assert "admin_ati" in autorizados
    assert "ex_funcionario" not in autorizados
    assert "estagiario" not in autorizados
    assert "terceiro" not in autorizados


def test_csv_so_com_root_e_recusado(tmp_path):
    """CSV vazio ou contendo apenas root deve ser recusado para evitar bloqueio total."""
    arq = tmp_path / "apenas_root.csv"
    arq.write_text("usuario,setor\nroot,TI\n", encoding="utf-8")

    with pytest.raises(ErroOffboarding) as exc:
        carregar_autorizados_csv(arq)

    assert "somente o usuário 'root'" in str(exc.value)


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


def test_falha_usermod_aparece_em_falhas(raiz, estado, runner, csv_autorizados):
    """Falhas na execução de comandos vão para a lista 'falhas' e não entram em 'mudancas'."""
    runner.respostas["usermod -L ex_funcionario"] = ResultadoComando(
        rc=1, saida="", erro="usermod: user ex_funcionario is currently used by process 1234"
    )

    relatorio = executar_offboarding(
        caminho_csv=csv_autorizados,
        raiz=raiz,
        estado_dir=estado,
        aplicar=True,
        runner=runner,
    )

    assert len(relatorio["falhas"]) > 0
    falha = [f for f in relatorio["falhas"] if f["conta"] == "ex_funcionario" and f["acao"] == "usermod -L"][0]
    assert "currently used" in falha["erro"]
    assert all("usermod -L em 'ex_funcionario'" not in m for m in relatorio["mudancas"])


def test_conta_ja_bloqueada_nao_gera_acoes(raiz, estado, runner, csv_autorizados):
    """Contas que já estão com ! no shadow, expiradas em 0 e com nologin não geram ações."""
    # Cria /etc/shadow com contas já bloqueadas e expiradas
    (raiz / "etc" / "shadow").write_text(
        "root:$6$hash:19000:0:99999:7:::\n"
        "admin_ati:$6$hash:19000:0:99999:7:::\n"
        "root:$6$hash:19000:0:99999:7:::\n"
        "admin_ati:$6$hash:19000:0:99999:7:::\n"
        "ex_funcionario:!$6$hash:19000:0:99999:7::0:\n"
        "estagiario:!$6$hash:19000:0:99999:7::0:\n",
        encoding="utf-8"
    )
    # /etc/passwd com shells já em /sbin/nologin
    (raiz / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin_ati:x:1000:1000:Admin ATI:/home/admin_ati:/bin/bash\n"
        "ex_funcionario:x:1001:1001:Ex Funcionario:/home/ex_funcionario:/sbin/nologin\n"
        "estagiario:x:1002:1002:Estagiario Temp:/home/estagiario:/sbin/nologin\n",
        encoding="utf-8"
    )
    # /etc/group sem os usuários em wheel
    (raiz / "etc" / "group").write_text(
        "root:x:0:\n"
        "wheel:x:10:root,admin_ati\n",
        encoding="utf-8"
    )

    # Dry-run não deve listar SERIA_CORRIGIDO
    relatorio_dry = executar_offboarding(csv_autorizados, raiz, estado, aplicar=False, runner=runner)
    assert not any("[SERIA_CORRIGIDO]" in a for a in relatorio_dry["acoes"])
    assert any("já se encontram devidamente bloqueadas" in a for a in relatorio_dry["acoes"])

    # Apply não deve alterar nada nem criar backup
    relatorio_app = executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert relatorio_app["mudancas"] == []
    assert not (estado / "backups").exists()


def test_segundo_apply_nao_altera_nada_e_nao_cria_nova_pasta_backup(raiz, estado, runner, csv_autorizados):
    """Após o primeiro apply, uma segunda execução não altera nada nem cria nova pasta de backup."""
    relatorio1 = executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert len(relatorio1["mudancas"]) > 0
    pastas_bkp_1 = list((estado / "backups").iterdir())
    assert len(pastas_bkp_1) == 1

    # Atualiza o estado simulado do sistema para refletir que as contas foram bloqueadas
    (raiz / "etc" / "shadow").write_text(
        "root:$6$hash:19000:0:99999:7:::\n"
        "admin_ati:$6$hash:19000:0:99999:7:::\n"
        "ex_funcionario:!$6$hash:19000:0:99999:7::0:\n"
        "estagiario:!$6$hash:19000:0:99999:7::0:\n",
        encoding="utf-8"
    )
    (raiz / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin_ati:x:1000:1000:Admin ATI:/home/admin_ati:/bin/bash\n"
        "ex_funcionario:x:1001:1001:Ex:/home/ex_funcionario:/sbin/nologin\n"
        "estagiario:x:1002:1002:Est:/home/estagiario:/sbin/nologin\n",
        encoding="utf-8"
    )
    (raiz / "etc" / "group").write_text(
        "root:x:0:\n"
        "wheel:x:10:root,admin_ati\n",
        encoding="utf-8"
    )

    relatorio2 = executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert relatorio2["mudancas"] == []
    pastas_bkp_2 = list((estado / "backups").iterdir())
    assert len(pastas_bkp_2) == 1  # Nenhuma pasta nova foi criada


def test_gshadow_incluido_no_backup(raiz, estado, runner, csv_autorizados):
    """/etc/gshadow deve estar presente no backup inicial junto de passwd, shadow e group."""
    (raiz / "etc" / "shadow").write_text("root:$6$hash:19000:0:99999:7:::\n", encoding="utf-8")
    (raiz / "etc" / "gshadow").write_text("wheel:::root,admin_ati,ex_funcionario\n", encoding="utf-8")


    relatorio = executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert "sessao_backup" in relatorio

    manifest_file = estado / "backups" / relatorio["sessao_backup"] / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    caminhos = [e["caminho"] for e in manifest["entradas"]]
    assert "/etc/gshadow" in caminhos
    assert "/etc/group" in caminhos
    assert "/etc/passwd" in caminhos
    assert "/etc/shadow" in caminhos


def test_operador_nao_autorizado_com_apply_recusado(raiz, estado, runner, csv_autorizados, monkeypatch):
    """Se o operador atual (SUDO_USER) não estiver na lista de autorizados, o apply é abortado."""
    monkeypatch.setenv("SUDO_USER", "operador_externo")

    with pytest.raises(ErroOffboarding) as exc:
        executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)

    assert "lockout" in str(exc.value)


def test_terminar_sessao_loginctl_e_fallback_pkill(raiz, estado, runner, csv_autorizados):
    """Sessão é encerrada via loginctl terminate-user; se falhar, tenta pkill -9 -u."""
    # Cenário 1: loginctl funciona
    executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert runner.chamou("loginctl", "terminate-user", "ex_funcionario")

    # Cenário 2: loginctl falha, aciona pkill
    runner.respostas["loginctl terminate-user ex_funcionario"] = ResultadoComando(
        rc=1, saida="", erro="Failed to terminate user: No session"
    )
    runner.chamadas.clear()

    executar_offboarding(csv_autorizados, raiz, estado, aplicar=True, runner=runner)
    assert runner.chamou("pkill", "-9", "-u", "ex_funcionario")


def test_offboarding_todos_autorizados_nao_gera_acoes(raiz, estado, runner, tmp_path):
    c = tmp_path / "todos.csv"
    c.write_text("usuario\nroot\nadmin_ati\nex_funcionario\nestagiario\n", encoding="utf-8")
    relatorio = executar_offboarding(c, raiz, estado, aplicar=False, runner=runner)
    assert len(relatorio["contas_nao_autorizadas"]) == 0
    assert "Nenhuma conta não autorizada" in relatorio["acoes"][0]
