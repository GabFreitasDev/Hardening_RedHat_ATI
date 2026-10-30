"""Testes unitários para a interface avaliar_offboarding e aplicar_offboarding (Parte 6)."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.models import Status
from hardener.offboarding import (
    aplicar_offboarding,
    avaliar_offboarding,
)
from hardener.runner import ResultadoComando


def test_avaliar_offboarding_conta_nao_autorizada_e_nao_conforme(raiz, runner, csv_autorizados):
    """Conta não autorizada pendente de ações deve resultar em NAO_CONFORME para OFF-001 a OFF-004."""
    # Simula sessões ativas com o comando loginctl
    runner.respostas["loginctl list-sessions --no-legend"] = ResultadoComando(
        0, "1 1001 ex_funcionario seat0 tty1\n"
    )
    runner.respostas["lastlog -b 90"] = ResultadoComando(0, "")

    resultados = avaliar_offboarding(csv_autorizados, raiz=raiz, runner=runner)
    res_map = {r.regra.id: r for r in resultados}

    # ex_funcionario e estagiario estão ativos na fixture raiz -> OFF-001 e OFF-002 não conformes
    assert res_map["OFF-001"].status == Status.NAO_CONFORME
    assert res_map["OFF-002"].status == Status.NAO_CONFORME

    # ex_funcionario está no grupo wheel -> OFF-004 não conforme
    assert res_map["OFF-004"].status == Status.NAO_CONFORME

    # Sessão ativa de ex_funcionario -> OFF-005 não conforme
    assert res_map["OFF-005"].status == Status.NAO_CONFORME

    # OFF-006 a OFF-008 vêm como somente_auditoria
    for rid in ("OFF-006", "OFF-007", "OFF-008"):
        r = res_map[rid]
        assert getattr(r.regra, "somente_auditoria", False) is True


def test_avaliar_offboarding_conta_bloqueada_e_conforme(raiz, runner, csv_autorizados):
    """Contas que já foram neutralizadas (bloqueadas, expiradas, shell nologin, sem keys, fora do wheel) são CONFORME."""
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
        "ex_funcionario:x:1001:1001:Ex Funcionario:/home/ex_funcionario:/sbin/nologin\n"
        "estagiario:x:1002:1002:Estagiario Temp:/home/estagiario:/sbin/nologin\n",
        encoding="utf-8"
    )
    (raiz / "etc" / "group").write_text(
        "root:x:0:\n"
        "wheel:x:10:root,admin_ati\n",
        encoding="utf-8"
    )
    runner.respostas["loginctl list-sessions --no-legend"] = ResultadoComando(0, "")
    runner.respostas["lastlog -b 90"] = ResultadoComando(0, "")

    resultados = avaliar_offboarding(csv_autorizados, raiz=raiz, runner=runner)
    res_map = {r.regra.id: r for r in resultados}

    assert res_map["OFF-001"].status == Status.CONFORME
    assert res_map["OFF-002"].status == Status.CONFORME
    assert res_map["OFF-003"].status == Status.CONFORME
    assert res_map["OFF-004"].status == Status.CONFORME
    assert res_map["OFF-005"].status == Status.CONFORME


def test_aplicar_offboarding_executa_e_segunda_aplicacao_nao_altera_nada(raiz, estado, runner, csv_autorizados):
    """Primeira aplicação corrige; segunda aplicação não altera nada e retorna CONFORME."""
    runner.respostas["loginctl list-sessions --no-legend"] = ResultadoComando(0, "")
    runner.respostas["lastlog -b 90"] = ResultadoComando(0, "")

    # 1ª Aplicação: corrige contas
    res1 = aplicar_offboarding(csv_autorizados, raiz=raiz, estado_dir=estado, runner=runner)
    res1_map = {r.regra.id: r for r in res1}

    assert res1_map["OFF-001"].status == Status.CORRIGIDO
    assert len(res1_map["OFF-001"].mudancas) > 0
    assert res1_map["OFF-002"].status == Status.CORRIGIDO
    assert res1_map["OFF-004"].status == Status.CORRIGIDO

    # Simula estado neutralizado no disco após a execução
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

    # 2ª Aplicação: não altera nada
    res2 = aplicar_offboarding(csv_autorizados, raiz=raiz, estado_dir=estado, runner=runner)
    res2_map = {r.regra.id: r for r in res2}

    assert res2_map["OFF-001"].status == Status.CONFORME
    assert res2_map["OFF-001"].mudancas == []
    assert res2_map["OFF-002"].status == Status.CONFORME
    assert res2_map["OFF-004"].status == Status.CONFORME

    # OFF-006 a 008 continuam como somente auditoria
    for rid in ("OFF-006", "OFF-007", "OFF-008"):
        assert getattr(res2_map[rid].regra, "somente_auditoria", False) is True
