"""Testes unitários para o motor de execução do Hardener."""

from pathlib import Path
import pytest

from hardener.engine import Motor
from hardener.models import Regra, Status
from hardener.rhel import recarregar_servico, validar_servico
from hardener.runner import ResultadoComando, Runner


class DummyRunner(Runner):
    def __init__(self):
        self.chamadas = []

    def executar(self, comando, timeout=30):
        self.chamadas.append(list(comando))
        return ResultadoComando(0, "")


def test_sudoers_nao_chama_systemctl_reload():
    runner = DummyRunner()
    ok, msg = recarregar_servico(runner, "sudoers")
    assert ok is True
    assert "sem daemon" in msg
    # Confirma que systemctl reload NÃO foi chamado para sudoers
    assert not any("systemctl" in c for c in runner.chamadas)


def test_sshd_chama_systemctl_reload():
    runner = DummyRunner()
    ok, msg = recarregar_servico(runner, "sshd")
    assert ok is True
    assert ["systemctl", "reload", "sshd"] in runner.chamadas


def test_regra_somente_auditoria_nao_tenta_corrigir(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    (raiz / "etc").mkdir()
    (raiz / "etc" / "os-release").write_text('ID="rhel"\nVERSION_ID="9.4"\n', encoding="utf-8")
    estado = tmp_path / "estado"
    estado.mkdir()

    runner = DummyRunner()

    regra_manual = Regra(
        id="ACC-001",
        descricao="UID 0 exclusivo",
        referencia="CIS 5.4.3",
        dor_ati=[6],
        severidade="critica",
        plataforma="rhel9",
        primitiva="sshd_config",  # usa primitiva existente para o teste
        parametros={"chave": "PermitRootLogin", "valor": "no"},
        somente_auditoria=True
    )

    motor = Motor([regra_manual], runner, raiz, estado, "rhel9")
    
    # Em dry-run
    res_dry = motor.aplicar(aplicar=False)
    assert res_dry[0].status == Status.NAO_CONFORME
    assert "Auditoria manual" in res_dry[0].detalhe

    # Em apply
    res_apply = motor.aplicar(aplicar=True)
    assert res_apply[0].status == Status.NAO_CONFORME
    assert "Auditoria manual" in res_apply[0].detalhe
