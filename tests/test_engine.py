import json

import pytest

from hardener.backup import ErroBackup
from hardener.checks.sshd_config import ARQUIVO_GERENCIADO
from hardener.engine import Motor
from hardener.models import Regra, Status
from hardener.report import codigo_saida


def _regra(rid="SSH-001", chave="PermitRootLogin", valor="no"):
    return Regra(rid, "desc", "ref", [6], "alta", "rhel9", "sshd_config",
                 {"chave": chave, "valor": valor}, "sshd")


def _motor(regras, runner, raiz, estado, plataforma="rhel9"):
    return Motor(regras, runner, raiz, estado, plataforma)


def _dropin(raiz):
    return raiz / ARQUIVO_GERENCIADO.lstrip("/")


def test_audit_reporta_nao_conforme_sem_alterar(runner, raiz, estado):
    res = _motor([_regra()], runner, raiz, estado).auditar()
    assert [r.status for r in res] == [Status.NAO_CONFORME]
    assert codigo_saida(res) == 1
    assert not _dropin(raiz).exists()
    assert not estado.exists()


def test_dry_run_nao_altera_nada(runner, raiz, estado):
    res = _motor([_regra()], runner, raiz, estado).aplicar(aplicar=False)
    assert res[0].status == Status.SERIA_CORRIGIDO
    assert "PermitRootLogin no" in res[0].detalhe
    assert not _dropin(raiz).exists()
    assert not estado.exists()  # nem sessão de backup
    assert not runner.chamou("systemctl", "reload", "sshd")


def test_apply_corrige_valida_e_recarrega(runner, raiz, estado):
    res = _motor([_regra()], runner, raiz, estado).aplicar(aplicar=True)
    assert res[0].status == Status.CORRIGIDO
    assert "PermitRootLogin no" in _dropin(raiz).read_text(encoding="utf-8")
    ordem = [c for c in runner.chamadas if c in (["sshd", "-t"], ["systemctl", "reload", "sshd"])]
    assert ordem == [["sshd", "-t"], ["systemctl", "reload", "sshd"]]  # valida antes de recarregar
    assert len(list((estado / "backups").iterdir())) == 1


def test_segundo_apply_nao_altera_nada(runner, raiz, estado):
    m = _motor([_regra()], runner, raiz, estado)
    m.aplicar(aplicar=True)
    conteudo = _dropin(raiz).read_text(encoding="utf-8")
    recargas = runner.chamadas.count(["systemctl", "reload", "sshd"])

    res = m.aplicar(aplicar=True)
    assert [r.status for r in res] == [Status.CONFORME]
    assert _dropin(raiz).read_text(encoding="utf-8") == conteudo
    assert runner.chamadas.count(["systemctl", "reload", "sshd"]) == recargas
    assert len(list((estado / "backups").iterdir())) == 1  # nenhuma sessão nova


def test_rollback_remove_arquivo_que_nao_existia(runner, raiz, estado):
    m = _motor([_regra()], runner, raiz, estado)
    m.aplicar(aplicar=True)
    acoes = m.reverter()
    assert not _dropin(raiz).exists()
    assert any("removido" in a for a in acoes)
    assert _motor([_regra()], runner, raiz, estado).auditar()[0].status == Status.NAO_CONFORME


def test_rollback_restaura_conteudo_original(runner, raiz, estado):
    original = "# meu arquivo\nPasswordAuthentication yes\n"
    d = _dropin(raiz)
    d.parent.mkdir(parents=True)
    d.write_text(original, encoding="utf-8")
    m = _motor([_regra()], runner, raiz, estado)
    m.aplicar(aplicar=True)
    assert d.read_text(encoding="utf-8") != original
    m.reverter()
    assert d.read_text(encoding="utf-8") == original


def test_rollback_duas_vezes_usa_sessoes_diferentes(runner, raiz, estado):
    m = _motor([_regra()], runner, raiz, estado)
    m.aplicar(aplicar=True)
    m.reverter()
    with pytest.raises(ErroBackup):  # a única sessão já foi revertida
        m.reverter()


def test_varias_regras_no_mesmo_arquivo_uma_sessao_uma_recarga(runner, raiz, estado):
    regras = [_regra("SSH-001"), _regra("SSH-002", "PasswordAuthentication", "no")]
    res = _motor(regras, runner, raiz, estado).aplicar(aplicar=True)
    assert [r.status for r in res] == [Status.CORRIGIDO, Status.CORRIGIDO]
    assert runner.chamadas.count(["systemctl", "reload", "sshd"]) == 1
    manifest = json.loads(next((estado / "backups").iterdir()).joinpath("manifest.json").read_text())
    assert len(manifest["entradas"]) == 1  # arquivo salvo uma vez só (estado ORIGINAL)


def test_validacao_falha_reverte_e_nao_recarrega(runner, raiz, estado):
    runner.sshd_t_rc = 1
    res = _motor([_regra()], runner, raiz, estado).aplicar(aplicar=True)
    assert res[0].status == Status.FALHOU
    assert "revertidas" in res[0].detalhe
    assert not _dropin(raiz).exists()
    assert not runner.chamou("systemctl", "reload", "sshd")
    assert codigo_saida(res) == 2


def test_recarga_falha_reverte(runner, raiz, estado):
    runner.reload_rc = 1
    res = _motor([_regra()], runner, raiz, estado).aplicar(aplicar=True)
    assert res[0].status == Status.FALHOU
    assert not _dropin(raiz).exists()


def test_regra_de_outra_plataforma_e_pulada(runner, raiz, estado):
    res = _motor([_regra()], runner, raiz, estado, plataforma="ubuntu22").auditar()
    assert res[0].status == Status.PULADO
    assert not runner.chamou("sshd", "-T")


def test_primitiva_desconhecida_vira_erro_sem_derrubar_o_resto(runner, raiz, estado):
    ruim = Regra("X-1", "d", "r", [6], "alta", "rhel9", "nao_existe", {}, None)
    res = _motor([ruim, _regra()], runner, raiz, estado).auditar()
    assert [r.status for r in res] == [Status.ERRO, Status.NAO_CONFORME]
