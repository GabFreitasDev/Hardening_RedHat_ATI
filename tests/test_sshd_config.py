import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.sshd_config import ARQUIVO_GERENCIADO, SshdConfig
from hardener.models import Contexto, ErroPrimitiva, Regra
from hardener.runner import ResultadoComando, Runner

PARAMS = {"chave": "PermitRootLogin", "valor": "no"}


def _regra():
    return Regra("T-1", "d", "r", [6], "alta", "rhel9", "sshd_config", dict(PARAMS), "sshd")


@pytest.fixture
def ctx(raiz, runner, estado):
    c = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    c.regra = _regra()
    return c


def test_verifica_nao_conforme_e_conforme(ctx):
    p = SshdConfig()
    v = p.verificar(PARAMS, ctx)
    assert not v.conforme and v.atual == "yes" and v.esperado == "no"
    p.corrigir(PARAMS, ctx)
    assert p.verificar(PARAMS, ctx).conforme


def test_corrigir_e_idempotente_nao_duplica_linhas(ctx, raiz):
    p = SshdConfig()
    p.corrigir(PARAMS, ctx)
    p.corrigir(PARAMS, ctx)
    texto = (raiz / ARQUIVO_GERENCIADO.lstrip("/")).read_text(encoding="utf-8")
    assert texto.count("PermitRootLogin") == 1
    assert texto.startswith("# Gerenciado")


def test_varias_diretivas_convivem_no_mesmo_arquivo(ctx, raiz):
    p = SshdConfig()
    p.corrigir(PARAMS, ctx)
    p.corrigir({"chave": "PasswordAuthentication", "valor": "no"}, ctx)
    p.corrigir({"chave": "PermitRootLogin", "valor": "prohibit-password"}, ctx)
    texto = (raiz / ARQUIVO_GERENCIADO.lstrip("/")).read_text(encoding="utf-8")
    assert "PasswordAuthentication no" in texto
    assert "PermitRootLogin prohibit-password" in texto
    assert texto.count("PermitRootLogin") == 1


def test_booleano_do_yaml_sem_aspas_e_tratado(ctx):
    p = SshdConfig()
    params = {"chave": "PermitRootLogin", "valor": False}  # `valor: no` sem aspas
    assert p.verificar(params, ctx).esperado == "no"
    assert "no" in p.descrever(params)


def test_parametros_obrigatorios():
    assert SshdConfig().validar_parametros({"chave": "X"})
    assert SshdConfig().validar_parametros(PARAMS) == []


def test_sshd_t_falhando_vira_erro_da_primitiva(ctx):
    class Quebrado(Runner):
        def executar(self, comando, timeout=30):
            return ResultadoComando(255, "", "permission denied")

    ctx.runner = Quebrado()
    with pytest.raises(ErroPrimitiva):
        SshdConfig().verificar(PARAMS, ctx)
