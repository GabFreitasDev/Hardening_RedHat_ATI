"""Testes unitários para a primitiva portas_escuta."""

from __future__ import annotations

import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.portas_escuta import PortasEscuta
from hardener.models import Contexto, ErroPrimitiva
from hardener.runner import ResultadoComando

SAIDA_SS_PADRAO = (
    "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    \n"
    "tcp   LISTEN 0      128        127.0.0.1:631       0.0.0.0:*    \n"
    "tcp   LISTEN 0      128             [::]:22           [::]:*    \n"
    "tcp   LISTEN 0      128            [::1]:25           [::]:*    \n"
)

SAIDA_SS_INSEGURA = (
    "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    \n"
    "tcp   LISTEN 0      128          0.0.0.0:8080      0.0.0.0:*    \n"
    "udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    \n"
)


def test_validar_parametros():
    prim = PortasEscuta()
    assert prim.validar_parametros({"portas_autorizadas": [22]}) == []
    assert len(prim.validar_parametros({"portas_autorizadas": ["22"]})) == 1
    assert len(prim.validar_parametros({})) == 1


def test_portas_escuta_conforme(raiz, runner, estado):
    """Conforme quando apenas porta 22 externa está em escuta e loopback é ignorado."""
    runner.respostas["ss -tulnH"] = ResultadoComando(0, SAIDA_SS_PADRAO)

    prim = PortasEscuta()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"portas_autorizadas": [22], "ignorar_loopback": True}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert "portas em escuta: [22]" in v.atual


def test_portas_escuta_nao_conforme(raiz, runner, estado):
    """Não conforme quando há portas não autorizadas em escuta (ex.: 8080, 5353)."""
    runner.respostas["ss -tulnH"] = ResultadoComando(0, SAIDA_SS_INSEGURA)

    prim = PortasEscuta()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"portas_autorizadas": [22], "ignorar_loopback": True}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "8080" in v.detalhe
    assert "5353" in v.detalhe


def test_portas_escuta_somente_auditoria_erro_ao_corrigir(raiz, runner, estado):
    """Regra somente de auditoria levanta ErroPrimitiva ao chamar corrigir."""
    prim = PortasEscuta()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"portas_autorizadas": [22]}

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir(params, ctx)
    assert "sem correção automática" in str(exc.value)
