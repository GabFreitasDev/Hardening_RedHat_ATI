"""Testes unitários para a primitiva servico."""

from __future__ import annotations

import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.servico import Servico
from hardener.models import Contexto
from hardener.runner import ResultadoComando


def test_validar_parametros():
    prim = Servico()
    assert prim.validar_parametros({"servicos_proibidos": ["telnet.socket", "rsh.socket"]}) == []
    assert len(prim.validar_parametros({"servicos_proibidos": []})) == 1
    assert len(prim.validar_parametros({"servicos_proibidos": "telnet.socket"})) == 1


def test_servico_conforme(raiz, runner, estado):
    """Conforme quando nenhum serviço proibido está ativo nem habilitado."""
    runner.respostas["systemctl is-active telnet.socket"] = ResultadoComando(3, "inactive\n")
    runner.respostas["systemctl is-enabled telnet.socket"] = ResultadoComando(1, "disabled\n")

    prim = Servico()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_proibidos": ["telnet.socket"]}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert "nenhum serviço proibido ativo" in v.detalhe


def test_servico_nao_conforme(raiz, runner, estado):
    """Não conforme quando um serviço proibido está ativo ou habilitado."""
    runner.respostas["systemctl is-active telnet.socket"] = ResultadoComando(0, "active\n")
    runner.respostas["systemctl is-enabled telnet.socket"] = ResultadoComando(0, "enabled\n")

    prim = Servico()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_proibidos": ["telnet.socket"]}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "telnet.socket" in v.detalhe


def test_servico_corrigir_desabilita_com_now(raiz, runner, estado):
    """Corrigir chama systemctl disable --now para cada serviço ativo/habilitado."""
    runner.respostas["systemctl is-active telnet.socket"] = ResultadoComando(0, "active\n")
    runner.respostas["systemctl is-enabled telnet.socket"] = ResultadoComando(0, "enabled\n")
    runner.respostas["systemctl disable --now telnet.socket"] = ResultadoComando(0, "")

    prim = Servico()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_proibidos": ["telnet.socket"]}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1
    assert runner.chamou("systemctl", "disable", "--now", "telnet.socket")
