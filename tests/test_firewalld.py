"""Testes unitários para a primitiva firewalld."""

from __future__ import annotations

import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.firewalld import Firewalld
from hardener.models import Contexto
from hardener.runner import ResultadoComando


def test_validar_parametros():
    prim = Firewalld()
    assert prim.validar_parametros({"servicos_permitidos": ["ssh"]}) == []
    assert prim.validar_parametros({"servicos_permitidos": ["ssh"], "portas_permitidas": ["80/tcp"]}) == []
    assert len(prim.validar_parametros({"servicos_permitidos": "ssh"})) == 1
    assert len(prim.validar_parametros({"servicos_permitidos": ["ssh"], "portas_permitidas": [80]})) == 1


def test_firewalld_conforme(raiz, runner, estado):
    """Conforme quando firewalld ativo e apenas serviços/portas permitidos estão abertos."""
    runner.respostas["firewall-cmd --state"] = ResultadoComando(0, "running\n")
    runner.respostas["firewall-cmd --list-services"] = ResultadoComando(0, "ssh\n")
    runner.respostas["firewall-cmd --list-ports"] = ResultadoComando(0, "\n")

    prim = Firewalld()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_permitidos": ["ssh"], "portas_permitidas": []}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert "serviços: [ssh]" in v.atual


def test_firewalld_inativo(raiz, runner, estado):
    """Não conforme se firewalld não estiver em execução."""
    runner.respostas["firewall-cmd --state"] = ResultadoComando(252, "not running\n")

    prim = Firewalld()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_permitidos": ["ssh"]}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "não está em execução" in v.detalhe


def test_firewalld_servicos_e_portas_excedentes(raiz, runner, estado):
    """Não conforme quando há serviços ou portas não autorizadas ativas."""
    runner.respostas["firewall-cmd --state"] = ResultadoComando(0, "running\n")
    runner.respostas["firewall-cmd --list-services"] = ResultadoComando(0, "cockpit dhcpv6-client ssh\n")
    runner.respostas["firewall-cmd --list-ports"] = ResultadoComando(0, "8080/tcp 9000/udp\n")

    prim = Firewalld()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_permitidos": ["ssh"], "portas_permitidas": []}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "cockpit" in v.detalhe
    assert "8080/tcp" in v.detalhe


def test_firewalld_corrigir_remove_excedentes_e_adiciona_faltantes(raiz, runner, estado):
    """Correção remove serviços/portas extras e garante serviços permitidos com reload."""
    runner.respostas["firewall-cmd --state"] = ResultadoComando(0, "running\n")
    runner.respostas["firewall-cmd --list-services"] = ResultadoComando(0, "cockpit\n")
    runner.respostas["firewall-cmd --list-ports"] = ResultadoComando(0, "8080/tcp\n")

    prim = Firewalld()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"servicos_permitidos": ["ssh"], "portas_permitidas": []}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 3
    assert runner.chamou("firewall-cmd", "--remove-service=cockpit")
    assert runner.chamou("firewall-cmd", "--permanent", "--remove-service=cockpit")
    assert runner.chamou("firewall-cmd", "--remove-port=8080/tcp")
    assert runner.chamou("firewall-cmd", "--permanent", "--remove-port=8080/tcp")
    assert runner.chamou("firewall-cmd", "--add-service=ssh")
    assert runner.chamou("firewall-cmd", "--permanent", "--add-service=ssh")
    assert runner.chamou("firewall-cmd", "--reload")
