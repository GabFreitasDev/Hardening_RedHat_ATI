"""Testes unitários para a primitiva sysctl."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.sysctl import Sysctl, ARQUIVO_GERENCIADO
from hardener.models import Contexto, ErroPrimitiva
from hardener.runner import ResultadoComando


def test_validar_parametros():
    prim = Sysctl()
    assert prim.validar_parametros({"chave": "net.ipv4.ip_forward", "valor": "0"}) == []
    assert len(prim.validar_parametros({"chave": "", "valor": "0"})) == 1
    assert len(prim.validar_parametros({"chave": "net.ipv4.ip_forward"})) == 1


def test_sysctl_conforme(raiz, runner, estado):
    """Conforme quando runtime e config correspondem ao valor esperado."""
    conf = raiz / ARQUIVO_GERENCIADO.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("# header\nnet.ipv4.ip_forward = 0\n", encoding="utf-8")

    runner.respostas["sysctl -n net.ipv4.ip_forward"] = ResultadoComando(0, "0\n")

    prim = Sysctl()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"chave": "net.ipv4.ip_forward", "valor": "0"}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert v.atual == "runtime=0, config=0"
    assert v.esperado == "0"


def test_sysctl_nao_conforme_runtime(raiz, runner, estado):
    """Não conforme quando o kernel está com valor divergente."""
    conf = raiz / ARQUIVO_GERENCIADO.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("net.ipv4.ip_forward = 0\n", encoding="utf-8")

    runner.respostas["sysctl -n net.ipv4.ip_forward"] = ResultadoComando(0, "1\n")

    prim = Sysctl()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"chave": "net.ipv4.ip_forward", "valor": "0"}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert v.atual == "runtime=1, config=0"


def test_sysctl_nao_conforme_sem_config(raiz, runner, estado):
    """Não conforme quando o arquivo de persistência não existe ou não tem a chave."""
    runner.respostas["sysctl -n net.ipv4.ip_forward"] = ResultadoComando(0, "0\n")

    prim = Sysctl()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"chave": "net.ipv4.ip_forward", "valor": "0"}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert v.atual == "runtime=0, config=ausente"


def test_sysctl_corrigir_atomica_e_backup(raiz, runner, estado):
    """Correção atualiza o arquivo com backup e aplica no runtime."""
    conf = raiz / ARQUIVO_GERENCIADO.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("kernel.randomize_va_space = 2\n", encoding="utf-8")

    runner.respostas["sysctl -n net.ipv4.ip_forward"] = ResultadoComando(0, "1\n")
    runner.respostas["sysctl -w net.ipv4.ip_forward=0"] = ResultadoComando(0, "net.ipv4.ip_forward = 0\n")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Sysctl()
    params = {"chave": "net.ipv4.ip_forward", "valor": "0"}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 1
    assert any("net.ipv4.ip_forward = 0" in m for m in mudancas)
    assert runner.chamou("sysctl", "-w", "net.ipv4.ip_forward=0")

    conteudo = conf.read_text(encoding="utf-8")
    assert "kernel.randomize_va_space = 2" in conteudo
    assert "net.ipv4.ip_forward = 0" in conteudo

    # Verifica se o arquivo foi salvo no backup
    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == ARQUIVO_GERENCIADO for e in sessao.entradas)


def test_sysctl_idempotencia(raiz, runner, estado):
    """Corrigir duas vezes preserva o mesmo conteúdo sem duplicar linhas."""
    runner.respostas["sysctl -n net.ipv4.ip_forward"] = ResultadoComando(0, "1\n")
    runner.respostas["sysctl -w net.ipv4.ip_forward=0"] = ResultadoComando(0, "net.ipv4.ip_forward = 0\n")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Sysctl()
    params = {"chave": "net.ipv4.ip_forward", "valor": "0"}

    prim.corrigir(params, ctx)
    conf = raiz / ARQUIVO_GERENCIADO.lstrip("/")
    linhas1 = [l for l in conf.read_text(encoding="utf-8").splitlines() if "net.ipv4.ip_forward" in l]
    assert len(linhas1) == 1

    prim.corrigir(params, ctx)
    linhas2 = [l for l in conf.read_text(encoding="utf-8").splitlines() if "net.ipv4.ip_forward" in l]
    assert len(linhas2) == 1


def test_sysctl_falha_runner(raiz, runner, estado):
    """Falha em sysctl -n ou sysctl -w levanta ErroPrimitiva."""
    runner.respostas["sysctl -n chave.inexistente"] = ResultadoComando(1, "", "cannot stat /proc/sys/chave/inexistente")

    prim = Sysctl()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"chave": "chave.inexistente", "valor": "0"}

    with pytest.raises(ErroPrimitiva):
        prim.verificar(params, ctx)

    runner.respostas["sysctl -w chave.inexistente=0"] = ResultadoComando(1, "", "permission denied")
    with pytest.raises(ErroPrimitiva):
        prim.corrigir(params, ctx)
