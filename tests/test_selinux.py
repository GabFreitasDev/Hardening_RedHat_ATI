"""Testes unitários para a primitiva selinux."""

from __future__ import annotations

import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.selinux import Selinux, ARQUIVO_SELINUX_CONFIG
from hardener.models import Contexto
from hardener.runner import ResultadoComando


def test_validar_parametros():
    prim = Selinux()
    assert prim.validar_parametros({"modo": "estado", "esperado": "enforcing"}) == []
    assert prim.validar_parametros({"modo": "contexto_caminho", "caminho": "/var/www/uploads", "tipo_esperado": "httpd_sys_rw_content_t"}) == []
    assert len(prim.validar_parametros({"modo": "desconhecido"})) >= 1
    assert len(prim.validar_parametros({"modo": "estado"})) >= 1


def test_selinux_estado_conforme(raiz, runner, estado):
    """Conforme quando getenforce é enforcing e /etc/selinux/config possui SELINUX=enforcing."""
    conf = raiz / ARQUIVO_SELINUX_CONFIG.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("# config\nSELINUX=enforcing\nSELINUXTYPE=targeted\n", encoding="utf-8")

    runner.respostas["getenforce"] = ResultadoComando(0, "Enforcing\n")

    prim = Selinux()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"modo": "estado", "esperado": "enforcing"}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert v.atual == "runtime=enforcing, config=enforcing"


def test_selinux_estado_nao_conforme(raiz, runner, estado):
    """Não conforme quando getenforce está em Permissive ou config divergente."""
    conf = raiz / ARQUIVO_SELINUX_CONFIG.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("SELINUX=permissive\n", encoding="utf-8")

    runner.respostas["getenforce"] = ResultadoComando(0, "Permissive\n")

    prim = Selinux()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"modo": "estado", "esperado": "enforcing"}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "runtime=permissive" in v.atual


def test_selinux_estado_corrigir(raiz, runner, estado):
    """Corrigir atualiza o arquivo com backup e chama setenforce 1."""
    conf = raiz / ARQUIVO_SELINUX_CONFIG.lstrip("/")
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("SELINUX=permissive\n", encoding="utf-8")

    runner.respostas["getenforce"] = ResultadoComando(0, "Permissive\n")
    runner.respostas["setenforce 1"] = ResultadoComando(0, "")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Selinux()
    params = {"modo": "estado", "esperado": "enforcing"}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 2
    assert runner.chamou("setenforce", "1")
    assert "SELINUX=enforcing" in conf.read_text(encoding="utf-8")

    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == ARQUIVO_SELINUX_CONFIG for e in sessao.entradas)


def test_selinux_contexto_caminho(raiz, runner, estado):
    """Verifica e corrige contexto SELinux em diretório via chcon -R -t."""
    alvo = raiz / "var" / "www" / "uploads"
    alvo.mkdir(parents=True, exist_ok=True)

    runner.respostas["stat -c %C /var/www/uploads"] = ResultadoComando(0, "unconfined_u:object_r:default_t:s0\n")
    runner.respostas["chcon -R -t httpd_sys_rw_content_t /var/www/uploads"] = ResultadoComando(0, "")

    prim = Selinux()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"modo": "contexto_caminho", "caminho": "/var/www/uploads", "tipo_esperado": "httpd_sys_rw_content_t"}

    v = prim.verificar(params, ctx)
    assert not v.conforme

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 1
    assert runner.chamou("chcon", "-R", "-t", "httpd_sys_rw_content_t", "/var/www/uploads")
