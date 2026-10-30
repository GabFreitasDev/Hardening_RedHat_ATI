"""Testes unitários para a primitiva montagem."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.montagem import Montagem, ARQUIVO_FSTAB
from hardener.models import Contexto, ErroPrimitiva
from hardener.runner import ResultadoComando


def test_validar_parametros():
    prim = Montagem()
    assert prim.validar_parametros({"ponto": "/tmp", "opcoes": ["noexec", "nosuid", "nodev"]}) == []
    assert len(prim.validar_parametros({"ponto": "", "opcoes": ["noexec"]})) == 1
    assert len(prim.validar_parametros({"ponto": "/tmp", "opcoes": []})) == 1
    assert len(prim.validar_parametros({"ponto": "tmp", "opcoes": ["noexec"]})) == 1


def test_montagem_conforme(raiz, runner, estado):
    """Conforme quando fstab e runtime contêm todas as opções exigidas."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0\n", encoding="utf-8")

    runner.respostas["findmnt -n -o OPTIONS /tmp"] = ResultadoComando(0, "rw,nosuid,nodev,noexec,relatime\n")

    prim = Montagem()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"ponto": "/tmp", "opcoes": ["noexec", "nosuid", "nodev"]}

    v = prim.verificar(params, ctx)
    assert v.conforme
    assert "defaults,nodev,nosuid,noexec" in v.atual


def test_montagem_nao_conforme_fstab_sem_opcao(raiz, runner, estado):
    """Não conforme quando fstab não possui uma das opções exigidas."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("tmpfs /tmp tmpfs defaults,nodev 0 0\n", encoding="utf-8")

    runner.respostas["findmnt -n -o OPTIONS /tmp"] = ResultadoComando(0, "rw,nodev\n")

    prim = Montagem()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"ponto": "/tmp", "opcoes": ["noexec", "nosuid", "nodev"]}

    v = prim.verificar(params, ctx)
    assert not v.conforme


def test_montagem_nao_conforme_ponto_ausente(raiz, runner, estado):
    """Não conforme quando ponto de montagem não está presente em /etc/fstab."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("/dev/sda1 / ext4 defaults 1 1\n", encoding="utf-8")

    runner.respostas["findmnt -n -o OPTIONS /dev/shm"] = ResultadoComando(1, "")

    prim = Montagem()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"ponto": "/dev/shm", "opcoes": ["noexec", "nosuid", "nodev"]}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "ausente" in v.atual


def test_montagem_corrigir_acrescenta_opcoes_existente(raiz, runner, estado):
    """Acrescenta opções faltantes na linha existente de /etc/fstab sem duplicar."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("/dev/sda1\t/tmp\text4\tdefaults,nodev\t0\t0\n", encoding="utf-8")

    runner.respostas["findmnt -n /tmp"] = ResultadoComando(0, "/tmp")
    runner.respostas["mount -o remount /tmp"] = ResultadoComando(0, "")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Montagem()
    params = {"ponto": "/tmp", "opcoes": ["noexec", "nosuid", "nodev"]}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 1
    assert runner.chamou("mount", "-o", "remount", "/tmp")

    conteudo = fstab.read_text(encoding="utf-8")
    assert "nodev,noexec,nosuid" in conteudo or ("nodev" in conteudo and "noexec" in conteudo and "nosuid" in conteudo)

    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == ARQUIVO_FSTAB for e in sessao.entradas)


def test_montagem_corrigir_cria_tmpfs_quando_ausente(raiz, runner, estado):
    """Cria entrada tmpfs para /tmp quando ausente em /etc/fstab."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("# header fstab\n/dev/sda1 / ext4 defaults 1 1\n", encoding="utf-8")

    runner.respostas["findmnt -n /tmp"] = ResultadoComando(1, "")
    runner.respostas["mount /tmp"] = ResultadoComando(0, "")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Montagem()
    params = {"ponto": "/tmp", "opcoes": ["noexec", "nosuid", "nodev"]}

    mudancas = prim.corrigir(params, ctx)
    assert any("adicionada entrada para /tmp" in m for m in mudancas)
    assert runner.chamou("mount", "/tmp")

    conteudo = fstab.read_text(encoding="utf-8")
    assert "tmpfs\t/tmp\ttmpfs" in conteudo
    assert "noexec" in conteudo and "nosuid" in conteudo and "nodev" in conteudo


def test_montagem_corrigir_cria_bind_mount_para_diretorio(raiz, runner, estado):
    """Cria entrada bind mount para diretório como /var/www/uploads e cria pasta."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("# fstab\n", encoding="utf-8")

    uploads_dir = raiz / "var" / "www" / "uploads"
    assert not uploads_dir.exists()

    runner.respostas["findmnt -n /var/www/uploads"] = ResultadoComando(1, "")
    runner.respostas["mount /var/www/uploads"] = ResultadoComando(0, "")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Montagem()
    params = {"ponto": "/var/www/uploads", "opcoes": ["noexec", "nosuid", "nodev"]}

    prim.corrigir(params, ctx)
    assert uploads_dir.exists()

    conteudo = fstab.read_text(encoding="utf-8")
    assert "/var/www/uploads\t/var/www/uploads\tnone" in conteudo
    assert "bind" in conteudo


def test_montagem_idempotencia(raiz, runner, estado):
    """Execuções repetidas não alteram nem duplicam opções no fstab."""
    fstab = raiz / ARQUIVO_FSTAB.lstrip("/")
    fstab.parent.mkdir(parents=True, exist_ok=True)
    fstab.write_text("tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0\n", encoding="utf-8")

    runner.respostas["findmnt -n /dev/shm"] = ResultadoComando(0, "/dev/shm")
    runner.respostas["mount -o remount /dev/shm"] = ResultadoComando(0, "")

    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    prim = Montagem()
    params = {"ponto": "/dev/shm", "opcoes": ["noexec", "nosuid", "nodev"]}

    antes = fstab.read_text(encoding="utf-8")
    prim.corrigir(params, ctx)
    depois = fstab.read_text(encoding="utf-8")
    assert antes == depois
