"""Testes unitários para regras de upload e permissões estendidas."""

from __future__ import annotations

import os
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.apache_upload import ApacheUpload, ARQUIVO_CONF_UPLOAD
from hardener.checks.permissao_arquivo import PermissaoArquivo
from hardener.models import Contexto, ErroPrimitiva


def test_upl_001_arquivos_sem_execucao(raiz, runner, estado):
    """Arquivos dentro de /var/www/uploads com bit de execução são detectados e corrigidos."""
    dir_uploads = raiz / "var" / "www" / "uploads"
    dir_uploads.mkdir(parents=True, exist_ok=True)
    script = dir_uploads / "shell.sh"
    script.write_text("#!/bin/bash\necho malicioso\n", encoding="utf-8")
    os.chmod(str(script), 0o755)

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/var/www/uploads", "modo_max": "0640", "recursivo_arquivos": True}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "shell.sh" in v.detalhe

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 1
    assert "0640" in mudancas[0] or "modo alterado" in mudancas[0]

    st = script.stat().st_mode & 0o777
    assert (st & 0o111) == 0  # Sem bit de execução!

    v2 = prim.verificar(params, ctx)
    assert v2.conforme


def test_upl_002_diretorio_upload_criado_se_ausente(raiz, runner, estado):
    """Diretório de uploads é criado e ajustado para modo 0750 quando ausente."""
    dir_uploads = raiz / "var" / "www" / "uploads"
    assert not dir_uploads.exists()

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/var/www/uploads", "modo_max": "0750", "criar_se_ausente": True}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "não existe" in v.detalhe

    mudancas = prim.corrigir(params, ctx)
    assert dir_uploads.exists()
    assert (dir_uploads.stat().st_mode & 0o777) <= 0o750


def test_upl_005_apache_upload_bloqueio_scripts(raiz, runner, estado):
    """Configuração do Apache criada atomicamente proibindo execução de scripts."""
    conf = raiz / ARQUIVO_CONF_UPLOAD.lstrip("/")
    assert not conf.exists()

    prim = ApacheUpload()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"diretorio": "/var/www/uploads"}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "ausente" in v.atual

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) >= 1
    assert conf.exists()

    conteudo = conf.read_text(encoding="utf-8")
    assert "-ExecCGI" in conteudo
    assert "AllowOverride None" in conteudo

    v2 = prim.verificar(params, ctx)
    assert v2.conforme


def test_sys_002_auditoria_world_writable_sem_sticky(raiz, runner, estado):
    """Diretório world-writable sem sticky bit reprova no audit e corrigir levanta ErroPrimitiva."""
    dir_tmp = raiz / "tmp"
    dir_tmp.mkdir(parents=True, exist_ok=True)
    os.chmod(str(dir_tmp), 0o777)  # world-writable sem sticky (0o1000 ausente)

    prim = PermissaoArquivo()
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=GerenciadorBackup(estado, raiz))
    params = {"caminho": "/tmp", "auditar_world_writable": True}

    v = prim.verificar(params, ctx)
    assert not v.conforme
    assert "sem sticky bit" in v.detalhe

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir(params, ctx)
    assert "sem correção automática" in str(exc.value)
