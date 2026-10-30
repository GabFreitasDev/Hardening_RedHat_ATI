"""Testes unitários para a primitiva permissao_arquivo."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.permissao_arquivo import PermissaoArquivo
from hardener.models import Contexto, ErroPrimitiva


def test_modo_frouxo_reprova(raiz, runner):
    """Modo com bits além do máximo deve reprovar na verificação."""
    arq = raiz / "etc" / "teste_frouxo.conf"
    arq.write_text("conteudo\n", encoding="utf-8")
    os.chmod(str(arq), 0o644)

    prim = PermissaoArquivo()
    ctx = Contexto(runner=runner, raiz=raiz)
    params = {"caminho": "/etc/teste_frouxo.conf", "modo_max": "0600"}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert "0644" in (verif.atual or "")
    assert "mais permissivo que o máximo 0600" in verif.detalhe


def test_correcao_deixa_conforme(raiz, runner, estado):
    """Corrigir aplica a máscara e deixa o arquivo conforme."""
    arq = raiz / "etc" / "teste_corrigir.conf"
    arq.write_text("conteudo\n", encoding="utf-8")
    os.chmod(str(arq), 0o644)

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/etc/teste_corrigir.conf", "modo_max": "0600"}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1
    assert "modo alterado" in mudancas[0]

    verif = prim.verificar(params, ctx)
    assert verif.conforme
    modo_atual = arq.stat().st_mode & 0o777
    assert modo_atual == 0o600


def test_modo_mais_restrito_que_maximo_e_conforme(raiz, runner):
    """Modos mais restritivos que o máximo são conformes (0400 e 0000 passam com 0600)."""
    arq = raiz / "etc" / "teste_restrito.conf"
    arq.write_text("conteudo\n", encoding="utf-8")
    os.chmod(str(arq), 0o400)

    prim = PermissaoArquivo()
    ctx = Contexto(runner=runner, raiz=raiz)
    params = {"caminho": "/etc/teste_restrito.conf", "modo_max": "0600"}

    verif = prim.verificar(params, ctx)
    assert verif.conforme
    assert "0400" in (verif.atual or "")


def test_modo_nunca_aumenta(raiz, runner, estado):
    """Corrigir nunca adiciona bits nem aumenta permissões (0400 não sobe para 0600)."""
    arq = raiz / "etc" / "teste_nunca_aumenta.conf"
    arq.write_text("conteudo\n", encoding="utf-8")
    os.chmod(str(arq), 0o400)

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/etc/teste_nunca_aumenta.conf", "modo_max": "0600"}

    mudancas = prim.corrigir(params, ctx)
    assert mudancas == []
    modo_atual = arq.stat().st_mode & 0o777
    assert modo_atual == 0o400


def test_arquivo_inexistente_gera_erro_primitiva(raiz, runner, estado):
    """Arquivo inexistente deve levantar ErroPrimitiva tanto em verificar quanto em corrigir."""
    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/etc/nao_existe.conf", "modo_max": "0600"}

    with pytest.raises(ErroPrimitiva) as exc_v:
        prim.verificar(params, ctx)
    assert "não existe" in str(exc_v.value)

    with pytest.raises(ErroPrimitiva) as exc_c:
        prim.corrigir(params, ctx)
    assert "não existe" in str(exc_c.value)


def test_parametros_invalidos():
    """Validação de parâmetros obrigatórios e rejeição de modo_max não-octal."""
    prim = PermissaoArquivo()

    # Sem caminho
    erros1 = prim.validar_parametros({"modo_max": "0600"})
    assert any("caminho" in e for e in erros1)

    # Sem ao menos um entre modo_max, dono, grupo
    erros2 = prim.validar_parametros({"caminho": "/etc/arquivo"})
    assert any("ao menos um" in e for e in erros2)

    # modo_max com dígitos não octais (8 ou 9)
    erros3 = prim.validar_parametros({"caminho": "/etc/arquivo", "modo_max": "0800"})
    assert any("não é um octal válido" in e for e in erros3)

    # modo_max com texto
    erros4 = prim.validar_parametros({"caminho": "/etc/arquivo", "modo_max": "invalido"})
    assert any("não é um octal válido" in e for e in erros4)

    # Válido com modo_max
    assert prim.validar_parametros({"caminho": "/etc/arquivo", "modo_max": "0600"}) == []

    # Válido com modo_max "0000"
    assert prim.validar_parametros({"caminho": "/etc/arquivo", "modo_max": "0000"}) == []

    # Válido com dono ou grupo
    assert prim.validar_parametros({"caminho": "/etc/arquivo", "dono": "root"}) == []


def test_idempotencia(raiz, runner, estado):
    """Segunda execução de corrigir não altera nada e deixa arquivo conforme."""
    arq = raiz / "etc" / "teste_idempotente.conf"
    arq.write_text("conteudo\n", encoding="utf-8")
    os.chmod(str(arq), 0o666)

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/etc/teste_idempotente.conf", "modo_max": "0600"}

    # Primeira correção
    mudancas1 = prim.corrigir(params, ctx)
    assert len(mudancas1) == 1
    assert arq.stat().st_mode & 0o777 == 0o600

    # Segunda correção não altera nada
    mudancas2 = prim.corrigir(params, ctx)
    assert mudancas2 == []

    # Verificação pós-correção é conforme
    verif = prim.verificar(params, ctx)
    assert verif.conforme


def test_backup_criado_antes_de_alterar(raiz, runner, estado):
    """Sessão de backup com cópia do arquivo original é gerada antes de alterar."""
    arq = raiz / "etc" / "teste_backup.conf"
    arq.write_text("conteudo_original\n", encoding="utf-8")
    os.chmod(str(arq), 0o644)

    prim = PermissaoArquivo()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"caminho": "/etc/teste_backup.conf", "modo_max": "0600"}

    prim.corrigir(params, ctx)

    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == "/etc/teste_backup.conf" for e in sessao.entradas)
    assert (sessao.diretorio / "manifest.json").exists()
