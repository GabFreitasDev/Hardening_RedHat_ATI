"""Testes unitários para a primitiva arquivo_chave_valor."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.arquivo_chave_valor import ArquivoChaveValor, _texto
from hardener.models import Contexto


def test_chave_ausente_reprova_e_e_acrescentada(raiz, runner, estado):
    """Chave ausente é não conforme e deve ser acrescentada ao final do arquivo."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("# Arquivo de configuracao\nunlock_time = 900\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}

    verif1 = prim.verificar(params, ctx)
    assert not verif1.conforme
    assert verif1.atual is None
    assert "ausente" in verif1.detalhe

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1
    assert "deny = 5" in mudancas[0]

    verif2 = prim.verificar(params, ctx)
    assert verif2.conforme
    assert verif2.atual == "5"

    conteudo = arq.read_text(encoding="utf-8")
    assert "unlock_time = 900" in conteudo
    assert "deny = 5" in conteudo


def test_chave_comentada_nao_conta(raiz, runner, estado):
    """Linha comentada (#) é ignorada; chave é considerada ausente e acrescentada."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("# deny = 3\n# Outro comentario\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert verif.atual is None

    prim.corrigir(params, ctx)
    conteudo = arq.read_text(encoding="utf-8")
    assert "# deny = 3" in conteudo
    assert "deny = 5" in conteudo


def test_valor_diferente_e_substituido(raiz, runner, estado):
    """Linha ativa com valor divergente deve ser substituída pela nova linha."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("deny = 3\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert verif.atual == "3"

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1

    conteudo = arq.read_text(encoding="utf-8")
    assert "deny = 5" in conteudo
    assert "deny = 3" not in conteudo


def test_varias_ocorrencias_usam_a_ultima(raiz, runner, estado):
    """Quando há múltiplas ocorrências ativas da mesma chave, vale a última."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("deny = 10\ndeny = 5\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)

    # Com valor "5", a última linha já é 5 -> conforme
    params_ok = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}
    verif1 = prim.verificar(params_ok, ctx)
    assert verif1.conforme
    assert verif1.atual == "5"

    # Com valor "10", a última linha é 5, logo reprova (atual = "5")
    params_diff = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "10"}
    verif2 = prim.verificar(params_diff, ctx)
    assert not verif2.conforme
    assert verif2.atual == "5"

    # Atualizando para "8" substitui a última linha
    params_novo = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "8"}
    prim.corrigir(params_novo, ctx)
    verif3 = prim.verificar(params_novo, ctx)
    assert verif3.conforme
    assert verif3.atual == "8"


def test_separador_customizado(raiz, runner, estado):
    """Suporte a separador customizado, como espaço simples no login.defs."""
    arq = raiz / "etc" / "login.defs"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("PASS_MAX_DAYS 99999\nUMASK 022\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {
        "arquivo": "/etc/login.defs",
        "chave": "UMASK",
        "valor": "027",
        "separador": " ",
    }

    verif1 = prim.verificar(params, ctx)
    assert not verif1.conforme
    assert verif1.atual == "022"

    prim.corrigir(params, ctx)
    conteudo = arq.read_text(encoding="utf-8")
    assert "UMASK 027" in conteudo
    assert "UMASK 022" not in conteudo
    assert "PASS_MAX_DAYS 99999" in conteudo

    verif2 = prim.verificar(params, ctx)
    assert verif2.conforme
    assert verif2.atual == "027"


def test_comentarios_preservados(raiz, runner, estado):
    """Comentários e formatação geral do arquivo são preservados na alteração."""
    arq = raiz / "etc" / "security" / "pwquality.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    original = "# Configuracao de senhas\n# Regra de complexidade\nminlen = 8\n# Fim do arquivo\n"
    arq.write_text(original, encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/pwquality.conf", "chave": "minlen", "valor": "14"}

    prim.corrigir(params, ctx)
    linhas = arq.read_text(encoding="utf-8").splitlines()
    assert linhas[0] == "# Configuracao de senhas"
    assert linhas[1] == "# Regra de complexidade"
    assert linhas[2] == "minlen = 14"
    assert linhas[3] == "# Fim do arquivo"


def test_arquivo_inexistente(raiz, runner, estado):
    """Arquivo inexistente é tratado como não conforme (atual=None), não gera erro."""
    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/novo.conf", "chave": "minlen", "valor": "14"}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert verif.atual is None
    assert "não existe" in verif.detalhe

    # Corrigir cria o arquivo com modo 0644
    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1
    destino = raiz / "etc" / "security" / "novo.conf"
    assert destino.exists()
    assert "minlen = 14" in destino.read_text(encoding="utf-8")
    assert destino.stat().st_mode & 0o777 == 0o644

    verif_pos = prim.verificar(params, ctx)
    assert verif_pos.conforme
    assert verif_pos.atual == "14"


def test_idempotencia(raiz, runner, estado):
    """Segunda execução de corrigir não altera o arquivo."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("deny = 3\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}

    # Primeira execução altera
    mudancas1 = prim.corrigir(params, ctx)
    assert len(mudancas1) == 1

    # Segunda execução não altera
    mudancas2 = prim.corrigir(params, ctx)
    assert mudancas2 == []

    # Permanece conforme
    verif = prim.verificar(params, ctx)
    assert verif.conforme


def test_backup_criado_antes(raiz, runner, estado):
    """Sessão de backup com cópia do arquivo original é gerada antes de alterar."""
    arq = raiz / "etc" / "security" / "faillock.conf"
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text("deny = 3\n", encoding="utf-8")

    prim = ArquivoChaveValor()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {"arquivo": "/etc/security/faillock.conf", "chave": "deny", "valor": "5"}

    prim.corrigir(params, ctx)

    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == "/etc/security/faillock.conf" for e in sessao.entradas)
    assert (sessao.diretorio / "manifest.json").exists()


def test_conversao_tipos_texto():
    """Booleanos viram yes/no somente se booleanos reais; inteiros e strings mantidos."""
    assert _texto(True) == "yes"
    assert _texto(False) == "no"
    assert _texto(5) == "5"
    assert _texto(900) == "900"
    assert _texto("027") == "027"
    assert _texto("yes") == "yes"
    assert _texto("no") == "no"
