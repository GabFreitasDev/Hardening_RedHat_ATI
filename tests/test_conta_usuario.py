"""Testes unitários para a primitiva conta_usuario."""

from __future__ import annotations

from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.conta_usuario import ContaUsuario
from hardener.models import Contexto, ErroPrimitiva
from hardener.runner import ResultadoComando


def test_segundo_uid0_reprova(raiz, runner):
    """Segundo usuário com UID 0 em /etc/passwd deve reprovar a verificação."""
    caminho_passwd = raiz / "etc" / "passwd"
    conteudo_atual = caminho_passwd.read_text(encoding="utf-8")
    # Acrescenta conta adicional com UID 0
    caminho_passwd.write_text(conteudo_atual + "toor:x:0:0:Root Clone:/root:/bin/bash\n", encoding="utf-8")

    prim = ContaUsuario()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"modo": "uid0_unico"}, ctx)

    assert not verif.conforme
    assert "toor" in (verif.atual or "")
    assert "root" in (verif.atual or "")
    assert "toor" in verif.detalhe


def test_so_root_uid0_conforme(raiz, runner):
    """Apenas root com UID 0 (fixture raiz original) deve passar na verificação."""
    prim = ContaUsuario()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"modo": "uid0_unico"}, ctx)

    assert verif.conforme
    assert verif.atual == "root"


def test_uid0_unico_nao_tenta_corrigir(raiz, runner, estado):
    """Modo uid0_unico nunca deve alterar o sistema automaticamente; levanta ErroPrimitiva."""
    caminho_passwd = raiz / "etc" / "passwd"
    conteudo_atual = caminho_passwd.read_text(encoding="utf-8")
    caminho_passwd.write_text(conteudo_atual + "toor:x:0:0:Root Clone:/root:/bin/bash\n", encoding="utf-8")

    prim = ContaUsuario()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)

    # descrever deve explicitar que é apenas auditoria
    assert "apenas auditoria" in prim.descrever({"modo": "uid0_unico"})

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir({"modo": "uid0_unico"}, ctx)

    assert "sem correção automática: revisar manualmente" in str(exc.value)


def test_membro_extra_wheel_reprova(raiz, runner):
    """Membros extras não homologados em wheel devem reprovar (fixture tem ex_funcionario)."""
    prim = ContaUsuario()
    ctx = Contexto(runner=runner, raiz=raiz)
    params = {
        "modo": "membros_grupo",
        "grupo": "wheel",
        "permitidos": ["admin_ati"],
    }

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert "ex_funcionario" in verif.detalhe


def test_correcao_chama_gpasswd_d_para_extras(raiz, runner, estado):
    """Correção deve invocar gpasswd -d para remover membros não autorizados."""
    prim = ContaUsuario()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {
        "modo": "membros_grupo",
        "grupo": "wheel",
        "permitidos": ["admin_ati"],
    }

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1
    assert "ex_funcionario" in mudancas[0]

    # Verifica se chamou gpasswd -d ex_funcionario wheel no runner
    assert runner.chamou("gpasswd", "-d", "ex_funcionario", "wheel")


def test_falha_gpasswd_vira_erro_primitiva(raiz, runner, estado):
    """Se a execução de gpasswd -d retornar erro, deve levantar ErroPrimitiva."""
    prim = ContaUsuario()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {
        "modo": "membros_grupo",
        "grupo": "wheel",
        "permitidos": ["admin_ati"],
    }

    # Simula falha do comando gpasswd
    runner.respostas["gpasswd -d ex_funcionario wheel"] = ResultadoComando(
        rc=1, saida="", erro="gpasswd: user 'ex_funcionario' not found"
    )

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir(params, ctx)

    assert "gpasswd -d" in str(exc.value)


def test_grupo_inexistente_gera_erro_primitiva(raiz, runner):
    """Consulta a grupo ausente em /etc/group levanta ErroPrimitiva."""
    prim = ContaUsuario()
    ctx = Contexto(runner=runner, raiz=raiz)
    params = {
        "modo": "membros_grupo",
        "grupo": "grupo_fantasma",
        "permitidos": ["admin_ati"],
    }

    with pytest.raises(ErroPrimitiva) as exc:
        prim.verificar(params, ctx)

    assert "não encontrado em /etc/group" in str(exc.value)


def test_backup_group_e_gshadow_antes_de_alterar(raiz, runner, estado):
    """Ambos /etc/group e /etc/gshadow devem ser salvos no backup antes da remoção."""
    gshadow = raiz / "etc" / "gshadow"
    gshadow.write_text("wheel:::root,admin_ati,ex_funcionario\n", encoding="utf-8")

    prim = ContaUsuario()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador)
    params = {
        "modo": "membros_grupo",
        "grupo": "wheel",
        "permitidos": ["admin_ati"],
    }

    prim.corrigir(params, ctx)

    sessao = ctx.sessao_criada()
    assert sessao is not None
    salvos = [e["caminho"] for e in sessao.entradas]
    assert "/etc/group" in salvos
    assert "/etc/gshadow" in salvos


def test_validar_parametros_conta_usuario():
    """Validação de parâmetros para os dois modos da primitiva."""
    prim = ContaUsuario()

    # Sem modo
    erros = prim.validar_parametros({})
    assert any("modo" in e for e in erros)

    # Modo inválido
    erros = prim.validar_parametros({"modo": "modo_invalido"})
    assert any("inválido" in e for e in erros)

    # membros_grupo sem grupo ou sem permitidos
    erros = prim.validar_parametros({"modo": "membros_grupo"})
    assert any("grupo" in e for e in erros)
    assert any("permitidos" in e for e in erros)

    # Válidos
    assert prim.validar_parametros({"modo": "uid0_unico"}) == []
    assert prim.validar_parametros({
        "modo": "membros_grupo",
        "grupo": "wheel",
        "permitidos": ["admin_ati"]
    }) == []
