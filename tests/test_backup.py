"""Testes unitários para o gerenciador de backup e sessões."""

from pathlib import Path
import json
import pytest

from hardener.backup import GerenciadorBackup


def test_gerenciador_cria_sessao_e_grava_manifest(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    estado = tmp_path / "estado"
    estado.mkdir()

    arq = raiz / "etc" / "ssh" / "sshd_config"
    arq.parent.mkdir(parents=True)
    arq.write_text("PermitRootLogin yes\n", encoding="utf-8")

    gerenciador = GerenciadorBackup(estado, raiz)
    sessao = gerenciador.nova_sessao()
    sessao.salvar_arquivo("SSH-001", "/etc/ssh/sshd_config", arq, "sshd")

    assert (sessao.diretorio / "manifest.json").exists()
    manifest = json.loads((sessao.diretorio / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["entradas"]) == 1
    assert manifest["entradas"][0]["caminho"] == "/etc/ssh/sshd_config"
    assert manifest["entradas"][0]["existia"] is True


def test_sessao_restaura_conteudo_original(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    estado = tmp_path / "estado"
    estado.mkdir()

    arq = raiz / "etc" / "meu_arquivo.conf"
    arq.parent.mkdir(parents=True)
    conteudo_original = "valor_inicial = 1\n"
    arq.write_text(conteudo_original, encoding="utf-8")

    gerenciador = GerenciadorBackup(estado, raiz)
    sessao = gerenciador.nova_sessao()
    sessao.salvar_arquivo("REG-1", "/etc/meu_arquivo.conf", arq)

    # Simula alteração do arquivo
    arq.write_text("valor_alterado = 999\n", encoding="utf-8")
    assert arq.read_text(encoding="utf-8") != conteudo_original

    # Executa rollback da sessão
    acoes = sessao.restaurar()
    assert any("restaurado" in a for a in acoes)
    assert arq.read_text(encoding="utf-8") == conteudo_original
    assert sessao.revertida is True


def test_sessao_remove_arquivo_criado_que_nao_existia(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    estado = tmp_path / "estado"
    estado.mkdir()

    gerenciador = GerenciadorBackup(estado, raiz)
    sessao = gerenciador.nova_sessao()

    # Arquivo não existia antes
    dropin = raiz / "etc" / "novo_dropin.conf"
    dropin.parent.mkdir(parents=True)
    sessao.salvar_arquivo("REG-2", "/etc/novo_dropin.conf", dropin)

    # Cria o arquivo
    dropin.write_text("novo conteudo\n", encoding="utf-8")
    assert dropin.exists()

    # Rollback deve remover o arquivo
    acoes = sessao.restaurar()
    assert any("removido" in a for a in acoes)
    assert not dropin.exists()
