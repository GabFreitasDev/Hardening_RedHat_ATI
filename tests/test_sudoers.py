"""Testes unitários para a primitiva sudoers."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from hardener.backup import GerenciadorBackup
from hardener.checks.sudoers import Sudoers
from hardener.models import Contexto, ErroPrimitiva, Regra
from hardener.runner import ResultadoComando

CONTEUDO_DEMO_SUJAR = (
    "%wheel ALL=(ALL) NOPASSWD: ALL\n"
    "estagiario ALL=(ALL) NOPASSWD: ALL\n"
)

REGRA_SUDO = Regra(
    id="SUDO-001",
    descricao="teste sudoers",
    referencia="CIS",
    dor_ati=[6],
    severidade="alta",
    plataforma="rhel9",
    primitiva="sudoers",
    recarregar="sudoers",
)



def test_fixture_demo_sujar_servidor_violacoes(raiz, runner, estado):
    """Conteúdo de demo/sujar_servidor.sh em 99-inseguro-ati é detectado e corrigido."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "99-inseguro-ati"
    arq.write_text(CONTEUDO_DEMO_SUJAR, encoding="utf-8")
    os.chmod(str(arq), 0o440)

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)

    # SUDO-001 (proibir nopasswd) deve reprovar ambas as linhas
    params_nopasswd = {"proibir": "nopasswd"}
    verif_nopasswd = prim.verificar(params_nopasswd, ctx)
    assert not verif_nopasswd.conforme
    assert "%wheel" in verif_nopasswd.atual
    assert "estagiario" in verif_nopasswd.atual
    assert "2 regra(s)" in verif_nopasswd.detalhe

    # SUDO-002 (proibir all com permitidos ["root", "%wheel"]) reprova estagiario mas não %wheel
    params_all = {"proibir": "all", "permitidos": ["root", "%wheel"]}
    verif_all = prim.verificar(params_all, ctx)
    assert not verif_all.conforme
    assert "estagiario" in verif_all.atual
    assert "%wheel" not in verif_all.atual


def test_arquivo_ignorado_com_ponto_ou_til(raiz, runner, estado):
    """Arquivos com ponto ou terminando com til são ignorados pelo sudo."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    (sudoers_d / "regras.conf").write_text("estagiario ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    (sudoers_d / "regras~").write_text("estagiario ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

    prim = Sudoers()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"proibir": "nopasswd"}, ctx)
    assert verif.conforme
    assert verif.atual == "nenhuma regra proibida encontrada"


def test_wheel_all_nao_reprova_mas_estagiario_reprova(raiz, runner):
    """%wheel ALL=(ALL) ALL é padrão aceito; estagiario ALL=(ALL) ALL é reprovado."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "regras"
    arq.write_text(
        "%wheel ALL=(ALL) ALL\n"
        "estagiario ALL=(ALL) ALL\n",
        encoding="utf-8",
    )

    prim = Sudoers()
    ctx = Contexto(runner=runner, raiz=raiz)
    params = {"proibir": "all", "permitidos": ["root", "%wheel"]}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme
    assert "estagiario" in verif.atual
    assert "%wheel" not in verif.atual


def test_linhas_com_continuacao_barra_invertida(raiz, runner, estado):
    """Linhas unificadas com barra invertida são detectadas e comentadas."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "continuacao"
    arq.write_text(
        "estagiario ALL=(ALL) \\\n"
        "  NOPASSWD: ALL\n",
        encoding="utf-8",
    )

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)
    params = {"proibir": "nopasswd"}

    verif = prim.verificar(params, ctx)
    assert not verif.conforme

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 2

    linhas = arq.read_text(encoding="utf-8").splitlines()
    assert linhas[0].startswith("# hardener: desativado: estagiario ALL=(ALL) \\")
    assert linhas[1].startswith("# hardener: desativado:   NOPASSWD: ALL")

    verif_pos = prim.verificar(params, ctx)
    assert verif_pos.conforme


def test_correcao_comenta_linha_preserva_resto_e_modo_0440(raiz, runner, estado):
    """A correção comenta a linha ofensiva, preserva comentários/Defaults e aplica 0440."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "mix"
    arq.write_text(
        "# Cabecalho importante\n"
        "Defaults env_reset\n"
        "estagiario ALL=(ALL) NOPASSWD: ALL\n"
        "# Fim do arquivo\n",
        encoding="utf-8",
    )

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)
    params = {"proibir": "nopasswd"}

    mudancas = prim.corrigir(params, ctx)
    assert len(mudancas) == 1

    linhas = arq.read_text(encoding="utf-8").splitlines()
    assert linhas[0] == "# Cabecalho importante"
    assert linhas[1] == "Defaults env_reset"
    assert linhas[2] == "# hardener: desativado: estagiario ALL=(ALL) NOPASSWD: ALL"
    assert linhas[3] == "# Fim do arquivo"

    modo = arq.stat().st_mode & 0o777
    assert modo == 0o440


def test_fake_runner_recebe_visudo_cf(raiz, runner, estado):
    """Garante que a validação chama visudo -cf no arquivo temporário."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "checa_visudo"
    arq.write_text("estagiario ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)

    prim.corrigir({"proibir": "nopasswd"}, ctx)

    chamadas_visudo = [cmd for cmd in runner.chamadas if cmd[:2] == ["visudo", "-cf"]]
    assert len(chamadas_visudo) == 1
    assert chamadas_visudo[0][2].endswith(".tmp")


def test_visudo_falha_mantem_original_remove_tmp_e_lanca_erro(raiz, runner, estado):
    """Se visudo falhar, o original não é modificado, o tmp é removido e ErroPrimitiva é lançado."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "falha_visudo"
    conteudo_original = "estagiario ALL=(ALL) NOPASSWD: ALL\n"
    arq.write_text(conteudo_original, encoding="utf-8")

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)

    tmp_arq = arq.with_name(arq.name + ".tmp")
    runner.respostas["visudo -cf %s" % tmp_arq] = ResultadoComando(
        rc=1, saida="", erro=">>> /etc/sudoers.d/falha_visudo.tmp: syntax error <<<"
    )

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir({"proibir": "nopasswd"}, ctx)

    assert "validação visudo falhou" in str(exc.value)
    # Original preservado
    assert arq.read_text(encoding="utf-8") == conteudo_original
    # Temporário removido
    assert not tmp_arq.exists()


def test_idempotencia_sem_alteracao_nem_backup(raiz, runner, estado):
    """Segunda execução não altera nada e não cria backup."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "limpo"
    arq.write_text("%wheel ALL=(ALL) ALL\n", encoding="utf-8")

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)

    # Arquivo já conforme
    mudancas = prim.corrigir({"proibir": "all", "permitidos": ["root", "%wheel"]}, ctx)
    assert mudancas == []
    assert ctx.sessao_criada() is None


def test_backup_criado_antes_de_alterar(raiz, runner, estado):
    """Backup do arquivo original é gravado na sessão antes da modificação."""
    sudoers_d = raiz / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True, exist_ok=True)
    arq = sudoers_d / "com_backup"
    arq.write_text("estagiario ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

    prim = Sudoers()
    gerenciador = GerenciadorBackup(estado, raiz)
    ctx = Contexto(runner=runner, raiz=raiz, gerenciador=gerenciador, regra=REGRA_SUDO)

    prim.corrigir({"proibir": "nopasswd"}, ctx)

    sessao = ctx.sessao_criada()
    assert sessao is not None
    assert any(e["caminho"] == "/etc/sudoers.d/com_backup" for e in sessao.entradas)
    assert (sessao.diretorio / "manifest.json").exists()


def test_validar_parametros():
    """Validação estrita dos parâmetros da primitiva."""
    prim = Sudoers()
    assert any("proibir" in e for e in prim.validar_parametros({}))
    assert any("proibir" in e for e in prim.validar_parametros({"proibir": "invalido"}))
    assert any("permitidos" in e for e in prim.validar_parametros({"proibir": "all", "permitidos": "nao_lista"}))
    assert prim.validar_parametros({"proibir": "nopasswd"}) == []
    assert prim.validar_parametros({"proibir": "all", "permitidos": ["root", "%wheel"]}) == []
