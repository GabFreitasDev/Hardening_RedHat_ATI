"""Testes unitários para a primitiva suid_sgid e regra PERM-001."""

from __future__ import annotations

import os
from pathlib import Path
import pytest
import yaml

from hardener.checks.suid_sgid import SuidSgid
from hardener.models import Contexto, ErroPrimitiva


def test_suid_fora_da_lista_reprova(raiz, runner):
    """Arquivo regular com bit SUID fora da lista permitida deve reprovar."""
    bin_dir = raiz / "usr" / "local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_suid = bin_dir / "suid_teste"
    bin_suid.write_bytes(b"#!/bin/sh\nexit 0\n")
    os.chmod(str(bin_suid), 0o4755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert not verif.conforme
    assert "/usr/local/bin/suid_teste" in verif.atual
    assert "1 arquivo(s) fora da lista permitida" in verif.detalhe


def test_sgid_fora_da_lista_reprova(raiz, runner):
    """Arquivo regular com bit SGID fora da lista permitida deve reprovar."""
    bin_dir = raiz / "usr" / "local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_sgid = bin_dir / "sgid_teste"
    bin_sgid.write_bytes(b"#!/bin/sh\nexit 0\n")
    os.chmod(str(bin_sgid), 0o2755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert not verif.conforme
    assert "/usr/local/bin/sgid_teste" in verif.atual
    assert "1 arquivo(s) fora da lista permitida" in verif.detalhe


def test_binario_permitido_passa_conforme(raiz, runner):
    """Binário com bit SUID constante da lista permitida deve passar conforme."""
    bin_dir = raiz / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_passwd = bin_dir / "passwd"
    bin_passwd.write_bytes(b"passwd-binary")
    os.chmod(str(bin_passwd), 0o4755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert verif.conforme
    assert verif.atual == "nenhum arquivo SUID/SGID fora da lista"
    assert "todos os arquivos SUID/SGID estão na lista permitida" in verif.detalhe


def test_arquivo_sem_suid_sgid_ignorado(raiz, runner):
    """Arquivos regulares com permissões normais (ex: 0755) não devem reprovar."""
    bin_dir = raiz / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_comum = bin_dir / "comum"
    bin_comum.write_bytes(b"normal")
    os.chmod(str(bin_comum), 0o755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert verif.conforme
    assert verif.atual == "nenhum arquivo SUID/SGID fora da lista"


def test_links_simbolicos_nao_seguidos(raiz, runner):
    """Links simbólicos apontando para binários SUID não devem ser considerados arquivos regulares."""
    bin_dir = raiz / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_real = bin_dir / "passwd"
    bin_real.write_bytes(b"passwd-binary")
    os.chmod(str(bin_real), 0o4755)

    link = bin_dir / "passwd_link"
    link.symlink_to(bin_real)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    # Apenas /usr/bin/passwd está na lista; o link passwd_link não deve aparecer como violação
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert verif.conforme
    assert "/usr/bin/passwd_link" not in verif.atual


def test_diretorios_ignorados_nao_sao_percorridos(raiz, runner):
    """Arquivos dentro de /proc, /sys, /dev, /run não devem ser inspecionados."""
    proc_dir = raiz / "proc" / "1"
    proc_dir.mkdir(parents=True, exist_ok=True)
    bin_proc = proc_dir / "fake_suid"
    bin_proc.write_bytes(b"fake")
    os.chmod(str(bin_proc), 0o4755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert verif.conforme
    assert "/proc/1/fake_suid" not in verif.atual


def test_atual_trunca_em_20_com_total(raiz, runner):
    """Quando houver mais de 20 violações, `atual` lista os 20 primeiros e indica o total."""
    bin_dir = raiz / "usr" / "local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    for i in range(25):
        f = bin_dir / f"bin_{i:02d}"
        f.write_bytes(b"exec")
        os.chmod(str(f), 0o4755)

    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)
    verif = prim.verificar({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert not verif.conforme
    assert "(e mais 5 arquivos, total 25)" in verif.atual
    assert "25 arquivo(s) fora da lista permitida" in verif.detalhe


def test_validar_parametros():
    """Validações de tipos e requisitos de 'permitidos' e 'ignorar'."""
    prim = SuidSgid()

    # Ausente
    assert len(prim.validar_parametros({})) > 0

    # Não lista ou vazia
    assert len(prim.validar_parametros({"permitidos": "string"})) > 0
    assert len(prim.validar_parametros({"permitidos": []})) > 0

    # Item sem / inicial
    assert len(prim.validar_parametros({"permitidos": ["usr/bin/passwd"]})) > 0
    assert len(prim.validar_parametros({"permitidos": [123]})) > 0

    # ignorar inválido
    assert len(prim.validar_parametros({"permitidos": ["/usr/bin/passwd"], "ignorar": "nao_lista"})) > 0
    assert len(prim.validar_parametros({"permitidos": ["/usr/bin/passwd"], "ignorar": ["sem_barra"]})) > 0

    # Válido
    assert prim.validar_parametros({"permitidos": ["/usr/bin/passwd"]}) == []
    assert prim.validar_parametros({"permitidos": ["/usr/bin/passwd"], "ignorar": ["/proc", "/custom"]}) == []


def test_corrigir_levanta_erro_primitiva(raiz, runner):
    """Tentativa de corrigir deve levantar ErroPrimitiva pois a regra é apenas auditoria."""
    prim = SuidSgid()
    ctx = Contexto(runner=runner, raiz=raiz)

    assert "revisar arquivos SUID/SGID" in prim.descrever({})

    with pytest.raises(ErroPrimitiva) as exc:
        prim.corrigir({"permitidos": ["/usr/bin/passwd"]}, ctx)

    assert "sem correção automática: revisar manualmente" in str(exc.value)


def test_regra_perm001_no_yaml():
    """Verifica se a regra PERM-001 em rules/accounts.yaml está ativada com os 32 binários da baseline."""
    raiz_repo = Path(__file__).resolve().parent.parent
    caminho_yaml = raiz_repo / "rules" / "accounts.yaml"
    assert caminho_yaml.exists()

    dados = yaml.safe_load(caminho_yaml.read_text(encoding="utf-8"))
    regras_por_id = {r["id"]: r for r in dados}

    assert "PERM-001" in regras_por_id
    r = regras_por_id["PERM-001"]

    assert r["primitiva"] == "suid_sgid"
    assert r["dor_ati"] == [6]
    assert r["severidade"] == "media"
    assert r["plataforma"] == "rhel9"
    assert r["referencia"].endswith("(A CONFIRMAR o item no benchmark)")

    permitidos = r["parametros"]["permitidos"]
    assert isinstance(permitidos, list)
    assert len(permitidos) == 32
    assert len(set(permitidos)) == 32  # Sem duplicatas
    assert all(p.startswith("/") for p in permitidos)

    # Compara diretamente com o arquivo docs/baseline_suid_sgid_rhel9.txt
    caminho_baseline = raiz_repo / "docs" / "baseline_suid_sgid_rhel9.txt"
    assert caminho_baseline.exists()
    linhas_baseline = [
        l.strip()
        for l in caminho_baseline.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    assert len(linhas_baseline) == 32
    assert permitidos == linhas_baseline
