"""Testes unitários para a CLI e argumentos do Hardener."""

from pathlib import Path
import pytest

from hardener.cli import construir_parser, trava_vm


def test_parser_comandos_obrigatorios():
    p = construir_parser()
    args_audit = p.parse_args(["audit"])
    assert args_audit.comando == "audit"

    args_enforce = p.parse_args(["enforce"])
    assert args_enforce.comando == "enforce"
    assert not args_enforce.apply

    args_apply = p.parse_args(["enforce", "--apply"])
    assert args_apply.apply

    args_rollback = p.parse_args(["rollback", "--sessao", "20261025"])
    assert args_rollback.comando == "rollback"
    assert args_rollback.sessao == "20261025"


def test_parser_offboarding_args(tmp_path):
    p = construir_parser()
    csv_file = tmp_path / "lista.csv"
    args = p.parse_args(["offboarding", "--autorizados", str(csv_file)])
    assert args.comando == "offboarding"
    assert args.autorizados == csv_file
    assert not args.apply

    args_apply = p.parse_args(["offboarding", "--autorizados", str(csv_file), "--apply"])
    assert args_apply.apply


def test_trava_vm_recusa_sem_root(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    (raiz / "etc").mkdir()
    (raiz / "etc" / "hardener-vm").write_text("# vm marker", encoding="utf-8")

    # euid != 0 (não é root)
    motivo = trava_vm(raiz, "rhel9", euid=1000)
    assert motivo is not None
    assert "exige root" in motivo


def test_trava_vm_recusa_sem_marcador(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    (raiz / "etc").mkdir()

    # root mas sem marcador /etc/hardener-vm
    motivo = trava_vm(raiz, "rhel9", euid=0)
    assert motivo is not None
    assert "etc/hardener-vm não existe" in motivo


def test_trava_vm_aceita_com_root_e_marcador_em_rhel9(tmp_path):
    raiz = tmp_path / "root"
    raiz.mkdir()
    (raiz / "etc").mkdir()
    (raiz / "etc" / "hardener-vm").write_text("# vm marker", encoding="utf-8")

    motivo = trava_vm(raiz, "rhel9", euid=0)
    assert motivo is None
