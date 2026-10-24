import json
from pathlib import Path

from hardener.checks.sshd_config import ARQUIVO_GERENCIADO
from hardener.cli import main, trava_vm
from hardener.rhel import detectar_plataforma

REGRA = """
- id: T-001
  descricao: Desabilitar login direto como root
  referencia: "CIS (A CONFIRMAR)"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: sshd_config
  parametros: {chave: PermitRootLogin, valor: "no"}
  recarregar: sshd
"""


def _base(tmp_path, raiz, estado):
    regras = tmp_path / "regras"
    regras.mkdir()
    (regras / "t.yaml").write_text(REGRA, encoding="utf-8")
    return ["--regras-dir", str(regras), "--raiz", str(raiz), "--estado-dir", str(estado)]


def test_validar_com_politica_do_repositorio(capsys):
    assert main(["validar"]) == 0
    assert "SSH-001" in capsys.readouterr().out  # aparece na lista de referências a confirmar


def test_validar_politica_quebrada(tmp_path, capsys):
    (tmp_path / "x.yaml").write_text("- id: so-o-id\n", encoding="utf-8")
    assert main(["validar", "--regras-dir", str(tmp_path)]) == 2
    assert "política inválida" in capsys.readouterr().err


def test_audit_gera_relatorio_texto_e_json(tmp_path, raiz, estado, runner, capsys):
    saida_json = tmp_path / "rel.json"
    cod = main(["audit", "--json", str(saida_json)] + _base(tmp_path, raiz, estado), runner=runner)
    out = capsys.readouterr().out
    assert cod == 1
    assert "[NAO_CONFORME] T-001" in out and "Dor 6" in out
    dados = json.loads(saida_json.read_text(encoding="utf-8"))
    assert dados["regras"][0]["status"] == "NAO_CONFORME"
    assert dados["por_dor"]["6"]["conformes"] == 0
    assert dados["plataforma"] == "rhel9"


def test_enforce_sem_flags_e_dry_run(tmp_path, raiz, estado, runner, capsys):
    cod = main(["enforce"] + _base(tmp_path, raiz, estado), runner=runner)
    assert cod == 1
    assert "SERIA_CORRIGIDO" in capsys.readouterr().out
    assert not (raiz / ARQUIVO_GERENCIADO.lstrip("/")).exists()


def test_enforce_dry_run_e_apply_sao_excludentes(tmp_path, raiz, estado):
    import pytest

    with pytest.raises(SystemExit):
        main(["enforce", "--dry-run", "--apply"] + _base(tmp_path, raiz, estado))


def test_enforce_apply_e_recusado_fora_da_vm(tmp_path, raiz, estado, runner, capsys):
    # sem marcador /etc/hardener-vm (e/ou sem root) a CLI recusa e não toca em nada
    cod = main(["enforce", "--apply"] + _base(tmp_path, raiz, estado), runner=runner)
    assert cod == 2
    assert "RECUSADO" in capsys.readouterr().err
    assert not (raiz / ARQUIVO_GERENCIADO.lstrip("/")).exists()


def test_trava_vm(raiz):
    assert "só roda em RHEL 9" in trava_vm(raiz, "ubuntu22", 0)
    assert "root" in trava_vm(raiz, "rhel9", 1000)
    assert "trava de segurança" in trava_vm(raiz, "rhel9", 0)
    (raiz / "etc" / "hardener-vm").write_text("", encoding="utf-8")
    assert trava_vm(raiz, "rhel9", 0) is None


def test_rollback_sem_sessao(tmp_path, raiz, estado, runner, capsys):
    assert main(["rollback", "--raiz", str(raiz), "--estado-dir", str(estado)], runner=runner) == 2
    assert "nenhuma sessão" in capsys.readouterr().err


def test_report_reexibe_ultimo_audit(tmp_path, raiz, estado, runner, capsys):
    main(["audit"] + _base(tmp_path, raiz, estado), runner=runner)
    capsys.readouterr()
    assert main(["report", "--estado-dir", str(estado)]) == 0
    assert "T-001" in capsys.readouterr().out


def test_detectar_plataforma(tmp_path):
    (tmp_path / "etc").mkdir()
    assert detectar_plataforma(tmp_path) == "desconhecida"
    (tmp_path / "etc" / "os-release").write_text('ID="rocky"\nVERSION_ID="9.3"\n', encoding="utf-8")
    assert detectar_plataforma(tmp_path) == "rhel9"
    (tmp_path / "etc" / "os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8")
    assert detectar_plataforma(tmp_path) == "ubuntu22"
