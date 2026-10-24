from pathlib import Path

import pytest

from hardener.checks import REGISTRO
from hardener.cli import REGRAS_PADRAO
from hardener.policy import PoliticaInvalida, carregar_politica, filtrar, referencias_pendentes

REGRA_OK = """
- id: T-001
  descricao: teste
  referencia: "CIS (A CONFIRMAR)"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: sshd_config
  parametros: {chave: PermitRootLogin, valor: "no"}
  recarregar: sshd
"""


def _escrever(pasta: Path, nome: str, texto: str):
    (pasta / nome).write_text(texto, encoding="utf-8")


def test_politica_do_repositorio_e_valida():
    regras = carregar_politica(REGRAS_PADRAO, REGISTRO.keys())
    ids = [r.id for r in regras]
    assert "SSH-001" in ids
    assert len(ids) == len(set(ids))


def test_carrega_regra_valida(tmp_path):
    _escrever(tmp_path, "a.yaml", REGRA_OK)
    (regra,) = carregar_politica(tmp_path, REGISTRO.keys())
    assert regra.id == "T-001"
    assert regra.parametros["valor"] == "no"  # string, não booleano
    assert regra.recarregar == "sshd"
    assert referencias_pendentes([regra]) == [regra]


def test_arquivo_vazio_ou_so_comentarios_e_aceito(tmp_path):
    _escrever(tmp_path, "vazio.yaml", "\n")
    _escrever(tmp_path, "comentario.yaml", "# trilha sem regras ainda\n")
    assert carregar_politica(tmp_path) == []


@pytest.mark.parametrize(
    "trecho_errado, mensagem",
    [
        ("severidade: urgente", "severidade inválida"),
        ("dor_ati: [9]", "dor_ati"),
        ("primitiva: nao_existe", "primitiva desconhecida"),
        ("campo_extra: 1", "campos desconhecidos"),
    ],
)
def test_erros_de_validacao(tmp_path, trecho_errado, mensagem):
    chave = trecho_errado.split(":")[0]
    linhas = [l for l in REGRA_OK.splitlines() if not l.strip().startswith(chave + ":")]
    _escrever(tmp_path, "a.yaml", "\n".join(linhas) + "\n  " + trecho_errado + "\n")
    with pytest.raises(PoliticaInvalida) as e:
        carregar_politica(tmp_path, REGISTRO.keys())
    assert mensagem in str(e.value)


def test_campo_obrigatorio_ausente(tmp_path):
    _escrever(tmp_path, "a.yaml", REGRA_OK.replace("  descricao: teste\n", ""))
    with pytest.raises(PoliticaInvalida) as e:
        carregar_politica(tmp_path)
    assert "descricao" in str(e.value)


def test_id_duplicado(tmp_path):
    _escrever(tmp_path, "a.yaml", REGRA_OK)
    _escrever(tmp_path, "b.yaml", REGRA_OK)
    with pytest.raises(PoliticaInvalida) as e:
        carregar_politica(tmp_path)
    assert "duplicado" in str(e.value)


def test_yaml_quebrado(tmp_path):
    _escrever(tmp_path, "a.yaml", "- id: [abc\n")
    with pytest.raises(PoliticaInvalida):
        carregar_politica(tmp_path)


def test_filtrar_por_id_e_dor(tmp_path):
    _escrever(tmp_path, "a.yaml", REGRA_OK + REGRA_OK.replace("T-001", "T-002").replace("[6]", "[3]"))
    regras = carregar_politica(tmp_path)
    assert [r.id for r in filtrar(regras, ids=["t-002"])] == ["T-002"]
    assert [r.id for r in filtrar(regras, dores=[6])] == ["T-001"]
    assert len(filtrar(regras)) == 2
