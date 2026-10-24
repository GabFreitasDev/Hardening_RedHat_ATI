"""Garante que o código não usa sintaxe mais nova que Python 3.9 (o do RHEL 9).

Detecta, por exemplo, `match`, `X | Y` em tempo de execução não, mas sim sintaxe
nova do parser. Não substitui testar na VM, mas pega o erro no computador do aluno.
"""

import ast
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def test_codigo_compativel_com_python_39():
    arquivos = list((RAIZ / "hardener").rglob("*.py")) + list((RAIZ / "tests").rglob("*.py"))
    assert arquivos
    for arq in arquivos:
        ast.parse(arq.read_text(encoding="utf-8"), filename=str(arq), feature_version=(3, 9))
