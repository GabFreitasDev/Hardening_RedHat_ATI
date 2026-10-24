"""Execução de comandos do sistema.

Único ponto do projeto que chama subprocess. Nos testes, é substituído por
um Runner falso (veja tests/conftest.py), então nada roda de verdade.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class ResultadoComando:
    rc: int
    saida: str = ""
    erro: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Runner:
    """Executa comandos SEM shell (lista de argumentos), nunca com shell=True."""

    def executar(self, comando: Sequence[str], timeout: int = 30) -> ResultadoComando:
        try:
            p = subprocess.run(
                list(comando),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return ResultadoComando(127, "", "comando não encontrado: %s" % comando[0])
        except subprocess.TimeoutExpired:
            return ResultadoComando(124, "", "tempo esgotado (%ss): %s" % (timeout, " ".join(comando)))
        except OSError as e:  # permissão negada etc.
            return ResultadoComando(126, "", str(e))
        return ResultadoComando(p.returncode, p.stdout, p.stderr)
