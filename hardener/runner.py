"""Execução de comandos do sistema operacional com timeout e isolamento."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ResultadoComando:
    rc: int
    saida: str
    erro: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Runner:
    def executar(self, comando: List[str], timeout: int = 30) -> ResultadoComando:
        try:
            p = subprocess.run(
                comando,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            return ResultadoComando(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return ResultadoComando(124, "", "timeout de %ds expirado" % timeout)
        except FileNotFoundError as e:
            return ResultadoComando(127, "", str(e))
        except OSError as e:
            return ResultadoComando(126, "", str(e))
