from typing import Dict
from hardener.checks.base import Primitiva
from hardener.checks.sshd_config import SshdConfig

REGISTRO: Dict[str, Primitiva] = {
    SshdConfig.nome: SshdConfig(),
}
