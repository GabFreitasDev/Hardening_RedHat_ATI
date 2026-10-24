"""Registro de primitivas.

Para adicionar uma primitiva: crie o módulo em hardener/checks/, herde de
`Primitiva` e inclua uma instância na lista abaixo.
"""

from __future__ import annotations

from typing import Dict

from hardener.checks.base import Primitiva
from hardener.checks.sshd_config import SshdConfig

# TODO (por trilha; ver docs/CONTRATO.md):
#   B: sudoers, usuario_conta, suid_sgid, permissao_arquivo, pam_faillock, ...
#   C: sysctl, montagem, firewalld, portas_escuta, selinux, servico, ...
_PRIMITIVAS = [SshdConfig()]

REGISTRO: Dict[str, Primitiva] = {p.nome: p for p in _PRIMITIVAS}


def obter(nome: str) -> Primitiva:
    try:
        return REGISTRO[nome]
    except KeyError:
        raise KeyError("primitiva desconhecida: %s" % nome)
