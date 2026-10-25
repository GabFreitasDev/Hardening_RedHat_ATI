"""Camada específica do RHEL."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from hardener.runner import Runner

PLATAFORMA_ALVO = "rhel9"
FAMILIA_RHEL = ("rhel", "rocky", "almalinux", "centos", "ol")

VALIDADORES: Dict[str, List[str]] = {
    "sshd": ["sshd", "-t"],
    "sudoers": ["visudo", "-c"],
}


def detectar_plataforma(raiz: Path = Path("/")) -> str:
    arq = raiz / "etc" / "os-release"
    try:
        linhas = arq.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "desconhecida"
    dados = {}
    for linha in linhas:
        if "=" in linha and not linha.startswith("#"):
            k, v = linha.split("=", 1)
            dados[k.strip()] = v.strip().strip('"')
    ident = dados.get("ID", "").lower()
    versao = dados.get("VERSION_ID", "")
    if ident in FAMILIA_RHEL and versao.split(".")[0] == "9":
        return PLATAFORMA_ALVO
    return "%s%s" % (ident or "?", versao.split(".")[0])


# Daemons que rodam no systemd e necessitam de reload
SERVICOS_COM_RELOAD = {"sshd", "firewalld", "auditd", "systemd"}


def validar_servico(runner: Runner, servico: str) -> Tuple[bool, str]:
    cmd = VALIDADORES.get(servico)
    if cmd is None:
        return True, "sem validador para '%s'" % servico
    r = runner.executar(cmd)
    return r.ok, (r.erro or r.saida).strip()


def recarregar_servico(runner: Runner, servico: str) -> Tuple[bool, str]:
    # Se for um validador de arquivo estático sem daemon (ex: sudoers / visudo)
    if servico not in SERVICOS_COM_RELOAD:
        return True, "validação sintática concluída (sem daemon para recarregar)"
    r = runner.executar(["systemctl", "reload", servico])
    return r.ok, (r.erro or r.saida).strip()
