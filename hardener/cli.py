"""Interface de linha de comando.

  python -m hardener validar                 # confere os YAML (roda em qualquer máquina)
  python -m hardener audit                   # só verifica
  python -m hardener enforce                 # = enforce --dry-run (padrão): mostra o que mudaria
  python -m hardener enforce --apply         # aplica (somente na VM; ver trava abaixo)
  python -m hardener rollback [--sessao ID]  # desfaz a última sessão de enforce
  python -m hardener report                  # reexibe o último relatório salvo
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from hardener import __version__, report, rhel
from hardener.backup import ErroBackup
from hardener.checks import REGISTRO
from hardener.engine import Motor
from hardener.policy import PoliticaInvalida, carregar_politica, filtrar, referencias_pendentes
from hardener.runner import Runner

RAIZ_REPO = Path(__file__).resolve().parent.parent
REGRAS_PADRAO = RAIZ_REPO / "rules"
ESTADO_PADRAO = Path(os.environ.get("HARDENER_ESTADO_DIR", "/var/lib/hardener"))
MARCADOR_VM = "etc/hardener-vm"  # relativo à raiz; criado na VM com: sudo touch /etc/hardener-vm


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hardener", description="Conformidade de hardening para RHEL 9")
    p.add_argument("--version", action="version", version="hardener %s" % __version__)
    sub = p.add_subparsers(dest="comando", required=True)

    comum = argparse.ArgumentParser(add_help=False)
    comum.add_argument("--regras-dir", type=Path, default=REGRAS_PADRAO, help="pasta com os YAML (padrão: rules/)")
    comum.add_argument("--regra", action="append", metavar="ID", help="só estas regras (repetível)")
    comum.add_argument("--dor", action="append", type=int, metavar="N", help="só regras desta dor da ATI (1-6)")
    comum.add_argument("--estado-dir", type=Path, default=ESTADO_PADRAO, help="onde guardar backups e relatórios")
    comum.add_argument("--raiz", type=Path, default=Path("/"), help="prefixo de caminhos (desenvolvimento/testes)")
    comum.add_argument("--json", type=Path, metavar="ARQ", help="grava também o relatório JSON neste arquivo")

    sub.add_parser("validar", help="valida os YAML da política").add_argument(
        "--regras-dir", type=Path, default=REGRAS_PADRAO
    )
    sub.add_parser("audit", parents=[comum], help="verifica a conformidade (não altera nada)")

    enf = sub.add_parser("enforce", parents=[comum], help="corrige (dry-run por padrão)")
    grupo = enf.add_mutually_exclusive_group()
    grupo.add_argument("--dry-run", action="store_true", help="mostra o que mudaria (comportamento padrão)")
    grupo.add_argument("--apply", action="store_true", help="aplica as correções (somente na VM)")

    rb = sub.add_parser("rollback", help="restaura o backup da última sessão de enforce")
    rb.add_argument("--sessao", metavar="ID", help="id da sessão (padrão: a mais recente pendente)")
    rb.add_argument("--estado-dir", type=Path, default=ESTADO_PADRAO)
    rb.add_argument("--raiz", type=Path, default=Path("/"))

    rp = sub.add_parser("report", help="mostra o último relatório salvo")
    rp.add_argument("--estado-dir", type=Path, default=ESTADO_PADRAO)
    rp.add_argument("--formato", choices=("texto", "json"), default="texto")
    return p


def trava_vm(raiz: Path, plataforma: str, euid: Optional[int]) -> Optional[str]:
    """Motivo de recusa do `enforce --apply`, ou None se pode prosseguir."""
    if plataforma != rhel.PLATAFORMA_ALVO:
        return "plataforma '%s': enforce --apply só roda em RHEL 9 (ou Rocky/Alma 9)" % plataforma
    if euid != 0:
        return "enforce --apply exige root (use sudo)"
    if not (raiz / MARCADOR_VM).exists():
        return (
            "trava de segurança: /%s não existe. O enforce só deve rodar na VM de testes; "
            "nela, crie o marcador com: sudo touch /%s" % (MARCADOR_VM, MARCADOR_VM)
        )
    return None


def _configurar_saida() -> None:
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def _carregar(args: argparse.Namespace):
    regras = carregar_politica(args.regras_dir, REGISTRO.keys())
    return filtrar(regras, args.regra, args.dor)


def _emitir(resultados, modo: str, plataforma: str, args: argparse.Namespace, avisos: List[str], salvar: bool) -> None:
    dados = report.para_dict(resultados, modo, plataforma, avisos)
    if salvar:
        try:
            destino = report.salvar(args.estado_dir, dados)
            dados["avisos"].append("relatório salvo em %s" % destino)
        except OSError as e:
            dados["avisos"].append("não foi possível salvar o relatório em %s: %s" % (args.estado_dir, e))
    sys.stdout.write(report.texto(dados))
    if getattr(args, "json", None):
        args.json.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: Optional[List[str]] = None, runner: Optional[Runner] = None) -> int:
    _configurar_saida()
    args = construir_parser().parse_args(argv)
    runner = runner or Runner()

    try:
        if args.comando == "validar":
            regras = carregar_politica(args.regras_dir, REGISTRO.keys())
            problemas = []
            for r in regras:
                for e in REGISTRO[r.primitiva].validar_parametros(r.parametros):
                    problemas.append("%s: %s" % (r.id, e))
            if problemas:
                raise PoliticaInvalida(problemas)
            pend = referencias_pendentes(regras)
            print("%d regra(s) válida(s) em %s" % (len(regras), args.regras_dir))
            if pend:
                print("%d regra(s) com referência CIS ainda A CONFIRMAR: %s" % (len(pend), ", ".join(r.id for r in pend)))
            return 0

        if args.comando == "report":
            dados = report.ultimo(args.estado_dir)
            if dados is None:
                print("nenhum relatório salvo em %s" % args.estado_dir, file=sys.stderr)
                return 2
            sys.stdout.write(json.dumps(dados, indent=2, ensure_ascii=False) + "\n" if args.formato == "json" else report.texto(dados))
            return 0

        plataforma = rhel.detectar_plataforma(args.raiz)

        if args.comando == "rollback":
            motor = Motor([], runner, args.raiz, args.estado_dir, plataforma)
            for linha in motor.reverter(args.sessao):
                print(linha)
            return 0

        # audit / enforce
        regras = _carregar(args)
        avisos: List[str] = []
        if plataforma == "desconhecida":
            avisos.append("não foi possível detectar a plataforma (sem /etc/os-release); regras executadas sem checá-la")
        if not regras:
            print("nenhuma regra selecionada", file=sys.stderr)
            return 2
        motor = Motor(regras, runner, args.raiz, args.estado_dir, plataforma)

        if args.comando == "audit":
            resultados = motor.auditar()
            _emitir(resultados, "audit", plataforma, args, avisos, salvar=True)
            return report.codigo_saida(resultados)

        # enforce
        if args.apply:
            euid = os.geteuid() if hasattr(os, "geteuid") else None
            motivo = trava_vm(args.raiz, plataforma, euid)
            if motivo:
                print("RECUSADO: %s" % motivo, file=sys.stderr)
                return 2
            resultados = motor.aplicar(aplicar=True)
            _emitir(resultados, "enforce --apply", plataforma, args, avisos, salvar=True)
        else:
            resultados = motor.aplicar(aplicar=False)
            _emitir(resultados, "enforce --dry-run", plataforma, args, avisos, salvar=False)
        return report.codigo_saida(resultados)

    except PoliticaInvalida as e:
        print("política inválida:\n%s" % e, file=sys.stderr)
        return 2
    except ErroBackup as e:
        print("erro: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
