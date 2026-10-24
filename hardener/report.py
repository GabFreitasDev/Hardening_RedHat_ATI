"""Relatórios por regra e por dor da ATI, em texto e JSON."""

from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from hardener import __version__
from hardener.models import Resultado, Status

NOMES_DORES = {
    1: "Ransomware",
    2: "Uploads de arquivos",
    3: "Movimentação lateral",
    4: "Patches",
    5: "Revogação de credenciais",
    6: "Mínimo privilégio",
}
ORDEM_STATUS = [
    Status.CONFORME,
    Status.CORRIGIDO,
    Status.SERIA_CORRIGIDO,
    Status.NAO_CONFORME,
    Status.FALHOU,
    Status.ERRO,
    Status.PULADO,
]
_OK = (Status.CONFORME, Status.CORRIGIDO)


def resumo(resultados: Sequence[Resultado]) -> Dict[str, int]:
    contagem = {s: 0 for s in ORDEM_STATUS}
    for r in resultados:
        contagem[r.status] = contagem.get(r.status, 0) + 1
    return {k: v for k, v in contagem.items() if v}


def por_dor(resultados: Sequence[Resultado]) -> Dict[int, Dict[str, int]]:
    dores: Dict[int, Dict[str, int]] = {}
    for r in resultados:
        if r.status == Status.PULADO:
            continue
        for d in r.regra.dor_ati:
            item = dores.setdefault(d, {"total": 0, "conformes": 0})
            item["total"] += 1
            if r.status in _OK:
                item["conformes"] += 1
    return dict(sorted(dores.items()))


def codigo_saida(resultados: Sequence[Resultado]) -> int:
    """0 tudo conforme; 1 há pendências de conformidade; 2 houve erro/falha."""
    status = {r.status for r in resultados}
    if status & {Status.ERRO, Status.FALHOU}:
        return 2
    if status & {Status.NAO_CONFORME, Status.SERIA_CORRIGIDO}:
        return 1
    return 0


def para_dict(
    resultados: Sequence[Resultado], modo: str, plataforma: str, extras: Optional[List[str]] = None
) -> Dict[str, Any]:
    return {
        "ferramenta": "hardener",
        "versao": __version__,
        "modo": modo,
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "plataforma": plataforma,
        "resumo": resumo(resultados),
        "por_dor": {
            str(d): dict(v, nome=NOMES_DORES.get(d, "")) for d, v in por_dor(resultados).items()
        },
        "regras": [
            {
                "id": r.regra.id,
                "descricao": r.regra.descricao,
                "referencia": r.regra.referencia,
                "dor_ati": r.regra.dor_ati,
                "severidade": r.regra.severidade,
                "status": r.status,
                "atual": r.atual,
                "esperado": r.esperado,
                "detalhe": r.detalhe,
                "mudancas": r.mudancas,
            }
            for r in resultados
        ],
        "avisos": extras or [],
    }


def texto(dados: Dict[str, Any]) -> str:
    linhas = [
        "hardener %s | modo: %s | plataforma: %s | host: %s | %s"
        % (dados["versao"], dados["modo"], dados["plataforma"], dados["host"], dados["gerado_em"]),
        "",
    ]
    for aviso in dados.get("avisos", []):
        linhas.append("NOTA: %s" % aviso)
    if dados.get("avisos"):
        linhas.append("")
    for r in dados["regras"]:
        dores = ",".join(str(d) for d in r["dor_ati"])
        linhas.append("[%s] %s  %s  dor %s  %s" % (r["status"], r["id"], r["severidade"], dores, r["descricao"]))
        if r["status"] not in (Status.CONFORME, Status.PULADO):
            if r["atual"] is not None or r["esperado"] is not None:
                linhas.append("    atual: %s | esperado: %s" % (r["atual"], r["esperado"]))
            for m in r["mudancas"]:
                linhas.append("    alterado: %s" % m)
        if r["detalhe"]:
            linhas.append("    detalhe: %s" % r["detalhe"])
    linhas += ["", "Resumo (%d regra(s)): %s" % (len(dados["regras"]), ", ".join(
        "%s=%d" % kv for kv in dados["resumo"].items()) or "nenhuma regra")]
    if dados["por_dor"]:
        linhas.append("Por dor da ATI:")
        for d, v in dados["por_dor"].items():
            linhas.append("  Dor %s (%s): %d/%d conformes" % (d, v["nome"], v["conformes"], v["total"]))
    return "\n".join(linhas) + "\n"


def salvar(estado_dir: Path, dados: Dict[str, Any]) -> Path:
    pasta = Path(estado_dir) / "relatorios"
    pasta.mkdir(parents=True, exist_ok=True)
    nome = "%s-%s.json" % (datetime.now().strftime("%Y%m%d-%H%M%S"), dados["modo"].replace(" ", "_"))
    destino = pasta / nome
    destino.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")
    return destino


def ultimo(estado_dir: Path) -> Optional[Dict[str, Any]]:
    pasta = Path(estado_dir) / "relatorios"
    if not pasta.is_dir():
        return None
    arqs = sorted(pasta.glob("*.json"))
    if not arqs:
        return None
    return json.loads(arqs[-1].read_text(encoding="utf-8"))
