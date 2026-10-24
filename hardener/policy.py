"""Leitura e validação da política (rules/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml

from hardener.models import DORES_ATI, SEVERIDADES, Regra

OBRIGATORIOS = (
    "id",
    "descricao",
    "referencia",
    "dor_ati",
    "severidade",
    "plataforma",
    "primitiva",
)
OPCIONAIS = ("parametros", "recarregar")
PREFIXO_REFERENCIA_PENDENTE = "A CONFIRMAR"


class PoliticaInvalida(Exception):
    def __init__(self, erros: List[str]):
        super().__init__("\n".join(erros))
        self.erros = erros


def _validar_item(item: Any, origem: str, indice: int, conhecidas: Optional[Iterable[str]]) -> List[str]:
    nome = "%s[%d]" % (origem, indice)
    if not isinstance(item, dict):
        return ["%s: cada regra deve ser um mapa YAML" % nome]
    erros: List[str] = []
    rid = item.get("id")
    if rid:
        nome = "%s (%s)" % (nome, rid)
    for campo in OBRIGATORIOS:
        if campo not in item or item[campo] in (None, "", []):
            erros.append("%s: campo obrigatório ausente: %s" % (nome, campo))
    extras = set(item) - set(OBRIGATORIOS) - set(OPCIONAIS)
    if extras:
        erros.append("%s: campos desconhecidos: %s" % (nome, ", ".join(sorted(extras))))
    sev = item.get("severidade")
    if sev and sev not in SEVERIDADES:
        erros.append("%s: severidade inválida '%s' (use %s)" % (nome, sev, "/".join(SEVERIDADES)))
    dores = item.get("dor_ati")
    if dores:
        if not isinstance(dores, list) or not all(isinstance(d, int) and d in DORES_ATI for d in dores):
            erros.append("%s: dor_ati deve ser lista de inteiros 1..6" % nome)
    params = item.get("parametros", {})
    if params is not None and not isinstance(params, dict):
        erros.append("%s: parametros deve ser um mapa" % nome)
    prim = item.get("primitiva")
    if conhecidas is not None and prim and prim not in set(conhecidas):
        erros.append("%s: primitiva desconhecida '%s'" % (nome, prim))
    return erros


def carregar_politica(
    diretorio: Path, primitivas_conhecidas: Optional[Iterable[str]] = None
) -> List[Regra]:
    """Lê todos os *.yaml de `diretorio`. Levanta PoliticaInvalida com TODOS os erros."""
    diretorio = Path(diretorio)
    if not diretorio.is_dir():
        raise PoliticaInvalida(["diretório de regras não existe: %s" % diretorio])
    erros: List[str] = []
    regras: List[Regra] = []
    conhecidas = list(primitivas_conhecidas) if primitivas_conhecidas is not None else None
    for arq in sorted(diretorio.glob("*.yaml")):
        try:
            dados = yaml.safe_load(arq.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            erros.append("%s: YAML inválido: %s" % (arq.name, e))
            continue
        if dados is None:  # arquivo vazio/só comentários: trilha ainda sem regras
            continue
        if not isinstance(dados, list):
            erros.append("%s: o arquivo deve conter uma lista de regras" % arq.name)
            continue
        for i, item in enumerate(dados):
            e = _validar_item(item, arq.name, i, conhecidas)
            if e:
                erros.extend(e)
                continue
            regras.append(
                Regra(
                    id=str(item["id"]),
                    descricao=str(item["descricao"]),
                    referencia=str(item["referencia"]),
                    dor_ati=list(item["dor_ati"]),
                    severidade=item["severidade"],
                    plataforma=str(item["plataforma"]),
                    primitiva=str(item["primitiva"]),
                    parametros=dict(item.get("parametros") or {}),
                    recarregar=item.get("recarregar"),
                    origem=arq.name,
                )
            )
    vistos: Dict[str, str] = {}
    for r in regras:
        if r.id in vistos:
            erros.append("id duplicado '%s' em %s e %s" % (r.id, vistos[r.id], r.origem))
        vistos[r.id] = r.origem
    if erros:
        raise PoliticaInvalida(erros)
    return regras


def filtrar(
    regras: Sequence[Regra], ids: Optional[Sequence[str]] = None, dores: Optional[Sequence[int]] = None
) -> List[Regra]:
    saida = list(regras)
    if ids:
        pedidos = {i.upper() for i in ids}
        saida = [r for r in saida if r.id.upper() in pedidos]
    if dores:
        saida = [r for r in saida if set(r.dor_ati) & set(dores)]
    return saida


def referencias_pendentes(regras: Sequence[Regra]) -> List[Regra]:
    """Regras cuja referência CIS ainda não foi confirmada no benchmark oficial."""
    return [r for r in regras if PREFIXO_REFERENCIA_PENDENTE in r.referencia.upper()]
