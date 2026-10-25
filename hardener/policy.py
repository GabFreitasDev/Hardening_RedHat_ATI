"""Leitura e validação dos arquivos YAML de regras."""

from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Set

from hardener.models import DORES_ATI, SEVERIDADES, Regra

CAMPOS_OBRIGATORIOS = {
    "id",
    "descricao",
    "referencia",
    "dor_ati",
    "severidade",
    "plataforma",
    "primitiva",
}
CAMPOS_CONHECIDOS = CAMPOS_OBRIGATORIOS | {"parametros", "recarregar", "somente_auditoria"}


class PoliticaInvalida(Exception):
    def __init__(self, erros: List[str]):
        self.erros = erros
        super().__init__("\n".join("- %s" % e for e in erros))


def carregar_arquivo(caminho: Path, primitivas_conhecidas: Iterable[str]) -> List[Regra]:
    try:
        import yaml
    except ImportError:
        raise PoliticaInvalida(["PyYAML não está instalado (pip install pyyaml)"])
    texto = caminho.read_text(encoding="utf-8")
    dados = yaml.safe_load(texto) or []
    if not isinstance(dados, list):
        raise PoliticaInvalida(["%s: esperado uma lista de regras" % caminho])

    regras: List[Regra] = []
    erros: List[str] = []
    ids_vistos: Set[str] = set()
    conhecidas = set(primitivas_conhecidas)

    for i, item in enumerate(dados, start=1):
        ctx = "%s (regra #%d)" % (caminho.name, i)
        if not isinstance(item, dict):
            erros.append("%s: deve ser um mapeamento/dicionário" % ctx)
            continue

        rid = item.get("id")
        if rid:
            ctx = "%s [%s]" % (caminho.name, rid)
            if rid in ids_vistos:
                erros.append("%s: id duplicado" % ctx)
            ids_vistos.add(rid)

        faltantes = CAMPOS_OBRIGATORIOS - set(item.keys())
        if faltantes:
            erros.append("%s: campos obrigatórios ausentes: %s" % (ctx, ", ".join(sorted(faltantes))))

        desconhecidos = set(item.keys()) - CAMPOS_CONHECIDOS
        if desconhecidos:
            erros.append("%s: campos desconhecidos: %s" % (ctx, ", ".join(sorted(desconhecidos))))

        dores = item.get("dor_ati")
        if isinstance(dores, list):
            for d in dores:
                if d not in DORES_ATI:
                    erros.append("%s: dor_ati inválida: %r" % (ctx, d))
        else:
            erros.append("%s: dor_ati deve ser lista" % ctx)

        sev = item.get("severidade")
        if sev not in SEVERIDADES:
            erros.append("%s: severidade inválida: %r" % (ctx, sev))

        prim = item.get("primitiva")
        if prim and prim not in conhecidas:
            erros.append("%s: primitiva desconhecida: %r" % (ctx, prim))

        if not erros:
            regras.append(
                Regra(
                    id=item["id"],
                    descricao=item["descricao"],
                    referencia=item["referencia"],
                    dor_ati=list(item["dor_ati"]),
                    severidade=item["severidade"],
                    plataforma=item["plataforma"],
                    primitiva=item["primitiva"],
                    parametros=item.get("parametros") or {},
                    recarregar=item.get("recarregar"),
                    origem=str(caminho),
                    somente_auditoria=bool(item.get("somente_auditoria", False)),
                )
            )

    if erros:
        raise PoliticaInvalida(erros)
    return regras


def carregar_politica(regras_dir: Path, primitivas_conhecidas: Iterable[str]) -> List[Regra]:
    regras: List[Regra] = []
    erros: List[str] = []
    ids: Set[str] = set()

    for arq in sorted(regras_dir.glob("*.yaml")):
        try:
            rs = carregar_arquivo(arq, primitivas_conhecidas)
        except PoliticaInvalida as e:
            erros.extend(e.erros)
            continue
        for r in rs:
            if r.id in ids:
                erros.append("%s: id '%s' já definido em outro arquivo" % (arq.name, r.id))
            ids.add(r.id)
            regras.append(r)

    if erros:
        raise PoliticaInvalida(erros)
    return regras


def filtrar(
    regras: Sequence[Regra],
    ids: Optional[Sequence[str]] = None,
    dores: Optional[Sequence[int]] = None,
) -> List[Regra]:
    res = list(regras)
    if ids:
        conj = {i.upper() for i in ids}
        res = [r for r in res if r.id.upper() in conj]
    if dores:
        conj_d = set(dores)
        res = [r for r in res if any(d in conj_d for d in r.dor_ati)]
    return res


def referencias_pendentes(regras: Sequence[Regra]) -> List[Regra]:
    return [r for r in regras if "A CONFIRMAR" in r.referencia]
