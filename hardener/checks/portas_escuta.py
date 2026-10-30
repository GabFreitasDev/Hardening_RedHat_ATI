"""Primitiva `portas_escuta`: auditoria de portas em escuta no sistema."""

from __future__ import annotations

from typing import Any, Dict, List, Set

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao


class PortasEscuta(Primitiva):
    nome = "portas_escuta"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        portas = params.get("portas_autorizadas")
        if portas is None or not isinstance(portas, list) or not all(isinstance(p, int) for p in portas):
            erros.append("parâmetro 'portas_autorizadas' deve ser uma lista de inteiros")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        r = ctx.runner.executar(["ss", "-tulnH"])
        if not r.ok:
            raise ErroPrimitiva("falha ao listar portas de escuta via ss -tulnH (rc=%d): %s" % (r.rc, (r.erro or r.saida).strip()[:200]))

        ignorar_loopback = bool(params.get("ignorar_loopback", True))
        portas_autorizadas: Set[int] = set(params.get("portas_autorizadas", []))
        portas_ativas: Set[int] = set()

        for linha in r.saida.splitlines():
            linha_limpa = linha.strip()
            if not linha_limpa:
                continue
            partes = linha_limpa.split()
            # Localiza a coluna de endereço local (geralmente índice 4 em ss -tulnH)
            col_local = None
            for p in partes:
                if ":" in p and not p.startswith("*:*") and not p.endswith(":*"):
                    col_local = p
                    break
            if col_local is None:
                continue

            endereco, _, porta_str = col_local.rpartition(":")
            if porta_str.isdigit():
                porta = int(porta_str)
                endereco_limpo = endereco.strip("[]")
                is_loopback = (
                    endereco_limpo in ("127.0.0.1", "::1", "localhost")
                    or endereco_limpo.startswith("127.")
                )
                if ignorar_loopback and is_loopback:
                    continue
                portas_ativas.add(porta)

        portas_excedentes = sorted(list(portas_ativas - portas_autorizadas))
        conforme = (len(portas_excedentes) == 0)

        atual = "portas em escuta: %s" % (sorted(list(portas_ativas)) if portas_ativas else "nenhuma")
        esperado = "portas autorizadas: %s" % sorted(list(portas_autorizadas))
        detalhe = (
            "portas não autorizadas ativas: %s" % portas_excedentes
            if portas_excedentes
            else "apenas portas autorizadas em escuta"
        )

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        portas = sorted(list(params.get("portas_autorizadas", [])))
        return "auditar portas em escuta contra lista autorizada %s (inspecionar com ss -tulnp)" % portas

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        raise ErroPrimitiva("sem correção automática: identificar e encerrar o processo/serviço manualmente")
