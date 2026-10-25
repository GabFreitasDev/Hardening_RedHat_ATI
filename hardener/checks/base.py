"""Base para todas as primitivas de verificação e correção."""

from __future__ import annotations

from typing import Any, Dict, List

from hardener.models import Contexto, Verificacao


class Primitiva:
    nome: str

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        return []

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        raise NotImplementedError

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        raise NotImplementedError

    def descrever(self, params: Dict[str, Any]) -> str:
        raise NotImplementedError
