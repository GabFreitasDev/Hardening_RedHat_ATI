"""Contrato de uma primitiva (interface que Aluno B e Aluno C implementam).

Uma primitiva sabe VERIFICAR e CORRIGIR um tipo de configuração (chave do
sshd_config, sysctl, opção de montagem...). A regra YAML só escolhe a primitiva
e passa `parametros`. Regras de implementação:

* verificar() NUNCA altera o sistema.
* corrigir() é IDEMPOTENTE e chama ctx.salvar_antes_de_alterar(caminho) antes de
  escrever em qualquer arquivo (é o que habilita o rollback).
* Falhas inesperadas viram `ErroPrimitiva` (o motor registra ERRO/FALHOU).
* Todo acesso a arquivo usa ctx.caminho(...); todo comando usa ctx.runner.
"""

from __future__ import annotations

from typing import Any, Dict, List

from hardener.models import Contexto, Verificacao


class Primitiva:
    nome = ""  # valor usado em `primitiva:` no YAML

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        """Retorna lista de erros de parâmetros (vazia se ok)."""
        return []

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        raise NotImplementedError

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        """Aplica a correção; retorna descrições curtas do que foi alterado."""
        raise NotImplementedError

    def descrever(self, params: Dict[str, Any]) -> str:
        """Texto do que seria feito (usado no dry-run)."""
        return "aplicar %s" % params
