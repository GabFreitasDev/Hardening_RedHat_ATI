"""Primitiva `servico`: desativação de serviços e sockets inseguros ou desnecessários."""

from __future__ import annotations

from typing import Any, Dict, List

from hardener.checks.base import Primitiva
from hardener.models import Contexto, Verificacao


class Servico(Primitiva):
    nome = "servico"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        srvs = params.get("servicos_proibidos")
        if not srvs or not isinstance(srvs, list) or not all(isinstance(s, str) for s in srvs):
            erros.append("parâmetro 'servicos_proibidos' deve ser uma lista não vazia de strings")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        servicos_proibidos: List[str] = [str(s).strip() for s in params.get("servicos_proibidos", [])]
        ativos_ou_habilitados: List[str] = []

        for srv in servicos_proibidos:
            r_act = ctx.runner.executar(["systemctl", "is-active", srv])
            r_enb = ctx.runner.executar(["systemctl", "is-enabled", srv])
            is_active = (r_act.saida.strip() == "active")
            is_enabled = (r_enb.saida.strip() == "enabled")

            if is_active or is_enabled:
                estado_str = []
                if is_active:
                    estado_str.append("ativo")
                if is_enabled:
                    estado_str.append("habilitado")
                ativos_ou_habilitados.append("%s (%s)" % (srv, "/".join(estado_str)))

        conforme = (len(ativos_ou_habilitados) == 0)
        atual = "serviços em execução: %s" % (", ".join(ativos_ou_habilitados) if ativos_ou_habilitados else "nenhum")
        esperado = "nenhum serviço proibido ativo ou habilitado"
        detalhe = (
            "serviços inseguros detectados: %s" % ", ".join(ativos_ou_habilitados)
            if ativos_ou_habilitados
            else "nenhum serviço proibido ativo ou habilitado"
        )

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        srvs = ", ".join(params.get("servicos_proibidos", []))
        return "desativar e desabilitar serviços inseguros: [%s]" % srvs

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        servicos_proibidos: List[str] = [str(s).strip() for s in params.get("servicos_proibidos", [])]
        mudancas: List[str] = []

        for srv in servicos_proibidos:
            r_act = ctx.runner.executar(["systemctl", "is-active", srv])
            r_enb = ctx.runner.executar(["systemctl", "is-enabled", srv])
            if r_act.saida.strip() == "active" or r_enb.saida.strip() == "enabled":
                r_dis = ctx.runner.executar(["systemctl", "disable", "--now", srv])
                mudancas.append("systemctl disable --now %s executado" % srv)

        return mudancas
