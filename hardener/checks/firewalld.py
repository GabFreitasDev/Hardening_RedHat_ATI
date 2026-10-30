"""Primitiva `firewalld`: controle de zona, serviços e portas ativas."""

from __future__ import annotations

from typing import Any, Dict, List

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao


class Firewalld(Primitiva):
    nome = "firewalld"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        servicos = params.get("servicos_permitidos")
        if servicos is None or not isinstance(servicos, list) or not all(isinstance(s, str) for s in servicos):
            erros.append("parâmetro 'servicos_permitidos' deve ser uma lista de strings")
        portas = params.get("portas_permitidas")
        if portas is not None and (not isinstance(portas, list) or not all(isinstance(p, str) for p in portas)):
            erros.append("parâmetro 'portas_permitidas' deve ser uma lista de strings")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        r_state = ctx.runner.executar(["firewall-cmd", "--state"])
        if not r_state.ok or r_state.saida.strip().lower() != "running":
            return Verificacao(
                conforme=False,
                atual="firewalld: %s" % (r_state.saida.strip() or "inativo"),
                esperado="running",
                detalhe="firewalld não está em execução",
            )

        r_srv = ctx.runner.executar(["firewall-cmd", "--list-services"])
        servicos_ativos = [s.strip() for s in r_srv.saida.strip().split() if s.strip()]

        r_port = ctx.runner.executar(["firewall-cmd", "--list-ports"])
        portas_ativas = [p.strip() for p in r_port.saida.strip().split() if p.strip()]

        servicos_permitidos = [s.strip() for s in params.get("servicos_permitidos", [])]
        portas_permitidas = [p.strip() for p in params.get("portas_permitidas", [])]

        servicos_extras = [s for s in servicos_ativos if s not in servicos_permitidos]
        portas_extras = [p for p in portas_ativas if p not in portas_permitidas]
        servicos_faltantes = [s for s in servicos_permitidos if s not in servicos_ativos]
        portas_faltantes = [p for p in portas_permitidas if p not in portas_ativas]

        conforme = (not servicos_extras and not portas_extras and not servicos_faltantes and not portas_faltantes)
        atual = "serviços: [%s], portas: [%s]" % (", ".join(servicos_ativos), ", ".join(portas_ativas))
        esperado = "serviços: [%s], portas: [%s]" % (", ".join(servicos_permitidos), ", ".join(portas_permitidas))

        detalhes: List[str] = []
        if servicos_extras:
            detalhes.append("serviços não autorizados: %s" % ", ".join(servicos_extras))
        if portas_extras:
            detalhes.append("portas não autorizadas: %s" % ", ".join(portas_extras))
        if servicos_faltantes:
            detalhes.append("serviços permitidos ausentes: %s" % ", ".join(servicos_faltantes))
        if portas_faltantes:
            detalhes.append("portas permitidas ausentes: %s" % ", ".join(portas_faltantes))

        return Verificacao(
            conforme=conforme,
            atual=atual,
            esperado=esperado,
            detalhe="; ".join(detalhes) if detalhes else "regras de firewall conformes",
        )

    def descrever(self, params: Dict[str, Any]) -> str:
        srv = ", ".join(params.get("servicos_permitidos", []))
        port = ", ".join(params.get("portas_permitidas", []))
        return "ajustar firewalld: permitir serviços [%s] e portas [%s], removendo excedentes" % (srv, port)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        r_state = ctx.runner.executar(["firewall-cmd", "--state"])
        if not r_state.ok or r_state.saida.strip().lower() != "running":
            r_start = ctx.runner.executar(["systemctl", "start", "firewalld"])
            if not r_start.ok:
                raise ErroPrimitiva("firewalld não está ativo e falhou ao iniciar: %s" % (r_start.erro or r_start.saida).strip())

        r_srv = ctx.runner.executar(["firewall-cmd", "--list-services"])
        servicos_ativos = [s.strip() for s in r_srv.saida.strip().split() if s.strip()]

        r_port = ctx.runner.executar(["firewall-cmd", "--list-ports"])
        portas_ativas = [p.strip() for p in r_port.saida.strip().split() if p.strip()]

        servicos_permitidos = [s.strip() for s in params.get("servicos_permitidos", [])]
        portas_permitidas = [p.strip() for p in params.get("portas_permitidas", [])]

        servicos_extras = [s for s in servicos_ativos if s not in servicos_permitidos]
        portas_extras = [p for p in portas_ativas if p not in portas_permitidas]
        servicos_faltantes = [s for s in servicos_permitidos if s not in servicos_ativos]
        portas_faltantes = [p for p in portas_permitidas if p not in portas_ativas]

        mudancas: List[str] = []

        for srv in servicos_extras:
            ctx.runner.executar(["firewall-cmd", "--remove-service=%s" % srv])
            ctx.runner.executar(["firewall-cmd", "--permanent", "--remove-service=%s" % srv])
            mudancas.append("removido serviço não autorizado do firewalld: %s" % srv)

        for p in portas_extras:
            ctx.runner.executar(["firewall-cmd", "--remove-port=%s" % p])
            ctx.runner.executar(["firewall-cmd", "--permanent", "--remove-port=%s" % p])
            mudancas.append("removida porta não autorizada do firewalld: %s" % p)

        for srv in servicos_faltantes:
            ctx.runner.executar(["firewall-cmd", "--add-service=%s" % srv])
            ctx.runner.executar(["firewall-cmd", "--permanent", "--add-service=%s" % srv])
            mudancas.append("adicionado serviço permitido ao firewalld: %s" % srv)

        for p in portas_faltantes:
            ctx.runner.executar(["firewall-cmd", "--add-port=%s" % p])
            ctx.runner.executar(["firewall-cmd", "--permanent", "--add-port=%s" % p])
            mudancas.append("adicionada porta permitida ao firewalld: %s" % p)

        if mudancas:
            ctx.runner.executar(["firewall-cmd", "--reload"])

        return mudancas
