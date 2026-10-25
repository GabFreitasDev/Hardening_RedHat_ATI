"""Motor: orquestra audit, enforce (dry-run/apply) e rollback."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from hardener import rhel
from hardener.backup import ErroBackup, GerenciadorBackup
from hardener.checks import REGISTRO
from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Regra, Resultado, Status, Verificacao
from hardener.runner import Runner


class Motor:
    def __init__(
        self,
        regras: Sequence[Regra],
        runner: Optional[Runner] = None,
        raiz: Path = Path("/"),
        estado_dir: Path = Path("/var/lib/hardener"),
        plataforma: Optional[str] = None,
        primitivas: Optional[Dict[str, Primitiva]] = None,
    ):
        self.regras = list(regras)
        self.runner = runner or Runner()
        self.raiz = Path(raiz)
        self.gerenciador = GerenciadorBackup(Path(estado_dir), self.raiz)
        self.plataforma = plataforma
        self.primitivas = primitivas if primitivas is not None else REGISTRO

    def _contexto(self) -> Contexto:
        return Contexto(runner=self.runner, raiz=self.raiz, gerenciador=self.gerenciador)

    def _verificar(
        self, regra: Regra, ctx: Contexto
    ) -> Tuple[Resultado, Optional[Primitiva]]:
        if self.plataforma and self.plataforma != "desconhecida" and regra.plataforma != self.plataforma:
            return (
                Resultado(
                    regra,
                    Status.PULADO,
                    detalhe="regra é de %s; sistema é %s" % (regra.plataforma, self.plataforma),
                ),
                None,
            )
        prim = self.primitivas.get(regra.primitiva)
        if prim is None:
            return Resultado(regra, Status.ERRO, detalhe="primitiva desconhecida: %s" % regra.primitiva), None
        erros = prim.validar_parametros(regra.parametros)
        if erros:
            return Resultado(regra, Status.ERRO, detalhe="; ".join(erros)), None
        ctx.regra = regra
        try:
            v: Verificacao = prim.verificar(regra.parametros, ctx)
        except ErroPrimitiva as e:
            return Resultado(regra, Status.ERRO, detalhe=str(e)), prim
        except Exception as e:
            return Resultado(regra, Status.ERRO, detalhe="erro inesperado: %r" % (e,)), prim
        status = Status.CONFORME if v.conforme else Status.NAO_CONFORME
        return Resultado(regra, status, atual=v.atual, esperado=v.esperado, detalhe=v.detalhe), prim

    def auditar(self) -> List[Resultado]:
        ctx = self._contexto()
        return [self._verificar(r, ctx)[0] for r in self.regras]

    def aplicar(self, aplicar: bool = False) -> List[Resultado]:
        ctx = self._contexto()
        resultados: List[Resultado] = []
        pendentes: Dict[str, List[Resultado]] = {}

        for regra in self.regras:
            res, prim = self._verificar(regra, ctx)
            resultados.append(res)
            if res.status != Status.NAO_CONFORME or prim is None:
                continue
            if regra.somente_auditoria:
                res.detalhe = (
                    "Auditoria manual: mantido não conforme por segurança (ação manual requerida)"
                    if aplicar
                    else "Auditoria manual: correção automática desabilitada por segurança (ação manual requerida)"
                )
                continue
            if not aplicar:
                res.status = Status.SERIA_CORRIGIDO
                res.detalhe = prim.descrever(regra.parametros)
                continue
            ctx.regra = regra
            try:
                mudancas = prim.corrigir(regra.parametros, ctx)
                v2 = prim.verificar(regra.parametros, ctx)
            except Exception as e:
                res.status = Status.FALHOU
                res.detalhe = "falha ao corrigir: %s (use rollback se algo foi alterado)" % e
                continue
            res.mudancas = list(mudancas)
            res.atual = v2.atual
            if v2.conforme:
                res.status = Status.CORRIGIDO
                if regra.recarregar:
                    pendentes.setdefault(regra.recarregar, []).append(res)
            else:
                res.status = Status.FALHOU
                res.detalhe = "continua não conforme após corrigir; alteração mantida (use rollback)"

        if aplicar:
            self._validar_e_recarregar(pendentes, ctx)
        return resultados

    def _validar_e_recarregar(self, pendentes: Dict[str, List[Resultado]], ctx: Contexto) -> None:
        sessao = ctx.sessao_criada()
        for servico, resultados in pendentes.items():
            recarga_falhou = False
            ok, msg = rhel.validar_servico(self.runner, servico)
            if ok:
                ok, msg = rhel.recarregar_servico(self.runner, servico)
                if ok:
                    continue
                recarga_falhou = True
                motivo = "recarga de '%s' falhou: %s" % (servico, msg)
            else:
                motivo = "validação de '%s' falhou: %s" % (servico, msg)
            if sessao is not None:
                sessao.restaurar(servico=servico)
                if recarga_falhou:
                    rhel.recarregar_servico(self.runner, servico)
            for r in resultados:
                r.status = Status.FALHOU
                r.detalhe = "%s; alterações revertidas" % motivo

    def reverter(self, sessao_id: Optional[str] = None) -> List[str]:
        if sessao_id:
            sessao = self.gerenciador.abrir(sessao_id)
        else:
            sessao = self.gerenciador.ultima_pendente()
            if sessao is None:
                raise ErroBackup("nenhuma sessão de backup pendente para reverter")
        acoes = ["sessão %s" % sessao.id]
        acoes.extend(sessao.restaurar())
        for servico in sessao.servicos():
            ok, msg = rhel.validar_servico(self.runner, servico)
            if not ok:
                acoes.append("AVISO: '%s' não recarregado, validação falhou: %s" % (servico, msg))
                continue
            ok, msg = rhel.recarregar_servico(self.runner, servico)
            acoes.append(
                "recarregado %s" % servico if ok else "AVISO: recarga de '%s' falhou: %s" % (servico, msg)
            )
        return acoes
