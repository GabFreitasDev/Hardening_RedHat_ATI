"""Primitiva `sysctl`: parâmetros de rede e kernel via sysctl e /etc/sysctl.d/99-hardener.conf."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

ARQUIVO_GERENCIADO = "/etc/sysctl.d/99-hardener.conf"
CABECALHO = "# Gerenciado pela ferramenta hardener. Alterações manuais serão sobrescritas."


def _texto(valor: Any) -> str:
    if isinstance(valor, bool):
        return "1" if valor else "0"
    if valor is None:
        return ""
    return str(valor).strip()


class Sysctl(Primitiva):
    nome = "sysctl"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        for campo in ("chave", "valor"):
            if params.get(campo) in (None, ""):
                erros.append("parâmetro obrigatório ausente: %s" % campo)
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        chave = str(params["chave"]).strip()
        esperado = _texto(params["valor"])

        # 1. Valor ativo no kernel
        r = ctx.runner.executar(["sysctl", "-n", chave])
        if not r.ok:
            raise ErroPrimitiva(
                "sysctl -n %s falhou (rc=%d): %s"
                % (chave, r.rc, (r.erro or r.saida).strip()[:200])
            )
        ativo = r.saida.strip()

        # 2. Valor persistido em /etc/sysctl.d/99-hardener.conf
        destino = ctx.caminho(ARQUIVO_GERENCIADO)
        config: Optional[str] = None
        if destino.exists():
            for linha in destino.read_text(encoding="utf-8").splitlines():
                linha_limpa = linha.strip()
                if not linha_limpa or linha_limpa.startswith("#"):
                    continue
                if "=" in linha_limpa:
                    k, v = linha_limpa.split("=", 1)
                    if k.strip().lower() == chave.lower():
                        config = v.strip()

        conforme = (ativo == esperado and config == esperado)
        atual = "runtime=%s, config=%s" % (
            ativo if ativo is not None else "ausente",
            config if config is not None else "ausente",
        )
        return Verificacao(conforme=conforme, atual=atual, esperado=esperado)

    def descrever(self, params: Dict[str, Any]) -> str:
        chave = str(params["chave"]).strip()
        valor = _texto(params["valor"])
        return "definir '%s = %s' em %s e aplicar no kernel" % (chave, valor, ARQUIVO_GERENCIADO)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        chave = str(params["chave"]).strip()
        valor = _texto(params["valor"])
        destino = ctx.caminho(ARQUIVO_GERENCIADO)

        # 1. Salvar antes de alterar para permitir rollback
        ctx.salvar_antes_de_alterar(ARQUIVO_GERENCIADO)

        # 2. Atualizar ou acrescentar no arquivo de configuração
        if destino.exists():
            linhas = destino.read_text(encoding="utf-8").splitlines()
        else:
            linhas = [CABECALHO]

        mantidas: List[str] = []
        substituido = False
        for l in linhas:
            linha_limpa = l.strip()
            if not linha_limpa.startswith("#") and "=" in linha_limpa:
                k = linha_limpa.split("=", 1)[0].strip()
                if k.lower() == chave.lower():
                    if not substituido:
                        mantidas.append("%s = %s" % (chave, valor))
                        substituido = True
                    continue
            mantidas.append(l)

        if not substituido:
            mantidas.append("%s = %s" % (chave, valor))

        conteudo = "\n".join(mantidas) + "\n"

        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_name(destino.name + ".tmp")
        tmp.write_text(conteudo, encoding="utf-8")
        try:
            os.chmod(str(tmp), 0o644)
        except OSError:
            pass
        os.replace(str(tmp), str(destino))

        # 3. Aplicar imediatamente no runtime
        r = ctx.runner.executar(["sysctl", "-w", "%s=%s" % (chave, valor)])
        if not r.ok:
            raise ErroPrimitiva(
                "sysctl -w %s=%s falhou (rc=%d): %s"
                % (chave, valor, r.rc, (r.erro or r.saida).strip()[:200])
            )

        return ["%s: %s = %s" % (ARQUIVO_GERENCIADO, chave, valor), "runtime: sysctl -w %s=%s" % (chave, valor)]
