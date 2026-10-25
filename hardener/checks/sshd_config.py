"""Primitiva `sshd_config`: uma diretiva efetiva do sshd."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

ARQUIVO_GERENCIADO = "/etc/ssh/sshd_config.d/00-hardener.conf"
CABECALHO = "# Gerenciado pela ferramenta hardener. Alterações manuais serão sobrescritas."


def _texto(valor: Any) -> str:
    if isinstance(valor, bool):
        return "yes" if valor else "no"
    return str(valor).strip()


class SshdConfig(Primitiva):
    nome = "sshd_config"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros = []
        for campo in ("chave", "valor"):
            if params.get(campo) in (None, ""):
                erros.append("parâmetro obrigatório ausente: %s" % campo)
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        chave = str(params["chave"]).lower()
        esperado = _texto(params["valor"])
        r = ctx.runner.executar(["sshd", "-T"])
        if not r.ok:
            raise ErroPrimitiva(
                "sshd -T falhou (rc=%d; precisa de root e do OpenSSH instalado): %s"
                % (r.rc, (r.erro or r.saida).strip()[:200])
            )
        valores = []
        for linha in r.saida.splitlines():
            partes = linha.strip().split(None, 1)
            if len(partes) == 2 and partes[0].lower() == chave:
                valores.append(partes[1].strip())
        atual = " | ".join(valores) if valores else None
        conforme = len(valores) == 1 and valores[0].lower() == esperado.lower()
        return Verificacao(conforme=conforme, atual=atual, esperado=esperado)

    def descrever(self, params: Dict[str, Any]) -> str:
        return "gravar '%s %s' em %s" % (params["chave"], _texto(params["valor"]), ARQUIVO_GERENCIADO)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        chave = str(params["chave"])
        valor = _texto(params["valor"])
        destino = ctx.caminho(ARQUIVO_GERENCIADO)

        ctx.salvar_antes_de_alterar(ARQUIVO_GERENCIADO)

        if destino.exists():
            linhas = destino.read_text(encoding="utf-8").splitlines()
        else:
            linhas = [CABECALHO]
        mantidas = [
            l for l in linhas if not (l.split() and l.split()[0].lower() == chave.lower())
        ]
        mantidas.append("%s %s" % (chave, valor))
        conteudo = "\n".join(mantidas) + "\n"

        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_name(destino.name + ".tmp")
        tmp.write_text(conteudo, encoding="utf-8")
        try:
            os.chmod(str(tmp), 0o600)
        except OSError:
            pass
        os.replace(str(tmp), str(destino))
        return ["%s: %s %s" % (ARQUIVO_GERENCIADO, chave, valor)]
