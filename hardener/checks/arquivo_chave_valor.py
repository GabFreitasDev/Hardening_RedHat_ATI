"""Primitiva `arquivo_chave_valor`: garante uma linha chave-valor em arquivos de configuração simples."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from hardener.checks.base import Primitiva
from hardener.models import Contexto, Verificacao


def _texto(valor: Any) -> str:
    if isinstance(valor, bool):
        return "yes" if valor else "no"
    if valor is None:
        return ""
    return str(valor).strip()


def _analisar_linha(linha: str, separador: str) -> Optional[Tuple[str, str]]:
    linha_strip = linha.strip()
    if not linha_strip or linha_strip.startswith("#"):
        return None

    sep_clean = separador.strip()
    if sep_clean:
        if sep_clean in linha:
            k, v = linha.split(sep_clean, 1)
            return k.strip(), v.strip()
        return None
    else:
        partes = linha_strip.split(None, 1)
        if len(partes) == 2:
            return partes[0].strip(), partes[1].strip()
        return None


class ArquivoChaveValor(Primitiva):
    nome = "arquivo_chave_valor"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        for campo in ("arquivo", "chave", "valor"):
            if params.get(campo) in (None, ""):
                erros.append("parâmetro obrigatório ausente: %s" % campo)
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        caminho_arquivo = str(params["arquivo"])
        chave = str(params["chave"])
        esperado = _texto(params["valor"])
        separador = params.get("separador") if params.get("separador") is not None else " = "

        destino = ctx.caminho(caminho_arquivo)
        if not destino.exists():
            return Verificacao(
                conforme=False,
                atual=None,
                esperado=esperado,
                detalhe="arquivo '%s' não existe" % caminho_arquivo,
            )

        try:
            linhas = destino.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            return Verificacao(
                conforme=False,
                atual=None,
                esperado=esperado,
                detalhe="falha ao ler '%s': %s" % (caminho_arquivo, e),
            )

        ultimo_valor: Optional[str] = None
        for linha in linhas:
            par = _analisar_linha(linha, separador)
            if par is not None:
                k, v = par
                if k.lower() == chave.lower():
                    ultimo_valor = v

        atual = ultimo_valor
        conforme = atual is not None and atual == esperado
        if atual is None:
            detalhe = "chave '%s' ausente em %s" % (chave, caminho_arquivo)
        elif not conforme:
            detalhe = "chave '%s' tem valor '%s' (esperado '%s')" % (chave, atual, esperado)
        else:
            detalhe = "chave '%s' conforme (%s)" % (chave, esperado)

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        arquivo = str(params.get("arquivo", ""))
        chave = str(params.get("chave", ""))
        valor = _texto(params.get("valor", ""))
        separador = params.get("separador") if params.get("separador") is not None else " = "
        return "gravar '%s%s%s' em %s" % (chave, separador, valor, arquivo)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        caminho_arquivo = str(params["arquivo"])
        chave = str(params["chave"])
        esperado = _texto(params["valor"])
        separador = params.get("separador") if params.get("separador") is not None else " = "

        # Idempotência: se já está conforme, não altera nada
        v = self.verificar(params, ctx)
        if v.conforme:
            return []

        ctx.salvar_antes_de_alterar(caminho_arquivo)

        destino = ctx.caminho(caminho_arquivo)
        if destino.exists():
            try:
                modo_original = destino.stat().st_mode & 0o7777
            except OSError:
                modo_original = 0o644
            try:
                linhas = destino.read_text(encoding="utf-8").splitlines()
            except OSError:
                linhas = []
        else:
            modo_original = 0o644
            linhas = []

        nova_linha = "%s%s%s" % (chave, separador, esperado)

        ultimo_idx: Optional[int] = None
        for i, linha in enumerate(linhas):
            par = _analisar_linha(linha, separador)
            if par is not None and par[0].lower() == chave.lower():
                ultimo_idx = i

        if ultimo_idx is not None:
            linhas[ultimo_idx] = nova_linha
        else:
            linhas.append(nova_linha)

        conteudo = "\n".join(linhas) + "\n"

        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_name(destino.name + ".tmp")
        tmp.write_text(conteudo, encoding="utf-8")
        try:
            os.chmod(str(tmp), modo_original)
        except OSError:
            pass
        os.replace(str(tmp), str(destino))

        return ["%s: %s%s%s" % (caminho_arquivo, chave, separador, esperado)]
