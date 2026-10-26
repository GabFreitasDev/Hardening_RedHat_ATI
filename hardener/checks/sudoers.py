"""Primitiva `sudoers`: auditoria e desativação segura de regras indevidas em sudoers e sudoers.d.

Limitação declarada: aliases (User_Alias, Runas_Alias, Host_Alias, Cmnd_Alias) e construções
complexas da gramática do sudoers não são interpretados semântica ou recursivamente.
A segurança vem antes de tudo: qualquer alteração é validada via `visudo -cf` antes da
substituição atômica, mantendo permissões estritas 0440.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

IGNORAR_PREFIXOS = (
    "defaults",
    "user_alias",
    "runas_alias",
    "host_alias",
    "cmnd_alias",
    "@include",
    "@includedir",
    "#include",
)


def _listar_arquivos_sudoers(ctx: Contexto) -> List[Tuple[str, Path]]:
    """Retorna lista de (caminho_logico, caminho_fisico) dos arquivos sudoers válidos."""
    arquivos: List[Tuple[str, Path]] = []

    # Arquivo principal /etc/sudoers
    caminho_principal = ctx.caminho("/etc/sudoers")
    if caminho_principal.exists() and caminho_principal.is_file():
        arquivos.append(("/etc/sudoers", caminho_principal))

    # Diretório /etc/sudoers.d/
    dir_sudoers_d = ctx.caminho("/etc/sudoers.d")
    if dir_sudoers_d.exists() and dir_sudoers_d.is_dir():
        for item in sorted(dir_sudoers_d.iterdir()):
            # O sudo ignora arquivos que contenham '.' ou terminem em '~'
            if "." in item.name or item.name.endswith("~"):
                continue
            if item.is_file():
                arquivos.append(("/etc/sudoers.d/%s" % item.name, item))

    return arquivos


def _ler_instrucoes(linhas: List[str]) -> List[Tuple[int, int, str]]:
    """
    Junta linhas que terminam com barra invertida (\\) com a seguinte.
    Retorna lista de tuplas (linha_inicio, linha_fim, texto_unificado) 1-indexed.
    """
    instrucoes: List[Tuple[int, int, str]] = []
    idx_inicio = 0
    buffer_linhas: List[str] = []

    for i, linha in enumerate(linhas):
        if not buffer_linhas:
            idx_inicio = i + 1
        linha_rstrip = linha.rstrip()
        if linha_rstrip.endswith("\\"):
            buffer_linhas.append(linha_rstrip[:-1].rstrip())
        else:
            buffer_linhas.append(linha_rstrip)
            texto_unificado = " ".join(b for b in buffer_linhas if b).strip()
            instrucoes.append((idx_inicio, i + 1, texto_unificado))
            buffer_linhas = []

    if buffer_linhas:
        texto_unificado = " ".join(b for b in buffer_linhas if b).strip()
        instrucoes.append((idx_inicio, len(linhas), texto_unificado))

    return instrucoes


def _eh_regra_violadora(texto: str, proibir: str, permitidos: List[str]) -> bool:
    """Verifica se uma instrução do sudoers viola a restrição especificada."""
    texto_strip = texto.strip()
    if not texto_strip or texto_strip.startswith("#"):
        return False

    primeiro_token = texto_strip.split()[0].split(":")[0].lower()
    if primeiro_token in IGNORAR_PREFIXOS:
        return False

    if "=" not in texto_strip:
        return False

    esquerda, direita = texto_strip.split("=", 1)
    quem_hosts = esquerda.strip().split()
    if not quem_hosts:
        return False

    quem = quem_hosts[0].strip()

    if proibir == "nopasswd":
        # Tag NOPASSWD presente na regra
        return bool(re.search(r"\bNOPASSWD\b", texto_strip))

    elif proibir == "all":
        # Se quem está na lista de permitidos, não reprova
        if quem in permitidos:
            return False

        # Remove runas (...)
        direita_sem_runas = re.sub(r"\(.*?\)", "", direita)
        comandos_raw = direita_sem_runas.split(",")
        for cmd in comandos_raw:
            # Remove tags como NOPASSWD:, PASSWD:, etc.
            cmd_limpo = re.sub(r"\b[A-Za-z_]+:\s*", "", cmd).strip()
            if cmd_limpo == "ALL":
                return True

    return False


def _encontrar_violacoes(params: Dict[str, Any], ctx: Contexto) -> List[Dict[str, Any]]:
    proibir = str(params.get("proibir", "")).strip().lower()
    permitidos_raw = params.get("permitidos")
    if permitidos_raw is not None and isinstance(permitidos_raw, list):
        permitidos = [str(p) for p in permitidos_raw]
    else:
        permitidos = ["root", "%wheel"]

    arquivos = _listar_arquivos_sudoers(ctx)
    violacoes: List[Dict[str, Any]] = []

    for caminho_logico, caminho_fisico in arquivos:
        try:
            linhas = caminho_fisico.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        instrucoes = _ler_instrucoes(linhas)
        for l_inicio, l_fim, texto in instrucoes:
            if _eh_regra_violadora(texto, proibir, permitidos):
                violacoes.append({
                    "arquivo_logico": caminho_logico,
                    "caminho_fisico": caminho_fisico,
                    "linha_inicio": l_inicio,
                    "linha_fim": l_fim,
                    "texto": texto,
                })

    return violacoes


class Sudoers(Primitiva):
    nome = "sudoers"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        proibir = params.get("proibir")
        if proibir not in ("nopasswd", "all"):
            erros.append("parâmetro 'proibir' deve ser 'nopasswd' ou 'all'")

        permitidos = params.get("permitidos")
        if permitidos is not None:
            if not isinstance(permitidos, list) or not all(isinstance(p, str) for p in permitidos):
                erros.append("parâmetro 'permitidos', se informado, deve ser uma lista de textos")

        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        proibir = str(params.get("proibir", "")).strip().lower()
        violacoes = _encontrar_violacoes(params, ctx)

        if not violacoes:
            return Verificacao(
                conforme=True,
                atual="nenhuma regra proibida encontrada",
                esperado="nenhuma regra com '%s' indevido" % proibir,
                detalhe="nenhuma regra com '%s' indevido em sudoers e sudoers.d" % proibir,
            )

        linhas_atual = [
            "%s:%d: %s" % (v["arquivo_logico"], v["linha_inicio"], v["texto"])
            for v in violacoes
        ]
        atual = "; ".join(linhas_atual)
        esperado = "nenhuma regra com '%s' indevido" % proibir
        detalhe = "%d regra(s) com '%s' indevido encontrada(s)" % (len(violacoes), proibir)

        return Verificacao(
            conforme=False,
            atual=atual,
            esperado=esperado,
            detalhe=detalhe,
        )

    def descrever(self, params: Dict[str, Any]) -> str:
        proibir = params.get("proibir", "")
        return "desativar regras com '%s' indevido em sudoers e sudoers.d" % proibir

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        violacoes = _encontrar_violacoes(params, ctx)
        if not violacoes:
            return []

        # Agrupa violações por arquivo
        por_arquivo: Dict[str, List[Dict[str, Any]]] = {}
        for v in violacoes:
            por_arquivo.setdefault(v["arquivo_logico"], []).append(v)

        mudancas: List[str] = []

        for caminho_logico, lista_v in por_arquivo.items():
            caminho_fisico = ctx.caminho(caminho_logico)
            if not caminho_fisico.exists():
                continue

            # Salva antes de alterar
            ctx.salvar_antes_de_alterar(caminho_logico)

            linhas = caminho_fisico.read_text(encoding="utf-8").splitlines()

            # Marca as linhas que devem ser comentadas
            linhas_comentar: Set[int] = set()
            for v in lista_v:
                for idx in range(v["linha_inicio"] - 1, v["linha_fim"]):
                    linhas_comentar.add(idx)

            for idx in sorted(linhas_comentar):
                linhas[idx] = "# hardener: desativado: " + linhas[idx]
                mudancas.append("%s:%d: comentada regra ofensiva" % (caminho_logico, idx + 1))

            novo_conteudo = "\n".join(linhas) + "\n"

            # Grava em temporário na mesma pasta
            tmp = caminho_fisico.with_name(caminho_fisico.name + ".tmp")
            tmp.write_text(novo_conteudo, encoding="utf-8")

            # Valida com visudo
            res = ctx.runner.executar(["visudo", "-cf", str(tmp)])
            if not res.ok:
                tmp.unlink(missing_ok=True)
                raise ErroPrimitiva(
                    "validação visudo falhou para %s: %s"
                    % (caminho_logico, res.erro or res.saida)
                )

            # Aplica permissão 0440 e substitui
            try:
                os.chmod(str(tmp), 0o440)
            except OSError:
                pass
            os.replace(str(tmp), str(caminho_fisico))

        return mudancas
