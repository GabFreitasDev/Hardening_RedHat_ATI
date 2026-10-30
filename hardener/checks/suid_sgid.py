"""Primitiva `suid_sgid`: auditoria de arquivos com bits SUID/SGID contra lista permitida.

Limitação declarada: links simbólicos não são seguidos (conforme comportamento do find -xdev),
filesystems montados externamente com st_dev diferente da raiz são ignorados, e arquivos
localizados dentro de diretórios sem permissão de leitura não são inspecionados.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any, Dict, List, Set

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

IGNORAR_PADRAO = ["/proc", "/sys", "/dev", "/run"]


def _caminho_ignorado(caminho_logico: str, ignorar: List[str]) -> bool:
    for prefixo in ignorar:
        p = prefixo.rstrip("/")
        if not p:
            continue
        if caminho_logico == p or caminho_logico.startswith(p + "/"):
            return True
    return False


class SuidSgid(Primitiva):
    nome = "suid_sgid"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        permitidos = params.get("permitidos")
        if permitidos is None:
            erros.append("parâmetro 'permitidos' é obrigatório")
        elif not isinstance(permitidos, list) or len(permitidos) == 0:
            erros.append("parâmetro 'permitidos' deve ser uma lista não vazia")
        else:
            for p in permitidos:
                if not isinstance(p, str) or not p.startswith("/"):
                    erros.append("todos os itens de 'permitidos' devem ser caminhos absolutos iniciando com '/'")
                    break

        ignorar = params.get("ignorar")
        if ignorar is not None:
            if not isinstance(ignorar, list) or not all(isinstance(x, str) and x.startswith("/") for x in ignorar):
                erros.append("parâmetro 'ignorar', se informado, deve ser uma lista de caminhos absolutos iniciando com '/'")

        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        permitidos = params.get("permitidos", [])
        permitidos_set: Set[str] = {str(p) for p in permitidos}

        ignorar_raw = params.get("ignorar")
        if ignorar_raw is not None and isinstance(ignorar_raw, list):
            ignorar = [str(x) for x in ignorar_raw]
        else:
            ignorar = IGNORAR_PADRAO

        raiz = ctx.caminho("/")
        if not raiz.exists():
            return Verificacao(
                conforme=True,
                atual="nenhum arquivo SUID/SGID fora da lista",
                esperado="apenas arquivos autorizados com bits SUID/SGID",
                detalhe="diretório raiz não encontrado",
            )

        try:
            dev_raiz = raiz.stat().st_dev
        except OSError:
            dev_raiz = 0

        erros_perm = 0

        def on_walk_error(err: OSError) -> None:
            nonlocal erros_perm
            erros_perm += 1

        fora: List[str] = []
        str_raiz = str(raiz)

        for dirpath, dirnames, filenames in os.walk(str_raiz, followlinks=False, topdown=True, onerror=on_walk_error):
            rel = os.path.relpath(dirpath, str_raiz)
            caminho_dir = "/" if rel == "." else "/" + rel.replace(os.sep, "/")

            if _caminho_ignorado(caminho_dir, ignorar):
                dirnames.clear()
                continue

            # Filtra subdiretórios in-place para não descer em ignorados ou outros filesystems
            novos_dirnames: List[str] = []
            for d in dirnames:
                sub_logico = ("/" if caminho_dir == "/" else caminho_dir + "/") + d
                if _caminho_ignorado(sub_logico, ignorar):
                    continue

                sub_fisico = Path(dirpath) / d
                try:
                    st_dir = os.stat(sub_fisico, follow_symlinks=False)
                except (PermissionError, OSError):
                    erros_perm += 1
                    continue

                # Evita cruzar sistemas de arquivos (como find -xdev)
                if not stat.S_ISLNK(st_dir.st_mode) and dev_raiz != 0 and st_dir.st_dev != dev_raiz:
                    continue

                novos_dirnames.append(d)

            dirnames[:] = novos_dirnames

            for f in filenames:
                caminho_fisico = Path(dirpath) / f
                try:
                    st = os.stat(caminho_fisico, follow_symlinks=False)
                except (PermissionError, OSError):
                    erros_perm += 1
                    continue

                # Apenas arquivos regulares (ignora links simbólicos, sockets, fifos, etc.)
                if not stat.S_ISREG(st.st_mode):
                    continue

                # Verifica se possui bit SUID ou SGID
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    caminho_logico = ("/" if caminho_dir == "/" else caminho_dir + "/") + f
                    if caminho_logico not in permitidos_set:
                        fora.append(caminho_logico)

        fora.sort()

        conforme = len(fora) == 0
        esperado = "apenas arquivos autorizados com bits SUID/SGID"

        if conforme:
            atual = "nenhum arquivo SUID/SGID fora da lista"
            detalhe = (
                "todos os arquivos SUID/SGID estão na lista permitida"
                if erros_perm == 0
                else "todos os arquivos SUID/SGID estão na lista permitida (%d erro(s) de permissão ignorados)" % erros_perm
            )
        else:
            if len(fora) <= 20:
                atual = ", ".join(fora)
            else:
                atual = "%s (e mais %d arquivos, total %d)" % (", ".join(fora[:20]), len(fora) - 20, len(fora))

            detalhe = (
                "%d arquivo(s) fora da lista permitida" % len(fora)
                if erros_perm == 0
                else "%d arquivo(s) fora da lista permitida (%d erro(s) de permissão ignorados)" % (len(fora), erros_perm)
            )

        return Verificacao(
            conforme=conforme,
            atual=atual,
            esperado=esperado,
            detalhe=detalhe,
        )

    def descrever(self, params: Dict[str, Any]) -> str:
        return (
            "revisar arquivos SUID/SGID fora da lista e decidir entre remover bits "
            "(chmod u-s,g-s <caminho>) ou adicionar aos permitidos"
        )

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        raise ErroPrimitiva("sem correção automática: revisar manualmente")
