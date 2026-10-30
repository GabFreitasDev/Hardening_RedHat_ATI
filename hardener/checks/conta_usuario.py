"""Primitiva `conta_usuario`: verificação de unicidade de UID 0 e controle de membros de grupos.

Limite declarado:
No modo 'membros_grupo', usuários que possuem o grupo como grupo primário (campo GID em /etc/passwd)
não constam no campo de membros secundários de /etc/group e, portanto, não são contabilizados aqui.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao


class ContaUsuario(Primitiva):
    nome = "conta_usuario"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        modo = params.get("modo")
        if not modo:
            erros.append("parâmetro obrigatório ausente: modo")
        elif modo not in ("uid0_unico", "membros_grupo"):
            erros.append("modo '%s' inválido (deve ser 'uid0_unico' ou 'membros_grupo')" % modo)

        if modo == "membros_grupo":
            if not params.get("grupo"):
                erros.append("parâmetro 'grupo' é obrigatório no modo 'membros_grupo'")
            if "permitidos" not in params or not isinstance(params.get("permitidos"), list):
                erros.append("parâmetro 'permitidos' (lista de usuários) é obrigatório no modo 'membros_grupo'")

        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        modo = str(params.get("modo"))

        if modo == "uid0_unico":
            return self._verificar_uid0_unico(ctx)
        elif modo == "membros_grupo":
            grupo = str(params["grupo"])
            permitidos = [str(u) for u in params.get("permitidos", [])]
            return self._verificar_membros_grupo(grupo, permitidos, ctx)

        raise ErroPrimitiva("modo desconhecido: %s" % modo)

    def _verificar_uid0_unico(self, ctx: Contexto) -> Verificacao:
        caminho_passwd = ctx.caminho("/etc/passwd")
        if not caminho_passwd.exists():
            raise ErroPrimitiva("arquivo /etc/passwd não existe")

        contas_uid0: List[str] = []
        try:
            linhas = caminho_passwd.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise ErroPrimitiva("falha ao ler /etc/passwd: %s" % e)

        for linha in linhas:
            linha_s = linha.strip()
            if not linha_s or linha_s.startswith("#"):
                continue
            partes = linha_s.split(":")
            if len(partes) >= 3:
                user = partes[0]
                uid_str = partes[2]
                if uid_str == "0":
                    contas_uid0.append(user)

        conforme = contas_uid0 == ["root"]
        atual = ", ".join(contas_uid0) if contas_uid0 else "nenhuma conta com UID 0"
        esperado = "apenas 'root' com UID 0"

        if conforme:
            detalhe = "somente a conta 'root' possui UID 0"
        else:
            extras = [u for u in contas_uid0 if u != "root"]
            detalhe = "contas adicionais com UID 0 detectadas: %s" % ", ".join(extras)

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def _verificar_membros_grupo(self, grupo: str, permitidos: List[str], ctx: Contexto) -> Verificacao:
        caminho_group = ctx.caminho("/etc/group")
        if not caminho_group.exists():
            raise ErroPrimitiva("arquivo /etc/group não existe")

        try:
            linhas = caminho_group.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise ErroPrimitiva("falha ao ler /etc/group: %s" % e)

        linha_grupo: Optional[str] = None
        for linha in linhas:
            linha_s = linha.strip()
            if not linha_s or linha_s.startswith("#"):
                continue
            partes = linha_s.split(":")
            if partes and partes[0] == grupo:
                linha_grupo = linha_s
                break

        if linha_grupo is None:
            raise ErroPrimitiva("grupo '%s' não encontrado em /etc/group" % grupo)

        partes_g = linha_grupo.split(":")
        membros_str = partes_g[3] if len(partes_g) >= 4 else ""
        membros = [m.strip() for m in membros_str.split(",") if m.strip()]

        permitidos_set = set(permitidos)
        permitidos_set.add("root")  # root é sempre aceito

        extras = [m for m in membros if m not in permitidos_set]

        conforme = len(extras) == 0
        atual = ", ".join(membros) if membros else "sem membros secundários"
        esperado = "apenas membros autorizados: %s" % ", ".join(sorted(permitidos_set))

        if conforme:
            detalhe = "todos os membros do grupo '%s' são autorizados" % grupo
        else:
            detalhe = "membros não autorizados em '%s': %s" % (grupo, ", ".join(extras))

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        modo = params.get("modo")
        if modo == "uid0_unico":
            return "apenas auditoria: verificar se somente root possui UID 0"
        elif modo == "membros_grupo":
            grupo = params.get("grupo", "")
            return "remover membros não autorizados do grupo '%s'" % grupo
        return "verificar contas de usuário"

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        modo = str(params.get("modo"))

        if modo == "uid0_unico":
            raise ErroPrimitiva("sem correção automática: revisar manualmente")

        if modo == "membros_grupo":
            grupo = str(params["grupo"])
            permitidos = [str(u) for u in params.get("permitidos", [])]

            v = self._verificar_membros_grupo(grupo, permitidos, ctx)
            if v.conforme:
                return []

            permitidos_set = set(permitidos)
            permitidos_set.add("root")

            caminho_group = ctx.caminho("/etc/group")
            linhas = caminho_group.read_text(encoding="utf-8").splitlines()
            membros: List[str] = []
            for linha in linhas:
                partes = linha.strip().split(":")
                if partes and partes[0] == grupo and len(partes) >= 4:
                    membros = [m.strip() for m in partes[3].split(",") if m.strip()]
                    break

            extras = [m for m in membros if m not in permitidos_set]
            if not extras:
                return []

            # Backup de /etc/group E /etc/gshadow antes de alterar
            ctx.salvar_antes_de_alterar("/etc/group")
            ctx.salvar_antes_de_alterar("/etc/gshadow")

            mudancas: List[str] = []
            for usuario in extras:
                r = ctx.runner.executar(["gpasswd", "-d", usuario, grupo])
                if not r.ok:
                    msg = (r.erro or r.saida).strip()
                    raise ErroPrimitiva("falha ao remover '%s' de '%s' via gpasswd -d: %s" % (usuario, grupo, msg))
                mudancas.append("removido '%s' do grupo '%s'" % (usuario, grupo))

            return mudancas

        raise ErroPrimitiva("modo desconhecido: %s" % modo)
