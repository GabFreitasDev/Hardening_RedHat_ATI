"""Primitiva `permissao_arquivo`: verificação e ajuste de permissões e propriedade."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao


def _obter_usuario(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _obter_grupo(gid: int) -> str:
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except Exception:
        return str(gid)


def _resolver_uid(nome_ou_uid: str) -> Optional[int]:
    try:
        import pwd
        return pwd.getpwnam(nome_ou_uid).pw_uid
    except KeyError:
        if str(nome_ou_uid).isdigit():
            return int(nome_ou_uid)
        return None
    except Exception:
        return None


def _resolver_gid(nome_ou_gid: str) -> Optional[int]:
    try:
        import grp
        return grp.getgrnam(nome_ou_gid).gr_gid
    except KeyError:
        if str(nome_ou_gid).isdigit():
            return int(nome_ou_gid)
        return None
    except Exception:
        return None


class PermissaoArquivo(Primitiva):
    nome = "permissao_arquivo"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        caminho = params.get("caminho")
        if not caminho or not str(caminho).strip():
            erros.append("parâmetro obrigatório ausente: caminho")

        auditar_ww = bool(params.get("auditar_world_writable", False))
        recursivo = bool(params.get("recursivo_arquivos", False))

        tem_propriedade = any(
            params.get(c) not in (None, "")
            for c in ("modo_max", "dono", "grupo")
        ) or auditar_ww

        if not tem_propriedade:
            erros.append("ao menos um entre 'modo_max', 'dono' ou 'grupo' deve ser informado")

        if recursivo and not params.get("modo_max"):
            erros.append("recursivo_arquivos requer 'modo_max'")

        modo_max = params.get("modo_max")
        if modo_max not in (None, ""):
            modo_str = str(modo_max).strip()
            if not modo_str or not all(c in "01234567" for c in modo_str):
                erros.append("modo_max '%s' não é um octal válido (deve conter apenas dígitos 0-7)" % modo_max)
            else:
                try:
                    int(modo_str, 8)
                except ValueError:
                    erros.append("modo_max '%s' não é um octal válido" % modo_max)

        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        caminho_logico = str(params["caminho"])
        destino = ctx.caminho(caminho_logico)
        criar_se_ausente = bool(params.get("criar_se_ausente", False))
        recursivo_arquivos = bool(params.get("recursivo_arquivos", False))
        auditar_ww = bool(params.get("auditar_world_writable", False))

        if not destino.exists():
            if criar_se_ausente:
                return Verificacao(
                    conforme=False,
                    atual="inexistente",
                    esperado=str(params.get("modo_max") or "existente"),
                    detalhe="caminho '%s' não existe" % caminho_logico,
                )
            raise ErroPrimitiva("arquivo '%s' não existe" % caminho_logico)

        # Auditoria world-writable sem sticky bit e sem dono (SYS-002)
        if auditar_ww:
            violacoes: List[str] = []
            if destino.is_dir():
                st_dir = destino.stat()
                modo_dir = st_dir.st_mode & 0o7777
                # world-writable (0o002) mas sem sticky bit (0o1000)
                if (modo_dir & 0o002 != 0) and (modo_dir & 0o1000 == 0):
                    violacoes.append("%s (diretório world-writable sem sticky bit)" % caminho_logico)

                for raiz_sub, _, arquivos in os.walk(str(destino)):
                    for nome_arq in arquivos:
                        caminho_arq = os.path.join(raiz_sub, nome_arq)
                        try:
                            st = os.lstat(caminho_arq)
                        except OSError:
                            continue
                        modo_arq = st.st_mode & 0o7777
                        if (modo_arq & 0o002) != 0:
                            violacoes.append("%s (arquivo world-writable)" % caminho_arq)
                        if _obter_usuario(st.st_uid).isdigit():
                            violacoes.append("%s (arquivo sem dono válido UID %d)" % (caminho_arq, st.st_uid))
            conforme = (len(violacoes) == 0)
            atual = "%d violação(ões)" % len(violacoes) if violacoes else "sem arquivos world-writable irregulares"
            esperado = "nenhum arquivo world-writable sem sticky ou sem dono"
            detalhe = "; ".join(violacoes[:5]) if violacoes else "diretórios conformes"
            return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

        # Verificação recursiva de arquivos internos (UPL-001)
        if recursivo_arquivos and destino.is_dir():
            modo_max_val = int(str(params["modo_max"]).strip(), 8)
            violacoes_rec: List[str] = []
            total_arquivos = 0
            for raiz_sub, _, arquivos in os.walk(str(destino)):
                for nome_arq in arquivos:
                    total_arquivos += 1
                    caminho_arq = os.path.join(raiz_sub, nome_arq)
                    try:
                        st = os.stat(caminho_arq)
                    except OSError:
                        continue
                    modo_arq = st.st_mode & 0o7777
                    if (modo_arq & ~modo_max_val) != 0:
                        rel = os.path.relpath(caminho_arq, str(destino))
                        violacoes_rec.append("%s (modo %04o)" % (rel, modo_arq))

            conforme = (len(violacoes_rec) == 0)
            atual = "%d arquivo(s) irregulares de %d" % (len(violacoes_rec), total_arquivos)
            esperado = "modo <= %04o em todos os arquivos" % modo_max_val
            detalhe = "arquivos excedendo permissão: " + ", ".join(violacoes_rec[:5]) if violacoes_rec else "todos os arquivos em conformidade"
            return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

        try:
            stat_res = destino.stat()
        except OSError as e:
            raise ErroPrimitiva("falha ao obter atributos de '%s': %s" % (caminho_logico, e))

        modo_atual = stat_res.st_mode & 0o7777
        modo_atual_str = "%04o" % modo_atual
        dono_atual = _obter_usuario(stat_res.st_uid)
        grupo_atual = _obter_grupo(stat_res.st_gid)

        atual = "%s %s:%s" % (modo_atual_str, dono_atual, grupo_atual)

        problemas: List[str] = []
        partes_esperado: List[str] = []

        if "modo_max" in params and params["modo_max"] not in (None, ""):
            modo_max_str = str(params["modo_max"]).strip()
            modo_max_val = int(modo_max_str, 8)
            partes_esperado.append("modo <= %04o" % modo_max_val)
            if (modo_atual & ~modo_max_val) != 0:
                problemas.append("modo %s mais permissivo que o máximo %04o" % (modo_atual_str, modo_max_val))

        dono = params.get("dono")
        if dono not in (None, ""):
            partes_esperado.append("dono=%s" % dono)
            if dono_atual != str(dono):
                problemas.append("dono '%s' diferente do esperado '%s'" % (dono_atual, dono))

        grupo = params.get("grupo")
        if grupo not in (None, ""):
            partes_esperado.append("grupo=%s" % grupo)
            if grupo_atual != str(grupo):
                problemas.append("grupo '%s' diferente do esperado '%s'" % (grupo_atual, grupo))

        esperado = ", ".join(partes_esperado)
        conforme = len(problemas) == 0
        detalhe = "; ".join(problemas) if problemas else "permissões e propriedade conformes"

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        caminho = params.get("caminho", "")
        if params.get("auditar_world_writable"):
            return "auditar arquivos world-writable e sem dono em %s" % caminho
        if params.get("recursivo_arquivos"):
            return "restringir permissões de arquivos internos em %s para modo <= %s" % (caminho, params.get("modo_max"))
        partes: List[str] = []
        if "modo_max" in params and params["modo_max"] not in (None, ""):
            modo_max_val = int(str(params["modo_max"]).strip(), 8)
            partes.append("modo <= %04o" % modo_max_val)
        if params.get("dono"):
            partes.append("dono=%s" % params["dono"])
        if params.get("grupo"):
            partes.append("grupo=%s" % params["grupo"])
        return "ajustar permissões de %s (%s)" % (caminho, ", ".join(partes))

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        caminho_logico = str(params["caminho"])
        destino = ctx.caminho(caminho_logico)
        criar_se_ausente = bool(params.get("criar_se_ausente", False))
        recursivo_arquivos = bool(params.get("recursivo_arquivos", False))
        auditar_ww = bool(params.get("auditar_world_writable", False))

        if auditar_ww:
            raise ErroPrimitiva("sem correção automática: auditar e corrigir arquivos world-writable manualmente")

        mudancas: List[str] = []

        if not destino.exists():
            if criar_se_ausente:
                destino.mkdir(parents=True, exist_ok=True)
                mudancas.append("criado diretório %s" % caminho_logico)
            else:
                raise ErroPrimitiva("arquivo '%s' não existe" % caminho_logico)

        # Correção recursiva de arquivos internos (UPL-001)
        if recursivo_arquivos and destino.is_dir():
            modo_max_val = int(str(params["modo_max"]).strip(), 8)
            for raiz_sub, _, arquivos in os.walk(str(destino)):
                for nome_arq in arquivos:
                    caminho_arq = os.path.join(raiz_sub, nome_arq)
                    try:
                        st = os.stat(caminho_arq)
                    except OSError:
                        continue
                    modo_arq = st.st_mode & 0o7777
                    if (modo_arq & ~modo_max_val) != 0:
                        novo_modo = modo_arq & modo_max_val
                        rel = os.path.relpath(caminho_arq, str(ctx.raiz))
                        ctx.salvar_antes_de_alterar("/" + rel.lstrip("/"))
                        try:
                            os.chmod(caminho_arq, novo_modo)
                            mudancas.append("modo alterado de %04o para %04o em %s" % (modo_arq, novo_modo, nome_arq))
                        except OSError as e:
                            raise ErroPrimitiva("falha ao alterar permissões de %s: %s" % (caminho_arq, e))
            return mudancas

        try:
            stat_res = destino.stat()
        except OSError as e:
            raise ErroPrimitiva("falha ao obter atributos de '%s': %s" % (caminho_logico, e))

        modo_atual = stat_res.st_mode & 0o7777
        dono_atual = _obter_usuario(stat_res.st_uid)
        grupo_atual = _obter_grupo(stat_res.st_gid)

        precisa_modo = False
        novo_modo = modo_atual
        if "modo_max" in params and params["modo_max"] not in (None, ""):
            modo_max_val = int(str(params["modo_max"]).strip(), 8)
            if (modo_atual & ~modo_max_val) != 0:
                novo_modo = modo_atual & modo_max_val
                precisa_modo = True

        dono = params.get("dono")
        grupo = params.get("grupo")
        precisa_dono = dono not in (None, "") and dono_atual != str(dono)
        precisa_grupo = grupo not in (None, "") and grupo_atual != str(grupo)

        if not precisa_modo and not precisa_dono and not precisa_grupo:
            return mudancas

        # Salva no backup antes de realizar qualquer alteração (apenas se for arquivo regular)
        if not destino.is_dir():
            ctx.salvar_antes_de_alterar(caminho_logico)

        if precisa_modo:
            try:
                os.chmod(str(destino), novo_modo)
                mudancas.append("modo alterado de %04o para %04o em %s" % (modo_atual, novo_modo, caminho_logico))
            except OSError as e:
                raise ErroPrimitiva("falha ao alterar permissões de %s: %s" % (caminho_logico, e))

        if precisa_dono or precisa_grupo:
            uid = _resolver_uid(str(dono)) if dono not in (None, "") else -1
            gid = _resolver_gid(str(grupo)) if grupo not in (None, "") else -1
            if dono not in (None, "") and uid is None:
                raise ErroPrimitiva("usuário '%s' não encontrado no sistema" % dono)
            if grupo not in (None, "") and gid is None:
                raise ErroPrimitiva("grupo '%s' não encontrado no sistema" % grupo)
            try:
                os.chown(str(destino), uid if uid is not None else -1, gid if gid is not None else -1)
                mudancas.append("propriedade alterada para %s:%s em %s" % (dono or dono_atual, grupo or grupo_atual, caminho_logico))
            except OSError as e:
                raise ErroPrimitiva("falha ao alterar dono/grupo de %s: %s" % (caminho_logico, e))

        return mudancas

