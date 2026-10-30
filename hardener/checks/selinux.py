"""Primitiva `selinux`: estado do SELinux (enforcing) e contextos de arquivos."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

ARQUIVO_SELINUX_CONFIG = "/etc/selinux/config"


class Selinux(Primitiva):
    nome = "selinux"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        modo = params.get("modo", "estado")
        if modo not in ("estado", "contexto_caminho"):
            erros.append("parâmetro 'modo' deve ser 'estado' ou 'contexto_caminho'")
        if modo == "estado":
            if not params.get("esperado"):
                erros.append("parâmetro 'esperado' obrigatório no modo 'estado'")
        elif modo == "contexto_caminho":
            if not params.get("caminho"):
                erros.append("parâmetro 'caminho' obrigatório no modo 'contexto_caminho'")
            if not params.get("tipo_esperado"):
                erros.append("parâmetro 'tipo_esperado' obrigatório no modo 'contexto_caminho'")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        modo = params.get("modo", "estado")

        if modo == "estado":
            esperado = str(params["esperado"]).strip().lower()

            r_get = ctx.runner.executar(["getenforce"])
            if not r_get.ok:
                raise ErroPrimitiva("getenforce falhou (rc=%d): %s" % (r_get.rc, (r_get.erro or r_get.saida).strip()[:200]))
            ativo = r_get.saida.strip().lower()

            conf_path = ctx.caminho(ARQUIVO_SELINUX_CONFIG)
            config_valor: Optional[str] = None
            if conf_path.exists():
                for linha in conf_path.read_text(encoding="utf-8").splitlines():
                    linha_limpa = linha.strip()
                    if not linha_limpa or linha_limpa.startswith("#"):
                        continue
                    if "=" in linha_limpa:
                        k, v = linha_limpa.split("=", 1)
                        if k.strip().upper() == "SELINUX":
                            config_valor = v.strip().lower()

            conforme = (ativo == esperado and config_valor == esperado)
            atual = "runtime=%s, config=%s" % (ativo, config_valor or "ausente")
            detalhe = "SELinux em modo %s no runtime e em %s" % (ativo, ARQUIVO_SELINUX_CONFIG)
            return Verificacao(conforme=conforme, atual=atual, esperado=esperado, detalhe=detalhe)

        else:
            # modo: contexto_caminho
            caminho_logico = str(params["caminho"])
            tipo_esperado = str(params["tipo_esperado"]).strip()
            alvo = ctx.caminho(caminho_logico)

            if not alvo.exists():
                return Verificacao(
                    conforme=False,
                    atual="caminho ausente",
                    esperado=tipo_esperado,
                    detalhe="caminho '%s' não existe no sistema" % caminho_logico,
                )

            r_stat = ctx.runner.executar(["stat", "-c", "%C", caminho_logico])
            if not r_stat.ok:
                raise ErroPrimitiva("falha ao obter contexto SELinux de %s: %s" % (caminho_logico, (r_stat.erro or r_stat.saida).strip()))

            contexto_atual = r_stat.saida.strip()
            conforme = tipo_esperado in contexto_atual
            atual = contexto_atual
            detalhe = "contexto SELinux contém %s" % tipo_esperado if conforme else "contexto %s não contém tipo %s" % (contexto_atual, tipo_esperado)
            return Verificacao(conforme=conforme, atual=atual, esperado=tipo_esperado, detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        modo = params.get("modo", "estado")
        if modo == "estado":
            return "garantir SELinux em modo %s no runtime e em %s" % (params.get("esperado"), ARQUIVO_SELINUX_CONFIG)
        return "definir contexto SELinux tipo %s recursivamente em %s" % (params.get("tipo_esperado"), params.get("caminho"))

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        modo = params.get("modo", "estado")
        mudancas: List[str] = []

        if modo == "estado":
            esperado = str(params["esperado"]).strip().lower()
            conf_path = ctx.caminho(ARQUIVO_SELINUX_CONFIG)

            ctx.salvar_antes_de_alterar(ARQUIVO_SELINUX_CONFIG)

            linhas: List[str] = []
            if conf_path.exists():
                linhas = conf_path.read_text(encoding="utf-8").splitlines()
            else:
                linhas = ["# Gerenciado pelo hardener"]

            substituido = False
            novas_linhas: List[str] = []
            for l in linhas:
                linha_limpa = l.strip()
                if not linha_limpa.startswith("#") and "=" in linha_limpa:
                    k = linha_limpa.split("=", 1)[0].strip()
                    if k.upper() == "SELINUX":
                        novas_linhas.append("SELINUX=%s" % esperado)
                        substituido = True
                        continue
                novas_linhas.append(l)

            if not substituido:
                novas_linhas.append("SELINUX=%s" % esperado)

            conf_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = conf_path.with_name(conf_path.name + ".tmp")
            tmp.write_text("\n".join(novas_linhas) + "\n", encoding="utf-8")
            try:
                os.chmod(str(tmp), 0o644)
            except OSError:
                pass
            os.replace(str(tmp), str(conf_path))
            mudancas.append("%s: SELINUX=%s" % (ARQUIVO_SELINUX_CONFIG, esperado))

            param_set = "1" if esperado == "enforcing" else "0"
            r_set = ctx.runner.executar(["setenforce", param_set])
            if not r_set.ok:
                raise ErroPrimitiva("setenforce %s falhou (rc=%d): %s" % (param_set, r_set.rc, (r_set.erro or r_set.saida).strip()[:200]))
            mudancas.append("runtime: setenforce %s" % param_set)

        else:
            caminho_logico = str(params["caminho"])
            tipo_esperado = str(params["tipo_esperado"]).strip()
            alvo = ctx.caminho(caminho_logico)
            if not alvo.exists():
                alvo.mkdir(parents=True, exist_ok=True)
                mudancas.append("criado diretório %s" % caminho_logico)

            r_chcon = ctx.runner.executar(["chcon", "-R", "-t", tipo_esperado, caminho_logico])
            if not r_chcon.ok:
                raise ErroPrimitiva("chcon -R -t %s %s falhou (rc=%d): %s" % (tipo_esperado, caminho_logico, r_chcon.rc, (r_chcon.erro or r_chcon.saida).strip()[:200]))
            mudancas.append("chcon -R -t %s %s executado com sucesso" % (tipo_esperado, caminho_logico))

        return mudancas
