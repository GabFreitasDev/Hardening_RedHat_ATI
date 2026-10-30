"""Primitiva `montagem`: opções de segurança em /etc/fstab e montagens ativas."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from hardener.checks.base import Primitiva
from hardener.models import Contexto, ErroPrimitiva, Verificacao

ARQUIVO_FSTAB = "/etc/fstab"


class Montagem(Primitiva):
    nome = "montagem"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        ponto = params.get("ponto")
        if not ponto or not isinstance(ponto, str) or not ponto.startswith("/"):
            erros.append("parâmetro 'ponto' deve ser um caminho absoluto válido")
        opcoes = params.get("opcoes")
        if not opcoes or not isinstance(opcoes, list) or not all(isinstance(o, str) for o in opcoes):
            erros.append("parâmetro 'opcoes' deve ser uma lista não vazia de strings")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        ponto = str(params["ponto"]).rstrip("/")
        if not ponto:
            ponto = "/"
        opcoes_esperadas: List[str] = [str(o).strip() for o in params["opcoes"]]

        destino = ctx.caminho(ARQUIVO_FSTAB)
        fstab_encontrado = False
        fstab_conforme = False
        fstab_opcoes_str = "ausente"

        if destino.exists():
            for linha in destino.read_text(encoding="utf-8").splitlines():
                linha_limpa = linha.strip()
                if not linha_limpa or linha_limpa.startswith("#"):
                    continue
                partes = linha_limpa.split()
                if len(partes) >= 4:
                    ponto_fstab = partes[1].rstrip("/")
                    if not ponto_fstab:
                        ponto_fstab = "/"
                    if ponto_fstab == ponto:
                        fstab_encontrado = True
                        fstab_opcoes_str = partes[3]
                        opcoes_presentes = [o.strip() for o in partes[3].split(",") if o.strip()]
                        faltantes = [o for o in opcoes_esperadas if o not in opcoes_presentes]
                        fstab_conforme = (len(faltantes) == 0)
                        break

        # Checar montagem em runtime via findmnt
        r = ctx.runner.executar(["findmnt", "-n", "-o", "OPTIONS", ponto])
        runtime_conforme = True
        runtime_str = "não montado"
        if r.ok and r.saida.strip():
            runtime_str = r.saida.strip()
            ops_runtime = [o.strip() for o in runtime_str.split(",") if o.strip()]
            faltantes_rt = [o for o in opcoes_esperadas if o not in ops_runtime]
            runtime_conforme = (len(faltantes_rt) == 0)

        conforme = (fstab_encontrado and fstab_conforme and runtime_conforme)
        atual = "fstab=%s, runtime=%s" % (fstab_opcoes_str, runtime_str)
        esperado = "opções: %s" % (",".join(opcoes_esperadas))

        return Verificacao(conforme=conforme, atual=atual, esperado=esperado)

    def descrever(self, params: Dict[str, Any]) -> str:
        ponto = params["ponto"]
        opcoes = ",".join(params.get("opcoes", []))
        return "garantir opções [%s] para %s em /etc/fstab e atualizar montagem" % (opcoes, ponto)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        ponto = str(params["ponto"]).rstrip("/")
        if not ponto:
            ponto = "/"
        opcoes_esperadas: List[str] = [str(o).strip() for o in params["opcoes"]]
        mudancas: List[str] = []

        destino = ctx.caminho(ARQUIVO_FSTAB)
        ctx.salvar_antes_de_alterar(ARQUIVO_FSTAB)

        linhas: List[str] = []
        if destino.exists():
            linhas = destino.read_text(encoding="utf-8").splitlines()

        novas_linhas: List[str] = []
        ponto_encontrado = False

        for linha in linhas:
            linha_limpa = linha.strip()
            if not linha_limpa or linha_limpa.startswith("#"):
                novas_linhas.append(linha)
                continue
            partes = linha_limpa.split()
            if len(partes) >= 4:
                ponto_fstab = partes[1].rstrip("/")
                if not ponto_fstab:
                    ponto_fstab = "/"
                if ponto_fstab == ponto:
                    ponto_encontrado = True
                    opcoes_atuais = [o.strip() for o in partes[3].split(",") if o.strip()]
                    adicionadas = [o for o in opcoes_esperadas if o not in opcoes_atuais]
                    if adicionadas:
                        todas_opcoes = opcoes_atuais + adicionadas
                        partes[3] = ",".join(todas_opcoes)
                        novas_linhas.append("\t".join(partes))
                        mudancas.append("fstab %s: adicionadas opções %s" % (ponto, ",".join(adicionadas)))
                    else:
                        novas_linhas.append(linha)
                    continue
            novas_linhas.append(linha)

        if not ponto_encontrado:
            # Ponto de montagem não existia em /etc/fstab
            if ponto in ("/tmp", "/dev/shm"):
                fs_spec = "tmpfs"
                fs_type = "tmpfs"
                # Garante defaults e as opções exigidas
                opts = ["defaults"] + [o for o in opcoes_esperadas if o != "defaults"]
                linha_nova = "%s\t%s\t%s\t%s\t0\t0" % (fs_spec, ponto, fs_type, ",".join(opts))
            else:
                # Diretório como /var/tmp ou /var/www/uploads (bind mount)
                ctx.caminho(ponto).mkdir(parents=True, exist_ok=True)
                fs_spec = ponto
                fs_type = "none"
                opts = ["bind", "defaults"] + [o for o in opcoes_esperadas if o not in ("bind", "defaults")]
                linha_nova = "%s\t%s\t%s\t%s\t0\t0" % (fs_spec, ponto, fs_type, ",".join(opts))

            novas_linhas.append(linha_nova)
            mudancas.append("fstab: adicionada entrada para %s (%s)" % (ponto, ",".join(opts)))

        conteudo = "\n".join(novas_linhas) + "\n"

        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_name(destino.name + ".tmp")
        tmp.write_text(conteudo, encoding="utf-8")
        try:
            os.chmod(str(tmp), 0o644)
        except OSError:
            pass
        os.replace(str(tmp), str(destino))

        # Remontar ou montar no runtime
        r_check = ctx.runner.executar(["findmnt", "-n", ponto])
        if r_check.ok and r_check.saida.strip():
            r_mount = ctx.runner.executar(["mount", "-o", "remount", ponto])
            acao = "remount"
        else:
            r_mount = ctx.runner.executar(["mount", ponto])
            acao = "mount"

        if not r_mount.ok:
            raise ErroPrimitiva(
                "falha na operação %s de %s (rc=%d): %s"
                % (acao, ponto, r_mount.rc, (r_mount.erro or r_mount.saida).strip()[:200])
            )
        mudancas.append("runtime: %s %s executado com sucesso" % (acao, ponto))

        return mudancas
