"""Primitiva `apache_upload`: restrições de execução de scripts no Apache para diretórios de upload."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from hardener.checks.base import Primitiva
from hardener.models import Contexto, Verificacao

ARQUIVO_CONF_UPLOAD = "/etc/httpd/conf.d/hardener-uploads.conf"


class ApacheUpload(Primitiva):
    nome = "apache_upload"

    def validar_parametros(self, params: Dict[str, Any]) -> List[str]:
        erros: List[str] = []
        diretorio = params.get("diretorio")
        if not diretorio or not isinstance(diretorio, str) or not diretorio.startswith("/"):
            erros.append("parâmetro 'diretorio' deve ser um caminho absoluto válido")
        return erros

    def verificar(self, params: Dict[str, Any], ctx: Contexto) -> Verificacao:
        diretorio = str(params.get("diretorio", "/var/www/uploads")).rstrip("/")
        destino = ctx.caminho(ARQUIVO_CONF_UPLOAD)

        if not destino.exists():
            return Verificacao(
                conforme=False,
                atual="ausente",
                esperado="configurado",
                detalhe="arquivo %s não existe" % ARQUIVO_CONF_UPLOAD,
            )

        conteudo = destino.read_text(encoding="utf-8")
        tem_dir = ('<Directory "%s">' % diretorio in conteudo) or ("<Directory %s>" % diretorio in conteudo)
        tem_options = "Options -ExecCGI" in conteudo or "-ExecCGI" in conteudo
        tem_override = "AllowOverride None" in conteudo

        conforme = (tem_dir and tem_options and tem_override)
        atual = "presente" if destino.exists() else "ausente"
        detalhe = (
            "configuração de bloqueio de scripts ativa em %s" % ARQUIVO_CONF_UPLOAD
            if conforme
            else "diretivas restritivas incompletas em %s" % ARQUIVO_CONF_UPLOAD
        )
        return Verificacao(conforme=conforme, atual=atual, esperado="presente e configurado", detalhe=detalhe)

    def descrever(self, params: Dict[str, Any]) -> str:
        diretorio = params.get("diretorio", "/var/www/uploads")
        return "bloquear execução de scripts em %s via %s" % (diretorio, ARQUIVO_CONF_UPLOAD)

    def corrigir(self, params: Dict[str, Any], ctx: Contexto) -> List[str]:
        diretorio = str(params.get("diretorio", "/var/www/uploads")).rstrip("/")
        destino = ctx.caminho(ARQUIVO_CONF_UPLOAD)

        ctx.salvar_antes_de_alterar(ARQUIVO_CONF_UPLOAD)

        conteudo = (
            "# Gerenciado pela ferramenta hardener. Bloqueio de scripts em upload.\n"
            '<Directory "%s">\n'
            "    Options -ExecCGI -Indexes -Includes\n"
            "    AllowOverride None\n"
            '    <FilesMatch "\\.(php|phtml|php3|php4|php5|php7|phps|cgi|pl|py|sh|bash)$">\n'
            "        Require all denied\n"
            "    </FilesMatch>\n"
            "</Directory>\n"
        ) % diretorio

        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_name(destino.name + ".tmp")
        tmp.write_text(conteudo, encoding="utf-8")
        try:
            os.chmod(str(tmp), 0o644)
        except OSError:
            pass
        os.replace(str(tmp), str(destino))

        return ["%s: configuradas opções -ExecCGI -Indexes -Includes e AllowOverride None para %s" % (ARQUIVO_CONF_UPLOAD, diretorio)]
