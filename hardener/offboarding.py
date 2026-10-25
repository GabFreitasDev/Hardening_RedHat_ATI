"""Módulo de Offboarding (Dor 5 da ATI - Revogação de Credenciais).

Implementa a verificação e revogação de acessos para colaboradores desligados
ou contas locais não autorizadas com base em uma lista CSV.
"""

from __future__ import annotations

import csv
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from hardener.backup import GerenciadorBackup, SessaoBackup
from hardener.models import Contexto, Regra, Resultado, Status
from hardener.runner import Runner

UID_MINIMO_USUARIO = 1000
USUARIOS_SISTEMA_IGNORAR = {"nobody", "nfsnobody"}


def carregar_autorizados_csv(caminho_csv: Path) -> Set[str]:
    """Lê a lista de usuários autorizados a partir de um arquivo CSV."""
    if not caminho_csv.exists():
        raise FileNotFoundError("Arquivo de autorizados não encontrado: %s" % caminho_csv)

    autorizados: Set[str] = set()
    with open(caminho_csv, mode="r", encoding="utf-8") as f:
        # Detecta dialeto ou usa padrão
        amostra = f.read(1024)
        f.seek(0)
        delimitador = ","
        if ";" in amostra and "," not in amostra:
            delimitador = ";"

        leitor = csv.reader(f, delimiter=delimitador)
        cabecalho = None
        coluna_idx = 0

        for num_linha, linha in enumerate(leitor):
            if not linha or not any(campo.strip() for campo in linha):
                continue

            linha_limpa = [c.strip() for c in linha]

            if cabecalho is None:
                cabecalho = [c.lower() for c in linha_limpa]
                if "usuario" in cabecalho:
                    coluna_idx = cabecalho.index("usuario")
                elif "user" in cabecalho:
                    coluna_idx = cabecalho.index("user")
                elif "username" in cabecalho:
                    coluna_idx = cabecalho.index("username")
                else:
                    coluna_idx = 0
                    # Primeira linha pode ser já um dado se não parecer cabeçalho
                    if linha_limpa[0].lower() not in ("usuario", "user", "username", "login"):
                        autorizados.add(linha_limpa[0].lower())
                continue

            if len(linha_limpa) > coluna_idx:
                user = linha_limpa[coluna_idx].lower()
                if user:
                    autorizados.add(user)

    # Root é sempre mantido como autorizado por segurança básica
    autorizados.add("root")
    return autorizados


def listar_usuarios_locais(raiz: Path = Path("/")) -> List[Dict[str, Any]]:
    """Lê /etc/passwd da raiz indicada e lista usuários locais regulares."""
    caminho_passwd = raiz / "etc" / "passwd"
    if not caminho_passwd.exists():
        return []

    usuarios = []
    linhas = caminho_passwd.read_text(encoding="utf-8").splitlines()
    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split(":")
        if len(partes) >= 7:
            username = partes[0]
            try:
                uid = int(partes[2])
                gid = int(partes[3])
            except ValueError:
                continue
            gecos = partes[4]
            home = partes[5]
            shell = partes[6]

            # Filtra contas regulares (UID >= 1000) e root
            if (uid >= UID_MINIMO_USUARIO or uid == 0) and username not in USUARIOS_SISTEMA_IGNORAR:
                usuarios.append({
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "gecos": gecos,
                    "home": home,
                    "shell": shell,
                })
    return usuarios


def executar_offboarding(
    caminho_csv: Path,
    raiz: Path = Path("/"),
    estado_dir: Path = Path("/var/lib/hardener"),
    aplicar: bool = False,
    runner: Optional[Runner] = None,
) -> Dict[str, Any]:
    """Executa o processo de offboarding para contas locais fora da lista de autorizados."""
    runner = runner or Runner()
    autorizados = carregar_autorizados_csv(caminho_csv)
    locais = listar_usuarios_locais(raiz)

    contas_nao_autorizadas = [u for u in locais if u["username"] not in autorizados]

    relatorio: Dict[str, Any] = {
        "arquivo_csv": str(caminho_csv),
        "total_autorizados": len(autorizados),
        "total_locais_avaliados": len(locais),
        "contas_nao_autorizadas": [u["username"] for u in contas_nao_autorizadas],
        "modo": "enforce --apply" if aplicar else "enforce --dry-run",
        "acoes": [],
        "mudancas": [],
    }

    if not contas_nao_autorizadas:
        relatorio["acoes"].append("Nenhuma conta não autorizada detectada. Todas as contas locais constam na lista.")
        return relatorio

    gerenciador = GerenciadorBackup(estado_dir, raiz)
    sessao: Optional[SessaoBackup] = None

    for conta in contas_nao_autorizadas:
        user = conta["username"]
        home = Path(conta["home"])

        # Checa se a conta já foi desativada em execução anterior (idempotência)
        auth_keys = raiz / home.as_posix().lstrip("/") / ".ssh" / "authorized_keys"
        shell_inativo = conta["shell"] in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false")
        chaves_ausentes = not auth_keys.exists()

        caminho_group = raiz / "etc" / "group"
        no_wheel = False
        if caminho_group.exists():
            for g_linha in caminho_group.read_text(encoding="utf-8").splitlines():
                if g_linha.startswith("wheel:"):
                    partes = g_linha.split(":")
                    if len(partes) >= 4 and user in partes[3].split(","):
                        no_wheel = True

        if shell_inativo and chaves_ausentes and not no_wheel:
            relatorio["acoes"].append("[JA_BLOQUEADO] Conta '%s' já se encontra neutralizada (shell nologin, sem chaves e sem wheel)" % user)
            continue

        if aplicar and sessao is None:
            sessao = gerenciador.nova_sessao()
            for arq in ("/etc/passwd", "/etc/shadow", "/etc/group"):
                caminho_real = raiz / arq.lstrip("/")
                if caminho_real.exists():
                    sessao.salvar_arquivo("OFF-001", arq, caminho_real)

        # 1. Bloquear conta (usermod -L e chage -E 0)
        desc_lock = "Bloquear conta '%s' (usermod -L e chage -E 0)" % user
        if not aplicar:
            relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_lock)
        else:
            runner.executar(["usermod", "-L", user])
            runner.executar(["chage", "-E", "0", user])
            relatorio["mudancas"].append("usermod -L e chage -E 0 em '%s'" % user)

        # 2. Alterar shell para /sbin/nologin
        if not shell_inativo:
            desc_shell = "Alterar shell de '%s' para /sbin/nologin" % user
            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_shell)
            else:
                runner.executar(["usermod", "-s", "/sbin/nologin", user])
                relatorio["mudancas"].append("shell de '%s' alterado para /sbin/nologin" % user)

        # 3. Arquivar authorized_keys
        auth_keys = raiz / home.as_posix().lstrip("/") / ".ssh" / "authorized_keys"
        if auth_keys.exists():
            desc_keys = "Arquivar chaves SSH de '%s' (%s)" % (user, auth_keys)
            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_keys)
            else:
                if sessao:
                    sessao.salvar_arquivo("OFF-003", str(home / ".ssh" / "authorized_keys"), auth_keys)
                backup_dest = raiz / "var" / "backups" / "revoked_ssh_keys"
                backup_dest.mkdir(parents=True, exist_ok=True)
                dest_file = backup_dest / ("%s_authorized_keys_%s" % (user, sessao.id if sessao else "bkp"))
                shutil.move(str(auth_keys), str(dest_file))
                relatorio["mudancas"].append("chave SSH de '%s' arquivada em %s" % (user, dest_file))

        # 4. Remover do grupo wheel se for membro
        caminho_group = raiz / "etc" / "group"
        if caminho_group.exists():
            for g_linha in caminho_group.read_text(encoding="utf-8").splitlines():
                if g_linha.startswith("wheel:"):
                    partes = g_linha.split(":")
                    if len(partes) >= 4 and user in partes[3].split(","):
                        desc_wheel = "Remover '%s' do grupo administrativo wheel" % user
                        if not aplicar:
                            relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_wheel)
                        else:
                            runner.executar(["gpasswd", "-d", user, "wheel"])
                            relatorio["mudancas"].append("'%s' removido do grupo wheel" % user)

        # 5. Encerrar sessões ativas
        desc_kill = "Encerrar sessões ativas de '%s' (pkill -u %s)" % (user, user)
        if not aplicar:
            relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_kill)
        else:
            runner.executar(["pkill", "-9", "-u", user])
            relatorio["mudancas"].append("sessões ativas de '%s' finalizadas" % user)

    if aplicar and sessao and relatorio["mudancas"]:
        relatorio["sessao_backup"] = sessao.id
        relatorio["acoes"].append("Sessão de backup gravada em %s/backups/%s" % (estado_dir, sessao.id))

    return relatorio
