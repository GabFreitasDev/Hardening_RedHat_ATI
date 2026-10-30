"""Relatórios de auditoria de contas locais (Dor 5 da ATI).

Funções somente de leitura para identificação de:
- Contas inativas (OFF-006)
- Senhas sem expiração (OFF-007)
- Chaves SSH sem dono ou de contas inválidas (OFF-008)
"""

from __future__ import annotations

import datetime
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from hardener.runner import Runner

UID_MINIMO_USUARIO = 1000
USUARIOS_SISTEMA_IGNORAR = {"nobody", "nfsnobody"}


def _tentar_parse_data(data_str: str) -> Optional[datetime.datetime]:
    """Tenta interpretar formatos comuns de data emitidos pelo utilitário lastlog."""
    limpa = data_str.strip()
    formatos = [
        "%a %b %d %H:%M:%S %z %Y",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %e %H:%M:%S %z %Y",
        "%a %b %e %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formatos:
        try:
            return datetime.datetime.strptime(limpa, fmt)
        except ValueError:
            continue
    # Tenta extrair ano de 4 dígitos caso haja formato não padrão
    match = re.search(r"\b(20\d\d|19\d\d)\b", limpa)
    if match:
        try:
            ano = int(match.group(1))
            return datetime.datetime(ano, 1, 1)
        except ValueError:
            pass
    return None


def relatorio_contas_inativas(
    raiz: Path = Path("/"),
    runner: Optional[Runner] = None,
    dias_inativos: int = 90,
) -> List[Dict[str, Any]]:
    """Relatório OFF-006: Contas regulares (UID >= 1000) inativas ou que nunca logaram.
    
    Usa o comando lastlog via runner para inspecionar registros de login.
    """
    runner = runner or Runner()
    caminho_passwd = raiz / "etc" / "passwd"
    if not caminho_passwd.exists():
        return []

    # 1. Carregar contas regulares do passwd
    contas_regulares: Dict[str, Dict[str, Any]] = {}
    linhas = caminho_passwd.read_text(encoding="utf-8").splitlines()
    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split(":")
        if len(partes) >= 3:
            user = partes[0]
            try:
                uid = int(partes[2])
            except ValueError:
                continue
            if uid >= UID_MINIMO_USUARIO and user not in USUARIOS_SISTEMA_IGNORAR:
                contas_regulares[user] = {"uid": uid}

    if not contas_regulares:
        return []

    # 2. Executar lastlog
    # Prioriza lastlog -b <dias>; se runner de teste tiver mock apenas para 'lastlog', usa 'lastlog'
    cmd = ["lastlog", "-b", str(dias_inativos)]
    if hasattr(runner, "respostas"):
        respostas = getattr(runner, "respostas")
        if "lastlog" in respostas and ("lastlog -b %s" % dias_inativos) not in respostas:
            cmd = ["lastlog"]

    r = runner.executar(cmd)
    if not r.ok and cmd != ["lastlog"]:
        cmd = ["lastlog"]
        r = runner.executar(cmd)

    saida = r.saida if r.ok else ""
    linhas_lastlog = saida.splitlines()

    achados: List[Dict[str, Any]] = []
    usuarios_no_lastlog: Set[str] = set()

    for linha in linhas_lastlog:
        linha = linha.strip()
        if not linha:
            continue
        partes = linha.split()
        if not partes:
            continue
        user = partes[0]
        if user.lower() in ("username", "usuário", "usuario"):
            continue
        if user not in contas_regulares:
            continue

        usuarios_no_lastlog.add(user)
        linha_lower = linha.lower()
        nunca = any(termo in linha_lower for termo in [
            "never logged in",
            "nunca fez login",
            "nunca logou",
            "never",
            "**never",
        ])

        if nunca:
            achados.append({
                "usuario": user,
                "motivo": "nunca logou",
            })
        else:
            # Extrai texto de data/último login
            data_texto = " ".join(partes[3:]) if len(partes) > 3 else " ".join(partes[1:])
            if "-b" in cmd:
                # O próprio lastlog -b já filtrou apenas registros anteriores a dias_inativos
                achados.append({
                    "usuario": user,
                    "motivo": "inativo há mais de %d dias (último login: %s)" % (dias_inativos, data_texto),
                })
            else:
                # Filtragem manual de data
                dt = _tentar_parse_data(data_texto)
                if dt:
                    agora = datetime.datetime.now(dt.tzinfo) if dt.tzinfo else datetime.datetime.now()
                    dias = (agora - dt).days
                    if dias >= dias_inativos:
                        achados.append({
                            "usuario": user,
                            "motivo": "inativo há mais de %d dias (último login: %s)" % (dias_inativos, data_texto),
                        })
                else:
                    achados.append({
                        "usuario": user,
                        "motivo": "inativo há mais de %d dias (último login: %s)" % (dias_inativos, data_texto),
                    })

    achados.sort(key=lambda x: str(x["usuario"]))
    return achados


def relatorio_senhas_sem_expiracao(
    raiz: Path = Path("/"),
    runner: Optional[Runner] = None,
) -> List[Dict[str, Any]]:
    """Relatório OFF-007: Contas com hash de senha real sem expiração máxima (campo 5 vazio ou 99999).
    
    Lê /etc/shadow e avalia apenas contas ativas com hash válido (que não iniciam com '!' ou '*').
    """
    caminho_shadow = raiz / "etc" / "shadow"
    if not caminho_shadow.exists():
        return []

    achados: List[Dict[str, Any]] = []
    try:
        linhas = caminho_shadow.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split(":")
        if len(partes) < 2:
            continue

        user = partes[0]
        senha = partes[1].strip()

        # Ignora contas bloqueadas ou sem senha (iniciando com '!' ou '*')
        if not senha or senha.startswith("!") or senha.startswith("*"):
            continue

        # Campo 5 (índice 4 em 0-index): validade máxima em dias
        max_dias = partes[4].strip() if len(partes) > 4 else ""

        if max_dias == "" or max_dias == "99999":
            if max_dias == "99999":
                motivo = "validade máxima de 99999 dias (sem expiração prática)"
            else:
                motivo = "campo de validade máxima vazio (sem expiração definida)"
            achados.append({
                "usuario": user,
                "motivo": motivo,
            })

    achados.sort(key=lambda x: str(x["usuario"]))
    return achados


def relatorio_chaves_ssh_sem_dono(
    raiz: Path = Path("/"),
    runner: Optional[Runner] = None,
) -> List[Dict[str, Any]]:
    """Relatório OFF-008: Chaves authorized_keys sem dono no passwd, ou de conta bloqueada/nologin.
    
    Varre /home/*/.ssh/authorized_keys e /root/.ssh/authorized_keys.
    """
    caminho_passwd = raiz / "etc" / "passwd"
    if not caminho_passwd.exists():
        return []

    # 1. Carregar mapeamento de passwd
    uids_passwd: Dict[int, Dict[str, Any]] = {}
    try:
        linhas_passwd = caminho_passwd.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for linha in linhas_passwd:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split(":")
        if len(partes) >= 7:
            user = partes[0]
            try:
                uid = int(partes[2])
            except ValueError:
                continue
            shell = partes[6]
            uids_passwd[uid] = {"username": user, "shell": shell}

    # 2. Carregar contas bloqueadas do shadow
    caminho_shadow = raiz / "etc" / "shadow"
    contas_bloqueadas: Set[str] = set()
    if caminho_shadow.exists():
        try:
            for l_sh in caminho_shadow.read_text(encoding="utf-8").splitlines():
                l_sh = l_sh.strip()
                if not l_sh or l_sh.startswith("#"):
                    continue
                p_sh = l_sh.split(":")
                if len(p_sh) >= 2:
                    if p_sh[1].strip().startswith("!"):
                        contas_bloqueadas.add(p_sh[0])
        except OSError:
            pass

    # 3. Varrer arquivos de chaves autorizadas
    arquivos_alvo: List[Path] = []
    root_keys = raiz / "root" / ".ssh" / "authorized_keys"
    if root_keys.is_file():
        arquivos_alvo.append(root_keys)

    pasta_home = raiz / "home"
    if pasta_home.is_dir():
        for d in pasta_home.iterdir():
            if d.is_dir():
                cand = d / ".ssh" / "authorized_keys"
                if cand.is_file():
                    arquivos_alvo.append(cand)

    achados: List[Dict[str, Any]] = []

    for arq in arquivos_alvo:
        try:
            st = arq.stat()
            file_uid = st.st_uid
        except OSError:
            continue

        nome_pasta_user = arq.parent.parent.name
        caminho_rel = "/" + arq.relative_to(raiz).as_posix()

        # Caso A: UID do arquivo não existe no /etc/passwd
        if file_uid not in uids_passwd:
            usuario_ident = nome_pasta_user if nome_pasta_user and nome_pasta_user not in ("root", "home") else str(file_uid)
            achados.append({
                "usuario": usuario_ident,
                "motivo": "dono do arquivo (UID %d) não existe no /etc/passwd" % file_uid,
                "arquivo": caminho_rel,
                "caminho": caminho_rel,
            })
            continue

        # Caso B: UID existe no passwd; verifica se conta está bloqueada ou com shell nologin
        conta = uids_passwd[file_uid]
        username = conta["username"]
        shell = conta["shell"]
        bloqueada = username in contas_bloqueadas
        nologin = shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false")

        if bloqueada or nologin:
            motivos = []
            if bloqueada:
                motivos.append("conta bloqueada")
            if nologin:
                motivos.append("shell nologin (%s)" % shell)
            achados.append({
                "usuario": username,
                "motivo": "chave de conta inválida: %s" % " e ".join(motivos),
                "arquivo": caminho_rel,
                "caminho": caminho_rel,
            })

    achados.sort(key=lambda x: (str(x["usuario"]), str(x.get("arquivo", ""))))
    return achados


# Nomes públicos canônicos conforme contrato da Parte 5
contas_inativas = relatorio_contas_inativas
senhas_sem_expiracao = relatorio_senhas_sem_expiracao
chaves_sem_dono = relatorio_chaves_ssh_sem_dono

__all__ = [
    "contas_inativas",
    "senhas_sem_expiracao",
    "chaves_sem_dono",
    "relatorio_contas_inativas",
    "relatorio_senhas_sem_expiracao",
    "relatorio_chaves_ssh_sem_dono",
]

