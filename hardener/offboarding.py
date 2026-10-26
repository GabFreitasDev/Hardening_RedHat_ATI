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
from hardener.relatorios_contas import (
    relatorio_chaves_ssh_sem_dono,
    relatorio_contas_inativas,
    relatorio_senhas_sem_expiracao,
)
from hardener.runner import Runner

UID_MINIMO_USUARIO = 1000
USUARIOS_SISTEMA_IGNORAR = {"nobody", "nfsnobody"}


class ErroOffboarding(Exception):
    """Exceção levantada para erros de validação ou segurança no módulo de offboarding."""
    pass


__all__ = [
    "ErroOffboarding",
    "carregar_autorizados_csv",
    "executar_offboarding",
    "avaliar_offboarding",
    "aplicar_offboarding",
    "listar_usuarios_locais",
    "relatorio_contas_inativas",
    "relatorio_senhas_sem_expiracao",
    "relatorio_chaves_ssh_sem_dono",
]



def _obter_usuario_execucao() -> str:
    """Identifica o usuário que invocou o comando (SUDO_USER ou usuário efetivo)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user.strip():
        return sudo_user.strip()
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        import getpass
        try:
            return getpass.getuser()
        except Exception:
            return "root"


def carregar_autorizados_csv(caminho_csv: Path) -> Set[str]:
    """Lê a lista de usuários autorizados a partir de um arquivo CSV.
    
    Respeita a coluna opcional 'status': contas com status desligado, inativo
    ou desativado não são incluídas como autorizadas.
    """
    if not caminho_csv.exists():
        raise FileNotFoundError("Arquivo de autorizados não encontrado: %s" % caminho_csv)

    autorizados: Set[str] = set()
    with open(caminho_csv, mode="r", encoding="utf-8") as f:
        amostra = f.read(1024)
        f.seek(0)
        delimitador = ","
        if ";" in amostra and "," not in amostra:
            delimitador = ";"

        leitor = csv.reader(f, delimiter=delimitador)
        cabecalho = None
        coluna_idx = 0
        status_idx: Optional[int] = None

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
                    if linha_limpa[0].lower() not in ("usuario", "user", "username", "login"):
                        autorizados.add(linha_limpa[0].lower())
                if "status" in cabecalho:
                    status_idx = cabecalho.index("status")
                continue

            if len(linha_limpa) > coluna_idx:
                user = linha_limpa[coluna_idx].lower()
                if user:
                    if status_idx is not None and len(linha_limpa) > status_idx:
                        status_val = linha_limpa[status_idx].lower()
                        if status_val in ("desligado", "inativo", "desativado"):
                            continue
                    autorizados.add(user)

    # Root é sempre mantido como autorizado por segurança básica
    autorizados.add("root")

    # Guarda: rejeita lista se contiver exclusivamente root
    if autorizados == {"root"}:
        raise ErroOffboarding(
            "A lista de autorizados contém somente o usuário 'root'. "
            "Operação abortada por segurança para evitar bloqueio acidental de todas as contas do sistema."
        )

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


def _carregar_shadow(raiz: Path) -> Dict[str, Dict[str, Any]]:
    """Lê /etc/shadow para inspecionar estado de bloqueio e expiração das contas."""
    caminho = raiz / "etc" / "shadow"
    if not caminho.exists():
        return {}
    shadow_data = {}
    try:
        linhas = caminho.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        partes = linha.split(":")
        if len(partes) >= 2:
            user = partes[0]
            senha = partes[1]
            expiracao = ""
            if len(partes) >= 8 and partes[7].strip():
                expiracao = partes[7].strip()
            elif len(partes) >= 9 and partes[8].strip():
                expiracao = partes[8].strip()
            shadow_data[user] = {
                "bloqueada": senha.startswith("!"),
                "expirada": expiracao == "0",
            }

    return shadow_data


def _usuario_no_grupo(raiz: Path, grupo: str, usuario: str) -> bool:
    """Verifica se o usuário consta como membro secundário do grupo em /etc/group."""
    caminho_group = raiz / "etc" / "group"
    if not caminho_group.exists():
        return False
    try:
        linhas = caminho_group.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for linha in linhas:
        partes = linha.strip().split(":")
        if partes and partes[0] == grupo and len(partes) >= 4:
            membros = [m.strip() for m in partes[3].split(",") if m.strip()]
            return usuario in membros
    return False


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

    # Guarda: validação de que o operador executor está na lista de autorizados
    if aplicar:
        operador = _obter_usuario_execucao()
        if operador and operador != "root" and operador not in autorizados:
            raise ErroOffboarding(
                "Usuário executor '%s' (SUDO_USER/efetivo) não consta na lista de autorizados. "
                "Operação abortada para evitar lockout acidental do operador." % operador
            )

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
        "falhas": [],
    }

    if not contas_nao_autorizadas:
        relatorio["acoes"].append("Nenhuma conta não autorizada detectada. Todas as contas locais constam na lista.")
        return relatorio

    shadow_data = _carregar_shadow(raiz)

    # Planejamento das ações estritamente necessárias por conta
    acoes_planejadas = []
    for conta in contas_nao_autorizadas:
        user = conta["username"]
        home = Path(conta["home"])

        sh_info = shadow_data.get(user)
        bloqueada = sh_info["bloqueada"] if sh_info is not None else False
        expirada = sh_info["expirada"] if sh_info is not None else False

        precisa_lock = not bloqueada
        precisa_expire = not expirada
        precisa_shell = conta["shell"] not in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false")

        auth_keys = raiz / home.as_posix().lstrip("/") / ".ssh" / "authorized_keys"
        precisa_keys = auth_keys.exists()

        precisa_wheel = _usuario_no_grupo(raiz, "wheel", user)

        precisa_alguma = precisa_lock or precisa_expire or precisa_shell or precisa_keys or precisa_wheel
        acoes_planejadas.append({
            "conta": conta,
            "user": user,
            "home": home,
            "auth_keys": auth_keys,
            "precisa_lock": precisa_lock,
            "precisa_expire": precisa_expire,
            "precisa_shell": precisa_shell,
            "precisa_keys": precisa_keys,
            "precisa_wheel": precisa_wheel,
            "precisa_alguma": precisa_alguma,
        })

    tem_acoes_pendentes = any(a["precisa_alguma"] for a in acoes_planejadas)

    if not tem_acoes_pendentes:
        relatorio["acoes"].append("Nenhuma alteração necessária: todas as contas não autorizadas já se encontram devidamente bloqueadas e desativadas.")
        return relatorio

    gerenciador = GerenciadorBackup(estado_dir, raiz)
    sessao: Optional[SessaoBackup] = None

    if aplicar:
        sessao = gerenciador.nova_sessao()
        # Backup prévio obrigatório de passwd, shadow, group e gshadow
        for arq in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"):
            caminho_real = raiz / arq.lstrip("/")
            if caminho_real.exists():
                sessao.salvar_arquivo("OFF-001", arq, caminho_real)

    for plano in acoes_planejadas:
        user = plano["user"]
        auth_keys = plano["auth_keys"]
        home = plano["home"]

        # Se esta conta já está 100% bloqueada, não gera ruído nem ações
        if not plano["precisa_alguma"]:
            relatorio["acoes"].append("[CONFORME] Conta '%s' já neutralizada" % user)
            continue

        # 1. Bloquear conta (usermod -L) e expirar (chage -E 0)
        if plano["precisa_lock"] or plano["precisa_expire"]:
            partes_desc = []
            if plano["precisa_lock"]:
                partes_desc.append("usermod -L")
            if plano["precisa_expire"]:
                partes_desc.append("chage -E 0")
            desc_lock = "Bloquear conta '%s' (%s)" % (user, " e ".join(partes_desc))

            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_lock)
            else:
                if plano["precisa_lock"]:
                    r_l = runner.executar(["usermod", "-L", user])
                    if r_l.ok:
                        relatorio["mudancas"].append("usermod -L em '%s'" % user)
                    else:
                        msg = (r_l.erro or r_l.saida).strip()
                        relatorio["falhas"].append({"conta": user, "acao": "usermod -L", "mensagem": msg, "erro": msg})

                if plano["precisa_expire"]:
                    r_e = runner.executar(["chage", "-E", "0", user])
                    if r_e.ok:
                        relatorio["mudancas"].append("chage -E 0 em '%s'" % user)
                    else:
                        msg = (r_e.erro or r_e.saida).strip()
                        relatorio["falhas"].append({"conta": user, "acao": "chage -E 0", "mensagem": msg, "erro": msg})

        # 2. Alterar shell para /sbin/nologin
        if plano["precisa_shell"]:
            desc_shell = "Alterar shell de '%s' para /sbin/nologin" % user
            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_shell)
            else:
                r_s = runner.executar(["usermod", "-s", "/sbin/nologin", user])
                if r_s.ok:
                    relatorio["mudancas"].append("shell de '%s' alterado para /sbin/nologin" % user)
                else:
                    msg = (r_s.erro or r_s.saida).strip()
                    relatorio["falhas"].append({"conta": user, "acao": "usermod -s /sbin/nologin", "mensagem": msg, "erro": msg})

        # 3. Arquivar authorized_keys se o arquivo existir
        if plano["precisa_keys"]:
            desc_keys = "Arquivar chaves SSH de '%s' (%s)" % (user, auth_keys)
            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_keys)
            else:
                if sessao:
                    sessao.salvar_arquivo("OFF-003", str(home / ".ssh" / "authorized_keys"), auth_keys)
                backup_dest = raiz / "var" / "backups" / "revoked_ssh_keys"
                backup_dest.mkdir(parents=True, exist_ok=True)
                dest_file = backup_dest / ("%s_authorized_keys_%s" % (user, sessao.id if sessao else "bkp"))
                try:
                    shutil.move(str(auth_keys), str(dest_file))
                    relatorio["mudancas"].append("chave SSH de '%s' arquivada em %s" % (user, dest_file))
                except OSError as e:
                    relatorio["falhas"].append({"conta": user, "acao": "arquivar authorized_keys", "mensagem": str(e), "erro": str(e)})

        # 4. Remover do grupo wheel se for membro
        if plano["precisa_wheel"]:
            desc_wheel = "Remover '%s' do grupo administrativo wheel" % user
            if not aplicar:
                relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_wheel)
            else:
                r_w = runner.executar(["gpasswd", "-d", user, "wheel"])
                if r_w.ok:
                    relatorio["mudancas"].append("'%s' removido do grupo wheel" % user)
                else:
                    msg = (r_w.erro or r_w.saida).strip()
                    relatorio["falhas"].append({"conta": user, "acao": "gpasswd -d wheel", "mensagem": msg, "erro": msg})

        # 5. Encerrar sessões ativas (loginctl terminate-user, fallback para pkill -9 -u)
        desc_kill = "Encerrar sessões ativas de '%s' (loginctl terminate-user / pkill)" % user
        if not aplicar:
            relatorio["acoes"].append("[SERIA_CORRIGIDO] %s" % desc_kill)
        else:
            r_login = runner.executar(["loginctl", "terminate-user", user])
            if r_login.ok:
                relatorio["mudancas"].append("sessões ativas de '%s' finalizadas via loginctl" % user)
            else:
                r_pkill = runner.executar(["pkill", "-9", "-u", user])
                if r_pkill.ok:
                    relatorio["mudancas"].append("sessões ativas de '%s' finalizadas via pkill" % user)
                else:
                    msg = (r_pkill.erro or r_pkill.saida).strip()
                    relatorio["falhas"].append({"conta": user, "acao": "encerrar sessões", "mensagem": msg, "erro": msg})

    if aplicar and sessao and relatorio["mudancas"]:
        relatorio["sessao_backup"] = sessao.id
        relatorio["acoes"].append("Sessão de backup gravada em %s/backups/%s" % (estado_dir, sessao.id))

    return relatorio


def avaliar_offboarding(
    caminho_csv: Path,
    raiz: Path = Path("/"),
    runner: Optional[Runner] = None,
) -> List[Resultado]:
    """Avaliação em modo somente leitura da conformidade de offboarding (OFF-001 a OFF-008).

    Verifica o estado atual das contas locais e do sistema sem aplicar nenhuma modificação.

    Parâmetros:
        caminho_csv: Caminho para o arquivo CSV com a lista de usuários autorizados.
        raiz: Prefixo de raiz do sistema de arquivos (padrão: Path("/")).
        runner: Instância de Runner para execução isolada de comandos (padrão: None).

    Retorna:
        Lista de objetos Resultado (hardener.models) correspondentes a OFF-001 a OFF-008.
    """
    runner = runner or Runner()
    autorizados = carregar_autorizados_csv(caminho_csv)
    locais = listar_usuarios_locais(raiz)
    contas_nao_autorizadas = [u for u in locais if u["username"] not in autorizados]
    shadow_data = _carregar_shadow(raiz)

    pendentes_lock: List[str] = []
    pendentes_shell: List[str] = []
    pendentes_keys: List[str] = []
    pendentes_wheel: List[str] = []

    for conta in contas_nao_autorizadas:
        user = conta["username"]
        home = Path(conta["home"])

        sh_info = shadow_data.get(user)
        bloqueada = sh_info["bloqueada"] if sh_info is not None else False
        expirada = sh_info["expirada"] if sh_info is not None else False

        if not bloqueada or not expirada:
            pendentes_lock.append(user)

        if conta["shell"] not in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false"):
            pendentes_shell.append(user)

        auth_keys = raiz / home.as_posix().lstrip("/") / ".ssh" / "authorized_keys"
        if auth_keys.exists():
            pendentes_keys.append(user)

        if _usuario_no_grupo(raiz, "wheel", user):
            pendentes_wheel.append(user)

    resultados: List[Resultado] = []

    # OFF-001: Bloqueio usermod -L / chage -E 0
    r_off1 = Regra(
        id="OFF-001",
        descricao="Contas locais fora da lista bloqueadas (usermod -L, chage -E 0)",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="alta",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    if not pendentes_lock:
        res1 = Resultado(r_off1, Status.CONFORME, detalhe="todas as contas não autorizadas estão bloqueadas e expiradas")
    else:
        res1 = Resultado(
            r_off1,
            Status.NAO_CONFORME,
            atual=", ".join(pendentes_lock),
            esperado="nenhuma conta pendente",
            detalhe="contas pendentes de usermod -L / chage -E 0: %s" % ", ".join(pendentes_lock),
        )
    resultados.append(res1)

    # OFF-002: Shell nologin
    r_off2 = Regra(
        id="OFF-002",
        descricao="Shell nologin nas contas bloqueadas",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="alta",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    if not pendentes_shell:
        res2 = Resultado(r_off2, Status.CONFORME, detalhe="todas as contas não autorizadas possuem shell nologin")
    else:
        res2 = Resultado(
            r_off2,
            Status.NAO_CONFORME,
            atual=", ".join(pendentes_shell),
            esperado="nenhuma conta pendente",
            detalhe="contas com shell interativo pendentes de alteração para nologin: %s" % ", ".join(pendentes_shell),
        )
    resultados.append(res2)

    # OFF-003: authorized_keys arquivado
    r_off3 = Regra(
        id="OFF-003",
        descricao="authorized_keys das contas bloqueadas arquivado",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="alta",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    if not pendentes_keys:
        res3 = Resultado(r_off3, Status.CONFORME, detalhe="nenhuma chave SSH authorized_keys ativa encontrada para contas não autorizadas")
    else:
        res3 = Resultado(
            r_off3,
            Status.NAO_CONFORME,
            atual=", ".join(pendentes_keys),
            esperado="nenhuma conta pendente",
            detalhe="chaves authorized_keys ativas encontradas para: %s" % ", ".join(pendentes_keys),
        )
    resultados.append(res3)

    # OFF-004: Removido de wheel
    r_off4 = Regra(
        id="OFF-004",
        descricao="Contas não autorizadas removidas do grupo administrativo wheel",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="critica",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    if not pendentes_wheel:
        res4 = Resultado(r_off4, Status.CONFORME, detalhe="nenhuma conta não autorizada pertence ao grupo wheel")
    else:
        res4 = Resultado(
            r_off4,
            Status.NAO_CONFORME,
            atual=", ".join(pendentes_wheel),
            esperado="nenhuma conta no grupo",
            detalhe="contas não autorizadas no grupo wheel: %s" % ", ".join(pendentes_wheel),
        )
    resultados.append(res4)

    # OFF-005: Sessões ativas
    r_off5 = Regra(
        id="OFF-005",
        descricao="Nenhuma sessão ativa de contas não autorizadas no sistema",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="alta",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    r_sess = runner.executar(["loginctl", "list-sessions", "--no-legend"])
    if not r_sess.ok:
        res5 = Resultado(
            r_off5,
            Status.ERRO,
            detalhe="falha ao consultar sessões ativas via loginctl: %s" % (r_sess.erro or r_sess.saida).strip(),
        )
    else:
        sessoes_inseguras: List[str] = []
        nao_aut_set = {u["username"] for u in contas_nao_autorizadas}
        for linha in r_sess.saida.splitlines():
            partes = linha.strip().split()
            if len(partes) >= 3:
                sess_user = partes[2]
                if sess_user in nao_aut_set:
                    sessoes_inseguras.append(sess_user)
        if not sessoes_inseguras:
            res5 = Resultado(r_off5, Status.CONFORME, detalhe="nenhuma sessão ativa de contas não autorizadas")
        else:
            res5 = Resultado(
                r_off5,
                Status.NAO_CONFORME,
                atual=", ".join(sorted(set(sessoes_inseguras))),
                esperado="nenhuma sessão ativa",
                detalhe="sessões ativas detectadas para: %s" % ", ".join(sorted(set(sessoes_inseguras))),
            )
    resultados.append(res5)

    # OFF-006: Contas inativas (somente auditoria)
    r_off6 = Regra(
        id="OFF-006",
        descricao="Auditoria de contas regulares inativas há mais de 90 dias",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="media",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    r_off6.somente_auditoria = True
    r_off6.parametros["somente_auditoria"] = True
    achados_inativos = relatorio_contas_inativas(raiz, runner, dias_inativos=90)
    if not achados_inativos:
        res6 = Resultado(r_off6, Status.CONFORME, detalhe="nenhuma conta regular inativa há mais de 90 dias")
    else:
        users = [a["usuario"] for a in achados_inativos]
        res6 = Resultado(
            r_off6,
            Status.NAO_CONFORME,
            atual=", ".join(users),
            esperado="nenhuma conta inativa",
            detalhe="%d conta(s) inativa(s) ou que nunca logaram: %s" % (len(users), ", ".join(users)),
        )
    resultados.append(res6)

    # OFF-007: Senhas sem expiração (somente auditoria)
    r_off7 = Regra(
        id="OFF-007",
        descricao="Auditoria de contas com senha sem expiração máxima definida",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="media",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    r_off7.somente_auditoria = True
    r_off7.parametros["somente_auditoria"] = True
    achados_sem_exp = relatorio_senhas_sem_expiracao(raiz)
    if not achados_sem_exp:
        res7 = Resultado(r_off7, Status.CONFORME, detalhe="todas as contas com senha ativa possuem expiração definida")
    else:
        users = [a["usuario"] for a in achados_sem_exp]
        res7 = Resultado(
            r_off7,
            Status.NAO_CONFORME,
            atual=", ".join(users),
            esperado="todas as contas com expiração",
            detalhe="%d conta(s) com senha sem expiração (99999 ou vazia): %s" % (len(users), ", ".join(users)),
        )
    resultados.append(res7)

    # OFF-008: Chaves SSH sem dono (somente auditoria)
    r_off8 = Regra(
        id="OFF-008",
        descricao="Auditoria de chaves SSH sem dono ou pertencentes a contas inválidas",
        referencia="Requisito ATI - Trilha B Offboarding",
        dor_ati=[5],
        severidade="alta",
        plataforma="rhel9",
        primitiva="offboarding",
    )
    r_off8.somente_auditoria = True
    r_off8.parametros["somente_auditoria"] = True
    achados_chaves = relatorio_chaves_ssh_sem_dono(raiz)
    if not achados_chaves:
        res8 = Resultado(r_off8, Status.CONFORME, detalhe="nenhuma chave SSH sem dono ou inválida encontrada")
    else:
        descricoes = ["%s (%s)" % (a["usuario"], a["motivo"]) for a in achados_chaves]
        res8 = Resultado(
            r_off8,
            Status.NAO_CONFORME,
            atual="%d chaves inválidas" % len(achados_chaves),
            esperado="nenhuma chave inválida",
            detalhe="%d chave(s) SSH sem dono ou inválida(s): %s" % (len(achados_chaves), "; ".join(descricoes)),
        )
    resultados.append(res8)

    return resultados


def aplicar_offboarding(
    caminho_csv: Path,
    raiz: Path = Path("/"),
    estado_dir: Path = Path("/var/lib/hardener"),
    runner: Optional[Runner] = None,
) -> List[Resultado]:
    """Aplica as correções de revogação de acessos para contas não autorizadas.

    Executa o offboarding com validação de segurança e devolve a lista de Resultados.
    Regras OFF-006 a OFF-008 são somente de auditoria e nunca são corrigidas.

    Parâmetros:
        caminho_csv: Caminho para o arquivo CSV de contas autorizadas.
        raiz: Prefixo de raiz do sistema de arquivos (padrão: Path("/")).
        estado_dir: Diretório de persistência de estado e backups (padrão: Path("/var/lib/hardener")).
        runner: Instância de Runner para execução de comandos (padrão: None).

    Retorna:
        Lista de objetos Resultado com status CORRIGIDO, FALHOU ou CONFORME.
    """
    runner = runner or Runner()

    # Guarda: valida operador no SUDO_USER
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user is not None and sudo_user.strip():
        autorizados = carregar_autorizados_csv(caminho_csv)
        operador = sudo_user.strip().lower()
        if operador != "root" and operador not in autorizados:
            raise ErroOffboarding(
                "Usuário executor '%s' (SUDO_USER) não consta na lista de autorizados. "
                "Operação abortada para evitar lockout acidental do operador." % sudo_user
            )

    relatorio = executar_offboarding(
        caminho_csv=caminho_csv,
        raiz=raiz,
        estado_dir=estado_dir,
        aplicar=True,
        runner=runner,
    )

    mudancas = relatorio.get("mudancas", [])
    falhas = relatorio.get("falhas", [])

    resultados: List[Resultado] = []

    # OFF-001: usermod -L e chage -E 0
    mudancas_off1 = [m for m in mudancas if "usermod -L" in m or "chage -E 0" in m]
    falhas_off1 = [f for f in falhas if f["acao"] in ("usermod -L", "chage -E 0")]
    r_off1 = Regra("OFF-001", "Contas locais fora da lista bloqueadas (usermod -L, chage -E 0)", "Requisito ATI - Trilha B Offboarding", [5], "alta", "rhel9", "offboarding")
    if falhas_off1:
        res1 = Resultado(r_off1, Status.FALHOU, mudancas=mudancas_off1, detalhe="falha ao bloquear contas: %s" % falhas_off1[0]["erro"])
    elif mudancas_off1:
        res1 = Resultado(r_off1, Status.CORRIGIDO, mudancas=mudancas_off1, detalhe="contas bloqueadas e expiradas com sucesso")
    else:
        res1 = Resultado(r_off1, Status.CONFORME, detalhe="todas as contas já se encontram bloqueadas e expiradas")
    resultados.append(res1)

    # OFF-002: usermod -s /sbin/nologin
    mudancas_off2 = [m for m in mudancas if "shell" in m and "nologin" in m]
    falhas_off2 = [f for f in falhas if "nologin" in f["acao"]]
    r_off2 = Regra("OFF-002", "Shell nologin nas contas bloqueadas", "Requisito ATI - Trilha B Offboarding", [5], "alta", "rhel9", "offboarding")
    if falhas_off2:
        res2 = Resultado(r_off2, Status.FALHOU, mudancas=mudancas_off2, detalhe="falha ao alterar shell: %s" % falhas_off2[0]["erro"])
    elif mudancas_off2:
        res2 = Resultado(r_off2, Status.CORRIGIDO, mudancas=mudancas_off2, detalhe="shell alterado para /sbin/nologin")
    else:
        res2 = Resultado(r_off2, Status.CONFORME, detalhe="todas as contas já possuem shell nologin")
    resultados.append(res2)

    # OFF-003: authorized_keys arquivado
    mudancas_off3 = [m for m in mudancas if "chave SSH" in m and "arquivada" in m]
    falhas_off3 = [f for f in falhas if "authorized_keys" in f["acao"]]
    r_off3 = Regra("OFF-003", "authorized_keys das contas bloqueadas arquivado", "Requisito ATI - Trilha B Offboarding", [5], "alta", "rhel9", "offboarding")
    if falhas_off3:
        res3 = Resultado(r_off3, Status.FALHOU, mudancas=mudancas_off3, detalhe="falha ao arquivar authorized_keys: %s" % falhas_off3[0]["erro"])
    elif mudancas_off3:
        res3 = Resultado(r_off3, Status.CORRIGIDO, mudancas=mudancas_off3, detalhe="chaves authorized_keys arquivadas")
    else:
        res3 = Resultado(r_off3, Status.CONFORME, detalhe="nenhuma chave authorized_keys ativa encontrada")
    resultados.append(res3)

    # OFF-004: gpasswd -d wheel
    mudancas_off4 = [m for m in mudancas if "removido do grupo wheel" in m]
    falhas_off4 = [f for f in falhas if "wheel" in f["acao"]]
    r_off4 = Regra("OFF-004", "Contas não autorizadas removidas do grupo administrativo wheel", "Requisito ATI - Trilha B Offboarding", [5], "critica", "rhel9", "offboarding")
    if falhas_off4:
        res4 = Resultado(r_off4, Status.FALHOU, mudancas=mudancas_off4, detalhe="falha ao remover do wheel: %s" % falhas_off4[0]["erro"])
    elif mudancas_off4:
        res4 = Resultado(r_off4, Status.CORRIGIDO, mudancas=mudancas_off4, detalhe="contas removidas do grupo wheel")
    else:
        res4 = Resultado(r_off4, Status.CONFORME, detalhe="nenhuma conta não autorizada no grupo wheel")
    resultados.append(res4)

    # OFF-005: Sessões finalizadas
    mudancas_off5 = [m for m in mudancas if "finalizadas via" in m]
    falhas_off5 = [f for f in falhas if "sessões" in f["acao"]]
    r_off5 = Regra("OFF-005", "Nenhuma sessão ativa de contas não autorizadas no sistema", "Requisito ATI - Trilha B Offboarding", [5], "alta", "rhel9", "offboarding")
    if falhas_off5:
        res5 = Resultado(r_off5, Status.FALHOU, mudancas=mudancas_off5, detalhe="falha ao encerrar sessões: %s" % falhas_off5[0]["erro"])
    elif mudancas_off5:
        res5 = Resultado(r_off5, Status.CORRIGIDO, mudancas=mudancas_off5, detalhe="sessões ativas encerradas")
    else:
        res5 = Resultado(r_off5, Status.CONFORME, detalhe="nenhuma sessão ativa pendente")
    resultados.append(res5)

    # OFF-006 a OFF-008: nunca são corrigidos, retornam o estado de auditoria
    audit_res = avaliar_offboarding(caminho_csv, raiz=raiz, runner=runner)
    for r in audit_res[5:]:
        resultados.append(r)

    return resultados

