"""Testes unitários para as funções de relatório de contas (OFF-006, OFF-007, OFF-008)."""

import os
from pathlib import Path
import pytest

from hardener.cli import main
from hardener.relatorios_contas import (
    relatorio_chaves_ssh_sem_dono,
    relatorio_contas_inativas,
    relatorio_senhas_sem_expiracao,
)
from hardener.runner import ResultadoComando


def test_relatorio_contas_inativas_detecta_caso_e_evita_falso_positivo(tmp_path, runner):
    """Testa detecção de conta inativa e nunca logada, sem falso positivo para saudável."""
    raiz = tmp_path / "raiz"
    raiz.mkdir(parents=True)
    etc = raiz / "etc"
    etc.mkdir(parents=True)

    # root (UID 0) deve ser ignorado
    # ativo (UID 1000) saudável - logou recentemente
    # inativo (UID 1001) inativo há mais de 90 dias
    # nunca (UID 1002) nunca logou
    # nobody (UID 65534) sistema ignorado
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "ativo:x:1000:1000:Usuario Ativo:/home/ativo:/bin/bash\n"
        "inativo:x:1001:1001:Usuario Inativo:/home/inativo:/bin/bash\n"
        "nunca:x:1002:1002:Novo Funcionario:/home/nunca:/bin/bash\n"
        "nobody:x:65534:65534:Nobody:/nonexistent:/sbin/nologin\n",
        encoding="utf-8"
    )

    # Mock do comando lastlog -b 90
    # Usuário 'ativo' NÃO consta na saída do -b 90 porque logou há 2 dias
    runner.respostas["lastlog -b 90"] = ResultadoComando(
        0,
        "Username         Port     From             Latest\n"
        "inativo          pts/0    192.168.1.50     Mon Jan 15 10:00:00 -0300 2024\n"
        "nunca                                      **Never logged in**\n"
    )

    achados = relatorio_contas_inativas(raiz, runner, dias_inativos=90)
    usuarios_achados = {a["usuario"]: a["motivo"] for a in achados}

    # Verifica que saudável, root e nobody não geram falso positivo
    assert "ativo" not in usuarios_achados
    assert "root" not in usuarios_achados
    assert "nobody" not in usuarios_achados

    # Verifica que inativo e nunca logado foram detectados
    assert "nunca" in usuarios_achados
    assert usuarios_achados["nunca"] == "nunca logou"

    assert "inativo" in usuarios_achados
    assert "inativo há mais de 90 dias" in usuarios_achados["inativo"]
    assert "2024" in usuarios_achados["inativo"]


def test_relatorio_contas_inativas_com_lastlog_completo(tmp_path, runner):
    """Testa suporte ao comando lastlog sem a flag -b, avaliando datas e 'nunca logou'."""
    raiz = tmp_path / "raiz"
    raiz.mkdir(parents=True)
    etc = raiz / "etc"
    etc.mkdir(parents=True)

    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "ativo:x:1000:1000:Usuario Ativo:/home/ativo:/bin/bash\n"
        "antigo:x:1001:1001:Usuario Antigo:/home/antigo:/bin/bash\n"
        "sem_login:x:1002:1002:Sem Login:/home/sem_login:/bin/bash\n",
        encoding="utf-8"
    )

    runner.respostas["lastlog"] = ResultadoComando(
        0,
        "Username         Port     From             Latest\n"
        "ativo            pts/0    10.0.0.1         Sun Oct 25 10:00:00 2026\n"
        "antigo           pts/1    10.0.0.2         Mon Jan 01 10:00:00 2020\n"
        "sem_login                                 **Nunca fez login**\n"
    )

    achados = relatorio_contas_inativas(raiz, runner, dias_inativos=90)
    usuarios = {a["usuario"]: a["motivo"] for a in achados}

    assert "ativo" not in usuarios
    assert "sem_login" in usuarios
    assert usuarios["sem_login"] == "nunca logou"
    assert "antigo" in usuarios
    assert "inativo há mais de 90 dias" in usuarios["antigo"]


def test_relatorio_senhas_sem_expiracao_detecta_caso_e_evita_falso_positivo(tmp_path):
    """Testa OFF-007: detecta senhas com hash real sem expiração (99999 ou vazio) sem falso positivo."""
    raiz = tmp_path / "raiz"
    raiz.mkdir(parents=True)
    etc = raiz / "etc"
    etc.mkdir(parents=True)

    # Formato shadow: login:password:last:min:max:warn:inact:expire:flag
    (etc / "shadow").write_text(
        # Contas com ! ou * são bloqueadas/sem senha -> NÃO reportar
        "root:*LK*:19000:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n"
        "bloqueada:!$6$saltsalt$hash:19000:0:99999:7:::\n"
        # Conta com hash real e validade máxima de 60 dias -> SAUDÁVEL (NÃO reportar)
        "saudavel:$6$saltsalt$hashsaudavel:19000:0:60:7:::\n"
        # Contas com hash real e campo 5 igual a 99999 ou vazio -> DEVE REPORTAR
        "usuario_99999:$6$saltsalt$hash99999:19000:0:99999:7:::\n"
        "usuario_vazio:$6$saltsalt$hashvazio:19000:0::7:::\n",
        encoding="utf-8"
    )

    achados = relatorio_senhas_sem_expiracao(raiz)
    usuarios_reportados = {a["usuario"]: a["motivo"] for a in achados}

    # Saudáveis e bloqueadas não devem gerar falso positivo
    assert "saudavel" not in usuarios_reportados
    assert "root" not in usuarios_reportados
    assert "daemon" not in usuarios_reportados
    assert "bloqueada" not in usuarios_reportados

    # Casos sem expiração devem ser detectados
    assert "usuario_99999" in usuarios_reportados
    assert "99999" in usuarios_reportados["usuario_99999"]

    assert "usuario_vazio" in usuarios_reportados
    assert "vazio" in usuarios_reportados["usuario_vazio"] or "vazia" in usuarios_reportados["usuario_vazio"]


def test_relatorio_chaves_ssh_sem_dono_detecta_caso_e_evita_falso_positivo(tmp_path, monkeypatch):
    """Testa OFF-008: chaves com UID inexistente no passwd, conta bloqueada ou shell nologin."""
    raiz = tmp_path / "raiz"
    raiz.mkdir(parents=True)
    etc = raiz / "etc"
    etc.mkdir(parents=True)

    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "dev:x:1000:1000:Desenvolvedor:/home/dev:/bin/bash\n"
        "bloqueado:x:1001:1001:Bloqueado:/home/bloqueado:/bin/bash\n"
        "servico:x:1002:1002:Servico:/home/servico:/sbin/nologin\n",
        encoding="utf-8"
    )

    (etc / "shadow").write_text(
        "root:$6$root:19000:0:90:7:::\n"
        "dev:$6$dev:19000:0:90:7:::\n"
        "bloqueado:!$6$bloqueado:19000:0:90:7:::\n"
        "servico:*LK*:19000:0:90:7:::\n",
        encoding="utf-8"
    )

    # Cria diretórios e arquivos authorized_keys
    root_ssh = raiz / "root" / ".ssh"
    root_ssh.mkdir(parents=True)
    root_key = root_ssh / "authorized_keys"
    root_key.write_text("ssh-rsa AAAAB3... root@server\n", encoding="utf-8")

    dev_ssh = raiz / "home" / "dev" / ".ssh"
    dev_ssh.mkdir(parents=True)
    dev_key = dev_ssh / "authorized_keys"
    dev_key.write_text("ssh-rsa AAAAB3... dev@workstation\n", encoding="utf-8")

    bloq_ssh = raiz / "home" / "bloqueado" / ".ssh"
    bloq_ssh.mkdir(parents=True)
    bloq_key = bloq_ssh / "authorized_keys"
    bloq_key.write_text("ssh-rsa AAAAB3... bloq@laptop\n", encoding="utf-8")

    serv_ssh = raiz / "home" / "servico" / ".ssh"
    serv_ssh.mkdir(parents=True)
    serv_key = serv_ssh / "authorized_keys"
    serv_key.write_text("ssh-rsa AAAAB3... servico@ci\n", encoding="utf-8")

    orfao_ssh = raiz / "home" / "ex_usuario_orfao" / ".ssh"
    orfao_ssh.mkdir(parents=True)
    orfao_key = orfao_ssh / "authorized_keys"
    orfao_key.write_text("ssh-rsa AAAAB3... orfao@antigo\n", encoding="utf-8")

    # Ajusta UIDs dos arquivos
    # root_key -> UID 0
    # dev_key -> UID 1000
    # bloq_key -> UID 1001
    # serv_key -> UID 1002
    # orfao_key -> UID 9999 (não existe no /etc/passwd)
    uids_map = {
        str(root_key): 0,
        str(dev_key): 1000,
        str(bloq_key): 1001,
        str(serv_key): 1002,
        str(orfao_key): 9999,
    }

    try:
        os.chown(str(root_key), 0, 0)
        os.chown(str(dev_key), 1000, 1000)
        os.chown(str(bloq_key), 1001, 1001)
        os.chown(str(serv_key), 1002, 1002)
        os.chown(str(orfao_key), 9999, 9999)
    except PermissionError:
        # Fallback portátil caso o teste rode em ambiente não-root
        original_stat = Path.stat
        def fake_stat(self, *args, **kwargs):
            st = original_stat(self, *args, **kwargs)
            s_path = str(self)
            if s_path in uids_map:
                import collections
                MockStat = collections.namedtuple(
                    "MockStat",
                    ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime"]
                )
                return MockStat(st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uids_map[s_path], uids_map[s_path], st.st_size, st.st_atime, st.st_mtime, st.st_ctime)
            return st
        monkeypatch.setattr(Path, "stat", fake_stat)

    achados = relatorio_chaves_ssh_sem_dono(raiz)
    usuarios_reportados = {a["usuario"]: a["motivo"] for a in achados}

    # root e dev são contas saudáveis -> NÃO geram achado
    assert "root" not in usuarios_reportados
    assert "dev" not in usuarios_reportados

    # bloqueado deve ser detectado
    assert "bloqueado" in usuarios_reportados
    assert "conta bloqueada" in usuarios_reportados["bloqueado"]

    # servico tem shell nologin -> deve ser detectado
    assert "servico" in usuarios_reportados
    assert "nologin" in usuarios_reportados["servico"]

    # orfao tem UID 9999 inexistente no passwd -> deve ser detectado
    assert ("ex_usuario_orfao" in usuarios_reportados or "9999" in usuarios_reportados)
    orfao_motivo = usuarios_reportados.get("ex_usuario_orfao") or usuarios_reportados.get("9999")
    assert "não existe" in orfao_motivo


def test_offboarding_cli_exibe_bloco_relatorios(tmp_path, runner, capsys):
    """Testa se o comando offboarding na CLI exibe a seção Relatórios com os 3 itens."""
    raiz = tmp_path / "raiz"
    raiz.mkdir(parents=True)
    etc = raiz / "etc"
    etc.mkdir(parents=True)

    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin_ati:x:1000:1000:Admin:/home/admin_ati:/bin/bash\n",
        encoding="utf-8"
    )
    (etc / "shadow").write_text(
        "root:*LK*:19000:0:99999:7:::\n"
        "admin_ati:$6$salt$hash:19000:0:99999:7:::\n",
        encoding="utf-8"
    )

    csv_arq = tmp_path / "lista.csv"
    csv_arq.write_text("usuario,departamento\nroot,TI\nadmin_ati,TI\n", encoding="utf-8")

    runner.respostas["lastlog -b 90"] = ResultadoComando(0, "")

    rc = main(
        ["offboarding", "--autorizados", str(csv_arq), "--raiz", str(raiz), "--estado-dir", str(tmp_path / "estado")],
        runner=runner,
    )

    assert rc == 0
    saida = capsys.readouterr().out
    assert "Relatórios:" in saida
    assert "Contas inativas (OFF-006):" in saida
    assert "Senhas sem expiração (OFF-007):" in saida
    assert "Chaves SSH sem dono (OFF-008):" in saida
    # admin_ati tem senha sem expiração (99999)
    assert "admin_ati" in saida
