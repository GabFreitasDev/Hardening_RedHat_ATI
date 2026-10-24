"""Fixtures compartilhadas. Nada aqui toca o sistema real: usa diretório temporário e runner falso."""

from pathlib import Path

import pytest

from hardener.runner import ResultadoComando, Runner

OS_RELEASE_RHEL9 = 'ID="rhel"\nVERSION_ID="9.4"\n'
DROPIN = "etc/ssh/sshd_config.d/00-hardener.conf"


class FakeRunner(Runner):
    """Simula `sshd -T`, `sshd -t` e `systemctl reload` sobre um diretório-raiz temporário."""

    def __init__(self, raiz: Path):
        self.raiz = raiz
        self.chamadas = []
        self.padroes = {"permitrootlogin": "yes", "passwordauthentication": "yes"}
        self.sshd_t_rc = 0
        self.reload_rc = 0

    def _efetivo(self):
        valores = dict(self.padroes)
        arq = self.raiz / DROPIN
        if arq.exists():
            vistos = set()
            for linha in arq.read_text(encoding="utf-8").splitlines():
                partes = linha.split(None, 1)
                if len(partes) == 2 and not linha.startswith("#"):
                    k = partes[0].lower()
                    if k not in vistos:  # primeiro valor vence, como no sshd
                        valores[k] = partes[1].strip().lower()
                        vistos.add(k)
        return valores

    def executar(self, comando, timeout=30):
        comando = list(comando)
        self.chamadas.append(comando)
        if comando == ["sshd", "-T"]:
            return ResultadoComando(0, "".join("%s %s\n" % kv for kv in self._efetivo().items()))
        if comando == ["sshd", "-t"]:
            return ResultadoComando(self.sshd_t_rc, "", "erro de sintaxe simulado" if self.sshd_t_rc else "")
        if comando[:2] == ["systemctl", "reload"]:
            return ResultadoComando(self.reload_rc, "", "falha simulada" if self.reload_rc else "")
        return ResultadoComando(127, "", "comando não simulado: %s" % comando)

    def chamou(self, *comando):
        return list(comando) in self.chamadas


@pytest.fixture
def raiz(tmp_path):
    r = tmp_path / "root"
    (r / "etc").mkdir(parents=True)
    (r / "etc" / "os-release").write_text(OS_RELEASE_RHEL9, encoding="utf-8")
    return r


@pytest.fixture
def estado(tmp_path):
    return tmp_path / "estado"


@pytest.fixture
def runner(raiz):
    return FakeRunner(raiz)
