"""Fixtures compartilhadas para testes unitários com pytest."""

from pathlib import Path
import pytest

from hardener.runner import ResultadoComando, Runner

OS_RELEASE_RHEL9 = 'ID="rhel"\nVERSION_ID="9.4"\n'


class FakeRunner(Runner):
    """Simulador de execução de comandos para testes sem root nem sistema real."""

    def __init__(self, raiz: Path):
        self.raiz = raiz
        self.chamadas = []
        self.respostas = {}

    def executar(self, comando, timeout=30):
        cmd = list(comando)
        self.chamadas.append(cmd)
        key = " ".join(cmd)
        if key in self.respostas:
            return self.respostas[key]
        return ResultadoComando(0, "")

    def chamou(self, *comando):
        return list(comando) in self.chamadas


@pytest.fixture
def raiz(tmp_path):
    r = tmp_path / "root"
    r.mkdir(parents=True)
    etc = r / "etc"
    etc.mkdir(parents=True)
    (etc / "os-release").write_text(OS_RELEASE_RHEL9, encoding="utf-8")
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin_ati:x:1000:1000:Admin ATI:/home/admin_ati:/bin/bash\n"
        "ex_funcionario:x:1001:1001:Ex Funcionario:/home/ex_funcionario:/bin/bash\n"
        "estagiario:x:1002:1002:Estagiario Temp:/home/estagiario:/bin/bash\n",
        encoding="utf-8"
    )
    (etc / "group").write_text(
        "root:x:0:\n"
        "wheel:x:10:root,admin_ati,ex_funcionario\n",
        encoding="utf-8"
    )
    return r


@pytest.fixture
def estado(tmp_path):
    d = tmp_path / "estado"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def runner(raiz):
    return FakeRunner(raiz)


@pytest.fixture
def csv_autorizados(tmp_path):
    c = tmp_path / "autorizados.csv"
    c.write_text("usuario,departamento\nroot,SecOps\nadmin_ati,TI\n", encoding="utf-8")
    return c
