"""Tipos de dados compartilhados entre os módulos (parte do contrato)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from hardener.backup import GerenciadorBackup, SessaoBackup
    from hardener.runner import Runner

SEVERIDADES = ("baixa", "media", "alta", "critica")
DORES_ATI = (1, 2, 3, 4, 5, 6)


class Status:
    CONFORME = "CONFORME"
    NAO_CONFORME = "NAO_CONFORME"
    SERIA_CORRIGIDO = "SERIA_CORRIGIDO"
    CORRIGIDO = "CORRIGIDO"
    FALHOU = "FALHOU"
    PULADO = "PULADO"
    ERRO = "ERRO"


@dataclass
class Regra:
    id: str
    descricao: str
    referencia: str
    dor_ati: List[int]
    severidade: str
    plataforma: str
    primitiva: str
    parametros: Dict[str, Any] = field(default_factory=dict)
    recarregar: Optional[str] = None
    origem: str = ""


@dataclass
class Verificacao:
    conforme: bool
    atual: Optional[str] = None
    esperado: Optional[str] = None
    detalhe: str = ""


@dataclass
class Resultado:
    regra: Regra
    status: str
    atual: Optional[str] = None
    esperado: Optional[str] = None
    detalhe: str = ""
    mudancas: List[str] = field(default_factory=list)


class ErroPrimitiva(Exception):
    pass


@dataclass
class Contexto:
    runner: "Runner"
    raiz: Path = Path("/")
    gerenciador: Optional["GerenciadorBackup"] = None
    regra: Optional[Regra] = None
    _sessao: Optional["SessaoBackup"] = None

    def caminho(self, logico: str) -> Path:
        return self.raiz / logico.lstrip("/")

    def sessao(self) -> "SessaoBackup":
        if self._sessao is None:
            if self.gerenciador is None:
                raise ErroPrimitiva("sem gerenciador de backup: não é seguro alterar arquivos")
            self._sessao = self.gerenciador.nova_sessao()
        return self._sessao

    def sessao_criada(self) -> Optional["SessaoBackup"]:
        return self._sessao

    def salvar_antes_de_alterar(self, logico: str) -> None:
        servico = self.regra.recarregar if self.regra else None
        regra_id = self.regra.id if self.regra else "?"
        self.sessao().salvar_arquivo(regra_id, logico, self.caminho(logico), servico)
