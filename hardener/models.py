"""Tipos de dados compartilhados entre os módulos (parte do contrato)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # evita import circular
    from hardener.backup import GerenciadorBackup, SessaoBackup
    from hardener.runner import Runner

SEVERIDADES = ("baixa", "media", "alta", "critica")
DORES_ATI = (1, 2, 3, 4, 5, 6)


class Status:
    """Estados possíveis de uma regra no relatório."""

    CONFORME = "CONFORME"
    NAO_CONFORME = "NAO_CONFORME"
    SERIA_CORRIGIDO = "SERIA_CORRIGIDO"  # enforce --dry-run
    CORRIGIDO = "CORRIGIDO"  # enforce --apply, corrigido e reverificado
    FALHOU = "FALHOU"  # tentou corrigir e não ficou conforme (ou foi revertido)
    PULADO = "PULADO"  # regra de outra plataforma
    ERRO = "ERRO"  # não foi possível verificar


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
    origem: str = ""  # arquivo YAML de onde veio (só para mensagens de erro)


@dataclass
class Verificacao:
    """Resposta de uma primitiva ao verificar uma regra."""

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
    """A primitiva não conseguiu verificar/corrigir (vira status ERRO/FALHOU)."""


@dataclass
class Contexto:
    """O que toda primitiva recebe. Toda E/S passa por aqui para ser testável."""

    runner: "Runner"
    raiz: Path = Path("/")  # prefixo de caminhos; os testes usam um diretório temporário
    gerenciador: Optional["GerenciadorBackup"] = None
    regra: Optional[Regra] = None  # regra em execução (preenchida pelo motor)
    _sessao: Optional["SessaoBackup"] = None

    def caminho(self, logico: str) -> Path:
        """Converte '/etc/ssh/x' em <raiz>/etc/ssh/x."""
        return self.raiz / logico.lstrip("/")

    def sessao(self) -> "SessaoBackup":
        """Sessão de backup da execução atual (criada só na primeira alteração)."""
        if self._sessao is None:
            if self.gerenciador is None:
                raise ErroPrimitiva("sem gerenciador de backup: não é seguro alterar arquivos")
            self._sessao = self.gerenciador.nova_sessao()
        return self._sessao

    def sessao_criada(self) -> Optional["SessaoBackup"]:
        return self._sessao

    def salvar_antes_de_alterar(self, logico: str) -> None:
        """Faz backup de um arquivo ANTES de a primitiva mexer nele."""
        servico = self.regra.recarregar if self.regra else None
        regra_id = self.regra.id if self.regra else "?"
        self.sessao().salvar_arquivo(regra_id, logico, self.caminho(logico), servico)
