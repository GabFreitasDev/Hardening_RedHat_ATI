"""Backup antes de alterar e rollback.

Cada execução de `enforce --apply` que altera algo cria UMA sessão em
<estado_dir>/backups/<id>/ com:
  manifest.json   -> o que foi salvo (gravado a cada arquivo, resiste a falhas no meio)
  arquivos/NNNN   -> cópia do conteúdo original

Rollback restaura os arquivos (ou apaga os que não existiam) em ordem inversa.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class ErroBackup(Exception):
    pass


class SessaoBackup:
    def __init__(self, diretorio: Path, raiz: Path):
        self.diretorio = diretorio
        self.raiz = raiz
        self.id = diretorio.name
        self.entradas: List[Dict[str, Any]] = []
        self.revertida = False

    # -- gravação -------------------------------------------------------
    def salvar_arquivo(
        self, regra_id: str, logico: str, real: Path, servico: Optional[str] = None
    ) -> None:
        """Guarda o estado atual de `real` (1x por arquivo e por sessão)."""
        if any(e["caminho"] == logico for e in self.entradas):
            # já salvo nesta sessão: mantém o estado ORIGINAL, só registra o serviço
            if servico:
                for e in self.entradas:
                    if e["caminho"] == logico:
                        e.setdefault("servicos", [])
                        if servico not in e["servicos"]:
                            e["servicos"].append(servico)
                self._gravar_manifest()
            return
        existia = real.exists()
        arquivo_backup = None
        if existia:
            (self.diretorio / "arquivos").mkdir(parents=True, exist_ok=True)
            arquivo_backup = "arquivos/%04d" % (len(self.entradas) + 1)
            shutil.copy2(str(real), str(self.diretorio / arquivo_backup))
        self.entradas.append(
            {
                "caminho": logico,
                "existia": existia,
                "arquivo_backup": arquivo_backup,
                "regra": regra_id,
                "servicos": [servico] if servico else [],
            }
        )
        self._gravar_manifest()

    def _gravar_manifest(self) -> None:
        self.diretorio.mkdir(parents=True, exist_ok=True)
        dados = {"id": self.id, "revertida": self.revertida, "entradas": self.entradas}
        tmp = self.diretorio / "manifest.json.tmp"
        tmp.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.diretorio / "manifest.json")

    # -- restauração ----------------------------------------------------
    def restaurar(self, servico: Optional[str] = None) -> List[str]:
        """Restaura arquivos desta sessão (todos, ou só os ligados a `servico`).

        Retorna a lista de ações realizadas.
        """
        acoes: List[str] = []
        for e in reversed(self.entradas):
            if servico is not None and servico not in e.get("servicos", []):
                continue
            destino = self.raiz / e["caminho"].lstrip("/")
            if e["existia"]:
                origem = self.diretorio / e["arquivo_backup"]
                destino.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(origem), str(destino))
                acoes.append("restaurado %s" % e["caminho"])
            else:
                try:
                    destino.unlink()
                    acoes.append("removido %s (não existia antes)" % e["caminho"])
                except FileNotFoundError:
                    pass
        if servico is None:
            self.revertida = True
            self._gravar_manifest()
        return acoes

    def servicos(self) -> List[str]:
        vistos: List[str] = []
        for e in self.entradas:
            for s in e.get("servicos", []):
                if s not in vistos:
                    vistos.append(s)
        return vistos


class GerenciadorBackup:
    def __init__(self, estado_dir: Path, raiz: Path = Path("/")):
        self.estado_dir = Path(estado_dir)
        self.raiz = Path(raiz)
        self.base = self.estado_dir / "backups"

    def nova_sessao(self) -> SessaoBackup:
        self.base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        sid, n = stamp, 0
        while (self.base / sid).exists():
            n += 1
            sid = "%s-%d" % (stamp, n)
        d = self.base / sid
        d.mkdir()
        sessao = SessaoBackup(d, self.raiz)
        sessao._gravar_manifest()
        return sessao

    def listar(self) -> List[str]:
        if not self.base.is_dir():
            return []
        return sorted(p.name for p in self.base.iterdir() if (p / "manifest.json").exists())

    def abrir(self, sessao_id: str) -> SessaoBackup:
        d = self.base / sessao_id
        manifest = d / "manifest.json"
        if not manifest.exists():
            raise ErroBackup("sessão de backup não encontrada: %s" % sessao_id)
        dados = json.loads(manifest.read_text(encoding="utf-8"))
        s = SessaoBackup(d, self.raiz)
        s.entradas = dados.get("entradas", [])
        s.revertida = bool(dados.get("revertida", False))
        return s

    def ultima_pendente(self) -> Optional[SessaoBackup]:
        """Sessão mais recente que ainda não foi revertida."""
        for sid in reversed(self.listar()):
            s = self.abrir(sid)
            if not s.revertida and s.entradas:
                return s
        return None
