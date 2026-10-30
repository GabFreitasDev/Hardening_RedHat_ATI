from typing import Dict
from hardener.checks.arquivo_chave_valor import ArquivoChaveValor
from hardener.checks.base import Primitiva
from hardener.checks.conta_usuario import ContaUsuario
from hardener.checks.montagem import Montagem
from hardener.checks.permissao_arquivo import PermissaoArquivo
from hardener.checks.sshd_config import SshdConfig
from hardener.checks.sudoers import Sudoers
from hardener.checks.suid_sgid import SuidSgid
from hardener.checks.sysctl import Sysctl

REGISTRO: Dict[str, Primitiva] = {
    SshdConfig.nome: SshdConfig(),
    PermissaoArquivo.nome: PermissaoArquivo(),
    ArquivoChaveValor.nome: ArquivoChaveValor(),
    Sudoers.nome: Sudoers(),
    ContaUsuario.nome: ContaUsuario(),
    SuidSgid.nome: SuidSgid(),
    Sysctl.nome: Sysctl(),
    Montagem.nome: Montagem(),
}




