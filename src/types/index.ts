export type Severidade = 'baixa' | 'media' | 'alta' | 'critica';

export type DorAtiId = 1 | 2 | 3 | 4 | 5 | 6;

export interface DorAtiInfo {
  id: DorAtiId;
  nome: string;
  descricao: string;
  cor: string;
}

export const NOMES_DORES: Record<DorAtiId, string> = {
  1: "Ransomware",
  2: "Uploads de arquivos",
  3: "Movimentação lateral",
  4: "Patches",
  5: "Revogação de credenciais",
  6: "Mínimo privilégio",
};

export const DORES_INFO: Record<DorAtiId, DorAtiInfo> = {
  1: {
    id: 1,
    nome: "Ransomware",
    descricao: "Mitigação de execução não autorizada em partições temporárias e reforço do kernel",
    cor: "from-rose-500/20 to-red-600/30 text-rose-300 border-rose-500/30",
  },
  2: {
    id: 2,
    nome: "Uploads de arquivos",
    descricao: "Impedir execução de scripts maliciosos em diretórios de upload",
    cor: "from-amber-500/20 to-orange-600/30 text-amber-300 border-amber-500/30",
  },
  3: {
    id: 3,
    nome: "Movimentação lateral",
    descricao: "Isolamento de rede, firewall estrito, desativação de roteamento e redirecionamentos",
    cor: "from-blue-500/20 to-indigo-600/30 text-blue-300 border-blue-500/30",
  },
  4: {
    id: 4,
    nome: "Patches",
    descricao: "Controle de atualizações e rastreabilidade de pacotes obsoletos",
    cor: "from-purple-500/20 to-violet-600/30 text-purple-300 border-purple-500/30",
  },
  5: {
    id: 5,
    nome: "Revogação de credenciais",
    descricao: "Offboarding ágil de contas locais, revogação de chaves SSH e sessões ativas",
    cor: "from-emerald-500/20 to-teal-600/30 text-emerald-300 border-emerald-500/30",
  },
  6: {
    id: 6,
    nome: "Mínimo privilégio",
    descricao: "Restrição de acesso root via SSH, controle fino de sudoers e políticas de senhas",
    cor: "from-cyan-500/20 to-sky-600/30 text-cyan-300 border-cyan-500/30",
  },
};

export type StatusRegra =
  | 'CONFORME'
  | 'NAO_CONFORME'
  | 'SERIA_CORRIGIDO'
  | 'CORRIGIDO'
  | 'FALHOU'
  | 'PULADO'
  | 'ERRO';

export const ORDEM_STATUS: StatusRegra[] = [
  'CONFORME',
  'CORRIGIDO',
  'SERIA_CORRIGIDO',
  'NAO_CONFORME',
  'FALHOU',
  'ERRO',
  'PULADO',
];

export interface Regra {
  id: string;
  descricao: string;
  referencia: string;
  dor_ati: DorAtiId[];
  severidade: Severidade;
  plataforma: string;
  primitiva: string;
  parametros: Record<string, any>;
  recarregar?: string;
  origem?: string;
}

export interface Verificacao {
  conforme: boolean;
  atual?: string | null;
  esperado?: string | null;
  detalhe: string;
}

export interface Resultado {
  regra: Regra;
  status: StatusRegra;
  atual?: string | null;
  esperado?: string | null;
  detalhe: string;
  mudancas: string[];
}

export interface BackupEntry {
  caminho: string;
  existia: boolean;
  arquivo_backup: string | null;
  regra: string;
  servicos: string[];
  conteudoOriginal?: string;
}

export interface BackupSession {
  id: string;
  criadoEm: string;
  revertida: boolean;
  entradas: BackupEntry[];
}

export interface RelatorioJSON {
  ferramenta: string;
  versao: string;
  modo: string;
  gerado_em: string;
  host: string;
  plataforma: string;
  resumo: Record<string, number>;
  por_dor: Record<string, { nome: string; total: number; conformes: number }>;
  regras: Array<{
    id: string;
    descricao: string;
    referencia: string;
    dor_ati: DorAtiId[];
    severidade: Severidade;
    status: StatusRegra;
    atual?: string | null;
    esperado?: string | null;
    detalhe: string;
    mudancas: string[];
  }>;
  avisos: string[];
}

export interface VirtualSystemState {
  hostname: string;
  plataforma: string;
  isRoot: boolean;
  hasVmMarker: boolean;
  files: Record<string, string>;
  services: Record<string, {
    active: boolean;
    validSyntax: boolean;
    simulatedReloadFailure: boolean;
  }>;
  simulatedSshdTFail: boolean;
  simulatedReloadFail: boolean;
}
