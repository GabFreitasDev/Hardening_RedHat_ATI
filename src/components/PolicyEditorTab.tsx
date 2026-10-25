import React, { useState } from 'react';
import yaml from 'js-yaml';
import { FileCode, CheckCircle, AlertTriangle, Save, Download, RefreshCw, Info } from 'lucide-react';
import { Regra } from '../types';

interface PolicyEditorTabProps {
  regras: Regra[];
  onUpdateRegras: (novasRegras: Regra[]) => void;
}

const DEFAULT_YAML_FILES: Record<string, string> = {
  "rules/ssh.yaml": `# Regras de SSH (trilha do Aluno B, dor 6 - mínimo privilégio).
# Formato e campos: docs/CONTRATO.md
#
# Atenção: no YAML, "no"/"yes" SEM aspas viram booleano. Escreva sempre "no" entre aspas.
# Atenção: o campo referencia só deixa de ser "A CONFIRMAR" depois de conferir o item
# no CIS Benchmark oficial do RHEL 9 (não usar numeração de memória).

- id: SSH-001
  descricao: Desabilitar login direto como root no SSH
  referencia: "CIS RHEL 9 - 5.2.8 SSH PermitRootLogin"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: sshd_config
  parametros:
    chave: PermitRootLogin
    valor: "no"
  recarregar: sshd

- id: SSH-002
  descricao: Permissões restritivas no arquivo /etc/ssh/sshd_config (0600 root:root)
  referencia: "CIS RHEL 9 - 5.2.1 sshd_config permissions"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: permissao_arquivo
  parametros:
    caminho: /etc/ssh/sshd_config
    modo: "0600"
    dono: root
    grupo: root
  recarregar: sshd

- id: NET-003
  descricao: Configurar AllowGroups no SSH para limitar conexões remotas
  referencia: "CIS RHEL 9 - 5.2.16 Ensure SSH access is limited (AllowGroups)"
  dor_ati: [3, 6]
  severidade: alta
  plataforma: rhel9
  primitiva: sshd_config
  parametros:
    chave: AllowGroups
    valor: "sshusers wheel"
  recarregar: sshd
`,

  "rules/accounts.yaml": `# Regras de Contas e Privilégios (Dores 5 e 6).
- id: SUDO-001
  descricao: Impedir diretiva NOPASSWD indevida no sudoers e sudoers.d
  referencia: "CIS RHEL 9 - 5.3.4 Ensure sudo commands require authentication"
  dor_ati: [6]
  severidade: critica
  plataforma: rhel9
  primitiva: sudoers
  parametros:
    proibir: NOPASSWD
  recarregar: sudoers

- id: SUDO-002
  descricao: Impedir permissões excessivas ALL indevidas em sudoers
  referencia: "CIS RHEL 9 - 5.3.3 Sudoers restricted specification"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: sudoers
  parametros:
    verificar_regras_gerais: true
  recarregar: sudoers

- id: SUDO-003
  descricao: Grupo wheel restrito exclusivamente a administradores autorizados
  referencia: "CIS RHEL 9 - 5.3.2 Restrict wheel group membership"
  dor_ati: [6]
  severidade: alta
  plataforma: rhel9
  primitiva: conta_usuario
  parametros:
    grupo: wheel
    autorizados: ["root", "admin_ati", "secops"]

- id: ACC-001
  descricao: UID 0 exclusivo para conta root
  referencia: "CIS RHEL 9 - 5.4.3 Ensure root is the only UID 0 account"
  dor_ati: [6]
  severidade: critica
  plataforma: rhel9
  primitiva: conta_usuario
  parametros:
    uid_zero_apenas: root

- id: OFF-001
  descricao: Contas locais inativas ou fora da lista de autorizados bloqueadas
  referencia: "Requisito ATI - Trilha B Offboarding"
  dor_ati: [5]
  severidade: alta
  plataforma: rhel9
  primitiva: offboarding
  parametros:
    acao: bloquear_inativos
    expiracao_dias: 90
`,

  "rules/mounts.yaml": `# Regras de Montagens e Partições (Dor 1 - Ransomware).
- id: MNT-001
  descricao: Partição /tmp montada com opções noexec, nosuid e nodev
  referencia: "CIS RHEL 9 - 1.1.2 Ensure /tmp has noexec, nosuid, nodev options"
  dor_ati: [1]
  severidade: alta
  plataforma: rhel9
  primitiva: montagem
  parametros:
    ponto: /tmp
    opcoes: ["noexec", "nosuid", "nodev"]

- id: MNT-002
  descricao: Partição /var/tmp montada com opções noexec, nosuid e nodev
  referencia: "CIS RHEL 9 - 1.1.4 Ensure /var/tmp has noexec, nosuid, nodev options"
  dor_ati: [1]
  severidade: alta
  plataforma: rhel9
  primitiva: montagem
  parametros:
    ponto: /var/tmp
    opcoes: ["noexec", "nosuid", "nodev"]

- id: MNT-003
  descricao: Memória compartilhada /dev/shm montada com noexec, nosuid e nodev
  referencia: "CIS RHEL 9 - 1.1.6 Ensure /dev/shm has noexec, nosuid, nodev options"
  dor_ati: [1]
  severidade: alta
  plataforma: rhel9
  primitiva: montagem
  parametros:
    ponto: /dev/shm
    opcoes: ["noexec", "nosuid", "nodev"]
`,

  "rules/network.yaml": `# Regras de Rede e Firewall (Dor 3 - Movimentação Lateral).
- id: NET-001
  descricao: Firewalld ativo com zona restritiva e apenas serviços declarados
  referencia: "CIS RHEL 9 - 3.4.2 Ensure firewalld service is enabled and active"
  dor_ati: [3]
  severidade: critica
  plataforma: rhel9
  primitiva: firewalld
  parametros:
    servico_ativo: true
    zona_padrao: drop
    servicos_permitidos: ["ssh"]
  recarregar: firewalld

- id: NET-004
  descricao: Desabilitar encaminhamento de pacotes IPv4 (net.ipv4.ip_forward = 0)
  referencia: "CIS RHEL 9 - 3.1.1 Ensure IP forwarding is disabled"
  dor_ati: [3]
  severidade: alta
  plataforma: rhel9
  primitiva: sysctl
  parametros:
    parametro: net.ipv4.ip_forward
    valor: "0"
`,

  "rules/uploads.yaml": `# Regras de Uploads Seguros (Dor 2 - Uploads de Arquivos).
- id: UPL-001
  descricao: Diretórios de upload declarados sem bit de execução (noexec)
  referencia: "Requisito ATI - Trilha C Prevenção de Uploads Executáveis"
  dor_ati: [2]
  severidade: critica
  plataforma: rhel9
  primitiva: permissao_arquivo
  parametros:
    caminho: /var/www/uploads
    modo: "0750"
    remover_exec: true

- id: UPL-004
  descricao: Contexto SELinux sem permissão de execução de scripts em uploads
  referencia: "Requisito ATI - Trilha C SELinux httpd_sys_rw_content_t"
  dor_ati: [2]
  severidade: alta
  plataforma: rhel9
  primitiva: selinux
  parametros:
    caminho: /var/www/uploads
    tipo: httpd_sys_rw_content_t
`
};

export const PolicyEditorTab: React.FC<PolicyEditorTabProps> = ({ regras, onUpdateRegras }) => {
  const [selectedFile, setSelectedFile] = useState<string>("rules/ssh.yaml");
  const [fileContents, setFileContents] = useState<Record<string, string>>(DEFAULT_YAML_FILES);
  const [validationResult, setValidationResult] = useState<{
    valid: boolean;
    messages: string[];
    pendingCisCount: number;
  } | null>(null);

  const currentYaml = fileContents[selectedFile] || "";

  const handleTextChange = (newText: string) => {
    setFileContents(prev => ({
      ...prev,
      [selectedFile]: newText
    }));
  };

  const handleValidate = () => {
    const messages: string[] = [];
    let pendingCisCount = 0;
    let totalParsedRules = 0;

    try {
      for (const [fileName, content] of Object.entries(fileContents)) {
        const parsed = yaml.load(content) as any[];
        if (!Array.isArray(parsed)) {
          messages.push(`${fileName}: Conteúdo deve ser uma lista de regras em YAML.`);
          continue;
        }

        parsed.forEach((item, idx) => {
          totalParsedRules++;
          // Validate required fields according to docs/CONTRATO.md
          const required = ['id', 'descricao', 'referencia', 'dor_ati', 'severidade', 'plataforma', 'primitiva'];
          for (const req of required) {
            if (item[req] === undefined || item[req] === null || item[req] === '') {
              messages.push(`${fileName} [regra #${idx + 1}]: Campo obrigatório ausente: '${req}'`);
            }
          }

          if (typeof item.referencia === 'string' && item.referencia.includes('A CONFIRMAR')) {
            pendingCisCount++;
          }
        });
      }

      const isValid = messages.length === 0;
      setValidationResult({
        valid: isValid,
        messages: isValid ? [`${totalParsedRules} regra(s) válida(s) nas políticas declarativas.`] : messages,
        pendingCisCount
      });
    } catch (err: any) {
      setValidationResult({
        valid: false,
        messages: [`Erro de sintaxe YAML: ${err.message}`],
        pendingCisCount: 0
      });
    }
  };

  const handleApplyToEngine = () => {
    try {
      const allRules: Regra[] = [];
      for (const [fileName, content] of Object.entries(fileContents)) {
        const parsed = yaml.load(content) as any[];
        if (Array.isArray(parsed)) {
          parsed.forEach(r => {
            allRules.push({
              id: r.id,
              descricao: r.descricao,
              referencia: r.referencia,
              dor_ati: r.dor_ati || [],
              severidade: r.severidade || 'media',
              plataforma: r.plataforma || 'rhel9',
              primitiva: r.primitiva,
              parametros: r.parametros || {},
              recarregar: r.recarregar,
              origem: fileName
            });
          });
        }
      }

      onUpdateRegras(allRules);
      setValidationResult({
        valid: true,
        messages: [`${allRules.length} regra(s) carregada(s) com sucesso no motor de hardening!`],
        pendingCisCount: allRules.filter(r => r.referencia.includes('A CONFIRMAR')).length
      });
    } catch (err: any) {
      alert(`Erro ao carregar regras: ${err.message}`);
    }
  };

  const handleDownload = () => {
    const blob = new Blob([currentYaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedFile.split('/').pop() || 'policy.yaml';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Policy Header & File Selector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Arquivos de Política Declarativa em YAML
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {Object.keys(fileContents).map(fileName => (
            <button
              key={fileName}
              onClick={() => setSelectedFile(fileName)}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
                selectedFile === fileName
                  ? 'bg-red-600 text-white shadow-sm'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
              }`}
            >
              {fileName}
            </button>
          ))}
        </div>
      </div>

      {/* YAML Editor Area */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[520px]">
        {/* Editor Toolbar */}
        <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>{selectedFile}</span>
            <span className="text-slate-600">|</span>
            <span>YAML</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleValidate}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition active:scale-95"
            >
              <CheckCircle className="w-3.5 h-3.5 text-blue-400" />
              <span>Validar (python -m hardener validar)</span>
            </button>

            <button
              onClick={handleApplyToEngine}
              className="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-200 text-xs font-semibold border border-emerald-800/60 flex items-center gap-1.5 transition active:scale-95"
            >
              <Save className="w-3.5 h-3.5 text-emerald-400" />
              <span>Carregar no Motor</span>
            </button>

            <button
              onClick={handleDownload}
              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              title="Baixar arquivo YAML"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Textarea */}
        <div className="p-4 flex-1">
          <textarea
            value={currentYaml}
            onChange={(e) => handleTextChange(e.target.value)}
            className="w-full h-full bg-transparent text-emerald-300 font-mono text-xs leading-relaxed focus:outline-none resize-none selection:bg-emerald-900/50"
            spellCheck={false}
          />
        </div>
      </div>

      {/* Validation Feedback Banner */}
      {validationResult && (
        <div
          className={`p-4 rounded-xl border ${
            validationResult.valid
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-rose-950/40 border-rose-800/60 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2 font-semibold text-xs mb-2">
            {validationResult.valid ? (
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            )}
            <span>
              {validationResult.valid ? 'Política Válida segundo o Contrato' : 'Erros de Validação na Política'}
            </span>
          </div>

          <ul className="text-xs space-y-1 font-mono text-[11px]">
            {validationResult.messages.map((msg, i) => (
              <li key={i}>{msg}</li>
            ))}
          </ul>

          {validationResult.pendingCisCount > 0 && (
            <div className="mt-2 pt-2 border-t border-slate-800 text-amber-300 text-xs flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5" />
              <span>
                Aviso: {validationResult.pendingCisCount} regra(s) possuem referência CIS marcada como "A CONFIRMAR".
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
