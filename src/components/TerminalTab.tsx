import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Copy, Trash2, Play, CornerDownLeft } from 'lucide-react';

interface TerminalTabProps {
  onExecuteCommand: (cmd: string) => { output: string; exitCode: number };
  initialLogs?: string[];
}

interface CommandHistoryItem {
  command: string;
  output: string;
  exitCode: number;
  time: string;
}

export const TerminalTab: React.FC<TerminalTabProps> = ({ onExecuteCommand }) => {
  const [inputCmd, setInputCmd] = useState('');
  const [history, setHistory] = useState<CommandHistoryItem[]>([
    {
      command: 'python -m hardener audit',
      output: `hardener 0.1.0 | modo: audit | plataforma: rhel9 | host: rhel9-vm-ati | 2026-10-24T10:47:00

[NAO_CONFORME] SSH-001  alta  dor 6  Desabilitar login direto como root no SSH
    atual: yes | esperado: no
    detalhe: diretiva PermitRootLogin difere do padrão de segurança
[NAO_CONFORME] SSH-002  alta  dor 6  Permissões restritivas no arquivo /etc/ssh/sshd_config (0600 root:root)
    atual: 0644 root:root | esperado: 0600 root:root
[NAO_CONFORME] SUDO-001  critica  dor 6  Impedir diretiva NOPASSWD indevida no sudoers
    atual: NOPASSWD presente em %wheel e estagiario | esperado: sem NOPASSWD (autenticação obrigatória)
[NAO_CONFORME] NET-001  critica  dor 3  Firewalld ativo com zona restritiva e apenas serviços declarados
    atual: inativo | esperado: ativo (zona padrão restritiva: drop)
[NAO_CONFORME] MNT-001  alta  dor 1  Partição /tmp montada com opções noexec, nosuid e nodev
    atual: defaults | esperado: noexec,nosuid,nodev
[NAO_CONFORME] SYS-001  critica  dor 1  SELinux ativado no modo enforcing (/etc/selinux/config)
    atual: permissive | esperado: enforcing

Resumo (30 regra(s)): NAO_CONFORME=28, CONFORME=2
Por dor da ATI:
  Dor 1 (Ransomware): 1/7 conformes
  Dor 2 (Uploads de arquivos): 0/4 conformes
  Dor 3 (Movimentação lateral): 0/6 conformes
  Dor 5 (Revogação de credenciais): 0/6 conformes
  Dor 6 (Mínimo privilégio): 1/11 conformes`,
      exitCode: 1,
      time: '10:47:00',
    },
  ]);

  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const handleRun = (cmdToRun: string) => {
    const trimmed = cmdToRun.trim();
    if (!trimmed) return;

    if (trimmed === 'clear') {
      setHistory([]);
      setInputCmd('');
      return;
    }

    const { output, exitCode } = onExecuteCommand(trimmed);
    const time = new Date().toLocaleTimeString();

    setHistory((prev) => [
      ...prev,
      {
        command: trimmed,
        output,
        exitCode,
        time,
      },
    ]);
    setInputCmd('');
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleRun(inputCmd);
    }
  };

  const quickCommands = [
    'python -m hardener audit',
    'python -m hardener enforce',
    'python -m hardener enforce --apply',
    'python -m hardener offboarding --autorizados lista.csv',
    'python -m hardener offboarding --autorizados lista.csv --apply',
    'python -m hardener rollback',
    'python -m hardener report --formato json',
    'python -m hardener report --formato texto',
    'python -m hardener validar',
    'python -m hardener audit --dor 5',
    'python -m hardener audit --regra SSH-001',
  ];

  return (
    <div className="space-y-4">
      {/* Quick Clickable CLI Commands */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-red-500" />
            Comandos Rápidos da CLI do Hardener
          </span>
          <button
            onClick={() => setHistory([])}
            className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"
          >
            <Trash2 className="w-3 h-3" />
            Limpar Terminal
          </button>
        </div>

        <div className="flex flex-wrap gap-2">
          {quickCommands.map((cmd) => (
            <button
              key={cmd}
              onClick={() => handleRun(cmd)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-mono text-xs border border-slate-700/80 transition flex items-center gap-1.5 shadow-sm active:scale-95"
            >
              <Play className="w-3 h-3 text-red-400" />
              <span>{cmd}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Window */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl shadow-2xl overflow-hidden font-mono text-xs flex flex-col h-[600px]">
        {/* Terminal Title Bar */}
        <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between select-none">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
            <span className="text-slate-400 text-xs ml-2">bash - root@rhel9-vm-ati: ~</span>
          </div>
          <span className="text-slate-500 text-[11px]">Hardener RedHat ATI Virtual Shell</span>
        </div>

        {/* Terminal Content Area */}
        <div className="p-4 flex-1 overflow-y-auto space-y-4 text-slate-300 leading-relaxed">
          <div className="text-slate-500 pb-2 border-b border-slate-900 text-[11px]">
            Red Hat Enterprise Linux 9.4 (Plow) - Terminal de Demonstração e Verificação
            <br />
            Digite <span className="text-red-400">help</span> para comandos suportados ou clique nos atalhos acima.
          </div>

          {history.map((item, index) => (
            <div key={index} className="space-y-1.5">
              {/* Command Prompt Line */}
              <div className="flex items-center gap-2 text-slate-200">
                <span className="text-emerald-400 font-semibold">[root@rhel9-vm-ati hardener]#</span>
                <span className="text-white font-bold">{item.command}</span>
                <span className="text-[10px] text-slate-500 ml-auto">{item.time}</span>
              </div>

              {/* Command Output */}
              <pre className="text-slate-300 whitespace-pre-wrap pl-2 border-l-2 border-slate-800 bg-slate-900/40 p-2.5 rounded font-mono text-[11.5px] overflow-x-auto">
                {item.output}
              </pre>

              {/* Exit Code Status */}
              <div className="text-[11px] flex items-center gap-2 pl-2">
                <span className="text-slate-500">return code:</span>
                <span
                  className={`px-1.5 py-0.2 rounded font-bold ${
                    item.exitCode === 0
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : item.exitCode === 1
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {item.exitCode}
                </span>
                <span className="text-slate-500">
                  {item.exitCode === 0
                    ? '(tudo conforme)'
                    : item.exitCode === 1
                    ? '(há pendências)'
                    : '(erro / falha de execução)'}
                </span>
              </div>
            </div>
          ))}

          <div ref={endRef} />
        </div>

        {/* Terminal Input Line */}
        <div className="bg-slate-900/90 border-t border-slate-800 p-3 flex items-center gap-2">
          <span className="text-emerald-400 font-semibold whitespace-nowrap">
            [root@rhel9-vm-ati hardener]#
          </span>
          <input
            type="text"
            value={inputCmd}
            onChange={(e) => setInputCmd(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Digite um comando da CLI (ex: python -m hardener audit)..."
            className="bg-transparent text-white font-mono text-xs w-full focus:outline-none placeholder:text-slate-600"
            autoFocus
          />
          <button
            onClick={() => handleRun(inputCmd)}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700"
            title="Executar comando"
          >
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
