import React, { useState } from 'react';
import { HardDrive, FileText, AlertTriangle, RefreshCw, CheckCircle, Shield, ToggleLeft, ToggleRight, Info } from 'lucide-react';
import { VirtualSystemState } from '../types';

interface VirtualSystemTabProps {
  system: VirtualSystemState;
  onUpdateFile: (path: string, content: string) => void;
  onToggleSimulatedSshdTFail: () => void;
  onToggleSimulatedReloadFail: () => void;
  onResetSystem: () => void;
}

export const VirtualSystemTab: React.FC<VirtualSystemTabProps> = ({
  system,
  onUpdateFile,
  onToggleSimulatedSshdTFail,
  onToggleSimulatedReloadFail,
  onResetSystem,
}) => {
  const filePaths = Object.keys(system.files);
  const [selectedFile, setSelectedFile] = useState<string>(
    filePaths.includes('/etc/ssh/sshd_config.d/00-hardener.conf')
      ? '/etc/ssh/sshd_config.d/00-hardener.conf'
      : '/etc/ssh/sshd_config'
  );

  const currentContent = system.files[selectedFile] || '';

  return (
    <div className="space-y-4">
      {/* Simulation Controls & Warnings */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-red-500" />
            <div>
              <h3 className="text-sm font-bold text-white">Inspeção do Sistema RHEL 9 & Laboratório de Validação</h3>
              <p className="text-xs text-slate-400">
                Verifique o conteúdo real dos arquivos de configuração e teste mecanismos de segurança e rollback automático.
              </p>
            </div>
          </div>

          <button
            onClick={onResetSystem}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold border border-slate-700 flex items-center gap-1.5 transition active:scale-95"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Restaurar Estado Inicial Pré-Hardening</span>
          </button>
        </div>

        {/* Test Toggles for Error Handling / Rollback Testing */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div
            onClick={onToggleSimulatedSshdTFail}
            className={`p-3 rounded-lg border cursor-pointer transition flex items-center justify-between ${
              system.simulatedSshdTFail
                ? 'bg-rose-950/60 border-rose-700 text-rose-200'
                : 'bg-slate-800/60 border-slate-700/60 text-slate-300 hover:bg-slate-800'
            }`}
          >
            <div>
              <span className="font-semibold block">Simular Falha na Validação (sshd -t)</span>
              <span className="text-[11px] text-slate-400">
                Se ativado, <code className="text-red-400">sshd -t</code> falha e o motor reverte os arquivos automaticamente.
              </span>
            </div>
            {system.simulatedSshdTFail ? (
              <ToggleRight className="w-6 h-6 text-rose-400 flex-shrink-0" />
            ) : (
              <ToggleLeft className="w-6 h-6 text-slate-500 flex-shrink-0" />
            )}
          </div>

          <div
            onClick={onToggleSimulatedReloadFail}
            className={`p-3 rounded-lg border cursor-pointer transition flex items-center justify-between ${
              system.simulatedReloadFail
                ? 'bg-rose-950/60 border-rose-700 text-rose-200'
                : 'bg-slate-800/60 border-slate-700/60 text-slate-300 hover:bg-slate-800'
            }`}
          >
            <div>
              <span className="font-semibold block">Simular Falha no systemctl reload</span>
              <span className="text-[11px] text-slate-400">
                Se a recarga do serviço falhar, o motor desfaz as alterações para evitar indisponibilidade.
              </span>
            </div>
            {system.simulatedReloadFail ? (
              <ToggleRight className="w-6 h-6 text-rose-400 flex-shrink-0" />
            ) : (
              <ToggleLeft className="w-6 h-6 text-slate-500 flex-shrink-0" />
            )}
          </div>
        </div>
      </div>

      {/* File Viewer Layout */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Files Tree */}
        <div className="md:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-3 space-y-1">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 py-1 block">
            Arquivos do Host ({filePaths.length})
          </span>
          <div className="space-y-1 max-h-[500px] overflow-y-auto">
            {filePaths.map((path) => {
              const isSelected = selectedFile === path;
              const isDropIn = path.includes('00-hardener.conf');
              return (
                <button
                  key={path}
                  onClick={() => setSelectedFile(path)}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-mono transition flex items-center justify-between ${
                    isSelected
                      ? 'bg-red-950 text-white font-bold border border-red-800'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <span className="truncate">{path}</span>
                  {isDropIn && (
                    <span className="w-2 h-2 rounded-full bg-emerald-400 flex-shrink-0" title="Arquivo gerenciado pelo hardener"></span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* File Content Preview */}
        <div className="md:col-span-3 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl flex flex-col h-[520px]">
          <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
            <span className="font-mono text-xs text-emerald-400 font-semibold">{selectedFile}</span>
            <span className="text-slate-500 text-[11px] font-mono">
              {currentContent.split('\n').length} linhas
            </span>
          </div>

          <div className="p-4 flex-1 overflow-y-auto">
            <textarea
              value={currentContent}
              onChange={(e) => onUpdateFile(selectedFile, e.target.value)}
              className="w-full h-full bg-transparent text-slate-200 font-mono text-xs leading-relaxed focus:outline-none resize-none selection:bg-red-900/60"
              spellCheck={false}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
