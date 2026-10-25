import React, { useState } from 'react';
import { History, RotateCcw, CheckCircle, FileText, Server, AlertCircle, HardDrive } from 'lucide-react';
import { BackupSession } from '../types';

interface BackupsTabProps {
  backups: BackupSession[];
  onRollbackSession: (sessionId?: string) => void;
}

export const BackupsTab: React.FC<BackupsTabProps> = ({ backups, onRollbackSession }) => {
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    backups.length > 0 ? backups[0].id : null
  );

  const selectedSession = backups.find((b) => b.id === selectedSessionId) || backups[0];

  return (
    <div className="space-y-4">
      {/* Overview & Quick Rollback Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-emerald-400" />
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Gerenciador de Backups & Ponto de Restauração
            </span>
            <p className="text-xs text-slate-400">
              Armazenados em <code className="text-red-400 font-mono">/var/lib/hardener/backups/</code>
            </p>
          </div>
        </div>

        <button
          onClick={() => onRollbackSession()}
          disabled={backups.length === 0 || backups.every((b) => b.revertida)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-950/80 hover:bg-red-900/80 text-red-200 border border-red-800/60 shadow-sm transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Rollback da Última Sessão Pendente</span>
        </button>
      </div>

      {backups.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 space-y-2">
          <HardDrive className="w-8 h-8 text-slate-600 mx-auto" />
          <p className="text-sm font-medium text-slate-300">Nenhuma sessão de backup registrada.</p>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Backups atômicos são criados automaticamente sempre que o comando{' '}
            <code className="text-red-400 font-mono">enforce --apply</code> modifica arquivos no sistema
            RHEL 9.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Sessions List */}
          <div className="md:col-span-1 space-y-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
              Sessões de Enforce ({backups.length})
            </span>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {backups.map((sessao) => {
                const isSelected = selectedSession?.id === sessao.id;
                return (
                  <div
                    key={sessao.id}
                    onClick={() => setSelectedSessionId(sessao.id)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition ${
                      isSelected
                        ? 'bg-slate-800 border-red-500 ring-2 ring-red-500/20 shadow-md'
                        : 'bg-slate-900 border-slate-800 hover:border-slate-700 hover:bg-slate-800/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-xs text-white">{sessao.id}</span>
                      {sessao.revertida ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                          Revertida
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                          Pendente
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 mt-2 flex items-center justify-between">
                      <span>{sessao.entradas.length} arquivo(s) salvos</span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(sessao.criadoEm).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Session Detail Inspector */}
          {selectedSession && (
            <div className="md:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-mono font-bold text-sm text-white">Sessão {selectedSession.id}</h3>
                    {selectedSession.revertida ? (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">
                        Já revertida
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                        Disponível para Reversão
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-slate-400">
                    Criada em {new Date(selectedSession.criadoEm).toLocaleString()}
                  </span>
                </div>

                {!selectedSession.revertida && (
                  <button
                    onClick={() => onRollbackSession(selectedSession.id)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 shadow-sm transition active:scale-95"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reverter Esta Sessão</span>
                  </button>
                )}
              </div>

              {/* Manifest Files Table */}
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 block">
                  Arquivos Registrados no manifest.json
                </span>

                <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/60">
                  {selectedSession.entradas.map((entry, idx) => (
                    <div key={idx} className="p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold text-slate-200">{entry.caminho}</span>
                        <span className="text-[11px] font-mono text-slate-500">
                          {entry.arquivo_backup || 'novo (sem backup)'}
                        </span>
                      </div>

                      <div className="flex items-center gap-4 text-slate-400 text-[11px]">
                        <span>Regra: <span className="font-mono text-red-400 font-semibold">{entry.regra}</span></span>
                        <span>Existia antes: <span className={entry.existia ? 'text-emerald-400' : 'text-amber-400'}>{entry.existia ? 'Sim' : 'Não (drop-in novo)'}</span></span>
                        {entry.servicos.length > 0 && (
                          <span>Serviços vinculados: <span className="font-mono text-cyan-300">{entry.servicos.join(', ')}</span></span>
                        )}
                      </div>

                      {entry.conteudoOriginal !== undefined && (
                        <details className="mt-2 text-[11px]">
                          <summary className="cursor-pointer text-slate-400 hover:text-slate-200">
                            Ver conteúdo original salvo
                          </summary>
                          <pre className="mt-1 p-2 bg-slate-900 border border-slate-800 rounded font-mono text-slate-300 overflow-x-auto max-h-32">
                            {entry.conteudoOriginal}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
