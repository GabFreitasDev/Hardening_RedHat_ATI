import React from 'react';
import { Shield, Server, Terminal, FileCode, History, HardDrive, Play, Eye, RotateCcw, CheckCircle2, AlertTriangle, UserX } from 'lucide-react';
import { HARDENER_VERSION } from '../engine/hardenerEngine';

interface NavbarProps {
  activeTab: 'dashboard' | 'terminal' | 'policy' | 'backups' | 'system';
  setActiveTab: (tab: 'dashboard' | 'terminal' | 'policy' | 'backups' | 'system') => void;
  onAudit: () => void;
  onDryRun: () => void;
  onApply: () => void;
  onRollback: () => void;
  onOffboarding?: () => void;
  isProcessing: boolean;
  hasPendingBackups: boolean;
  hasVmMarker: boolean;
  isRoot: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onAudit,
  onDryRun,
  onApply,
  onRollback,
  onOffboarding,
  isProcessing,
  hasPendingBackups,
  hasVmMarker,
  isRoot,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 to-rose-700 flex items-center justify-center shadow-lg shadow-red-900/30 border border-red-500/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-white tracking-tight">Hardening RHEL 9</span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800/40">
                  ATI Recife
                </span>
                <span className="text-xs text-slate-500 font-mono">v{HARDENER_VERSION}</span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                CIS Benchmark & Política Declarativa por Dores da ATI
              </p>
            </div>
          </div>

          {/* Quick Engine Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={onAudit}
              disabled={isProcessing}
              title="python -m hardener audit (verifica sem alterar)"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition shadow-sm active:scale-95 disabled:opacity-50"
            >
              <Eye className="w-3.5 h-3.5 text-blue-400" />
              <span>Audit</span>
            </button>

            <button
              onClick={onDryRun}
              disabled={isProcessing}
              title="python -m hardener enforce (simula o que mudaria)"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-amber-950/60 hover:bg-amber-900/60 text-amber-200 border border-amber-800/40 transition shadow-sm active:scale-95 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 text-amber-400" />
              <span>Dry-Run</span>
            </button>

            <button
              onClick={onApply}
              disabled={isProcessing}
              title="python -m hardener enforce --apply (aplica com backup e validação)"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-md shadow-red-950/50 transition active:scale-95 disabled:opacity-50"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-white" />
              <span>Apply</span>
            </button>

            <button
              onClick={onRollback}
              disabled={isProcessing || !hasPendingBackups}
              title="python -m hardener rollback (desfaz a última sessão)"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
              <span>Rollback</span>
            </button>

            {onOffboarding && (
              <button
                onClick={onOffboarding}
                disabled={isProcessing}
                title="python -m hardener offboarding --autorizados lista.csv"
                className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-purple-950/80 hover:bg-purple-900/80 text-purple-200 border border-purple-800/60 shadow-sm transition active:scale-95 disabled:opacity-50"
              >
                <UserX className="w-3.5 h-3.5 text-purple-400" />
                <span>Offboarding</span>
              </button>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 sm:space-x-4 border-t border-slate-800/80 -mb-px overflow-x-auto">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'dashboard'
                ? 'border-red-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Dashboard & Regras</span>
          </button>

          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'terminal'
                ? 'border-red-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Terminal CLI</span>
          </button>

          <button
            onClick={() => setActiveTab('policy')}
            className={`flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'policy'
                ? 'border-red-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Políticas (YAML)</span>
          </button>

          <button
            onClick={() => setActiveTab('backups')}
            className={`flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'backups'
                ? 'border-red-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Backups & Sessões</span>
            {hasPendingBackups && (
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('system')}
            className={`flex items-center gap-2 py-3 px-3 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'system'
                ? 'border-red-500 text-white'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <HardDrive className="w-4 h-4" />
            <span>Ambiente VM / Arquivos</span>
            {(!hasVmMarker || !isRoot) && (
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
