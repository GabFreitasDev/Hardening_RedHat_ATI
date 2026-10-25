import React from 'react';
import { AlertTriangle, CheckCircle, ShieldAlert, Cpu, UserCheck, Lock, Unlock, Server } from 'lucide-react';

interface StatusBannerProps {
  isRoot: boolean;
  setIsRoot: (val: boolean) => void;
  hasVmMarker: boolean;
  setHasVmMarker: (val: boolean) => void;
  platform: string;
  setPlatform: (val: string) => void;
  hostname: string;
}

export const StatusBanner: React.FC<StatusBannerProps> = ({
  isRoot,
  setIsRoot,
  hasVmMarker,
  setHasVmMarker,
  platform,
  setPlatform,
  hostname,
}) => {
  const isEnforceBlocked = !isRoot || !hasVmMarker || platform !== 'rhel9';

  return (
    <div className="bg-slate-900 border-b border-slate-800/80 px-4 py-2.5 sm:px-6">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Host & Platform Info */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-slate-300">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-mono text-slate-400">{hostname}</span>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/60">
            <Cpu className="w-3.5 h-3.5 text-red-400" />
            <span className="text-slate-400">Plataforma:</span>
            <select
              value={platform}
              onChange={(e) => setPlatform(e.target.value)}
              className="bg-transparent text-white font-mono font-medium focus:outline-none cursor-pointer"
            >
              <option value="rhel9" className="bg-slate-900 text-white">rhel9 (RHEL / Rocky / Alma 9)</option>
              <option value="ubuntu22" className="bg-slate-900 text-white">ubuntu22 (Incompatível - Testa PULADO)</option>
              <option value="desconhecida" className="bg-slate-900 text-white">desconhecida (Sem /etc/os-release)</option>
            </select>
          </div>
        </div>

        {/* Safety Lock Switches (Trava de Segurança da VM) */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Root status toggle */}
          <button
            onClick={() => setIsRoot(!isRoot)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border transition font-medium ${
              isRoot
                ? 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/40'
                : 'bg-rose-950/60 border-rose-800/60 text-rose-300 hover:bg-rose-900/40'
            }`}
            title="Alterna entre execução como root (sudo) ou usuário comum"
          >
            <UserCheck className="w-3.5 h-3.5" />
            <span>{isRoot ? 'Root (euid=0)' : 'Sem Root (sudo ausente)'}</span>
          </button>

          {/* /etc/hardener-vm marker toggle */}
          <button
            onClick={() => setHasVmMarker(!hasVmMarker)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border transition font-medium ${
              hasVmMarker
                ? 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/40'
                : 'bg-amber-950/60 border-amber-800/60 text-amber-300 hover:bg-amber-900/40'
            }`}
            title="Marcador /etc/hardener-vm: protege máquinas de desenvolvimento impedindo enforce --apply acidental"
          >
            {hasVmMarker ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
            <span>/etc/hardener-vm: {hasVmMarker ? 'Presente (VM)' : 'Ausente (Máquina Pessoal)'}</span>
          </button>

          {/* Latch Status Badge */}
          {isEnforceBlocked ? (
            <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/50 text-amber-300">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              <span>Trava de Segurança: Apply bloqueado</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/50 text-emerald-300">
              <CheckCircle className="w-3 h-3 text-emerald-400" />
              <span>VM Autorizada para Apply</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
