import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { StatusBanner } from './components/StatusBanner';
import { DashboardTab } from './components/DashboardTab';
import { TerminalTab } from './components/TerminalTab';
import { PolicyEditorTab } from './components/PolicyEditorTab';
import { BackupsTab } from './components/BackupsTab';
import { VirtualSystemTab } from './components/VirtualSystemTab';
import { HardenerEngine, HARDENER_VERSION } from './engine/hardenerEngine';
import { INITIAL_FILES, REGRAS_PADRAO } from './data/rules';
import { BackupSession, DorAtiId, Regra, Resultado, VirtualSystemState } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'terminal' | 'policy' | 'backups' | 'system'>('dashboard');
  const [regras, setRegras] = useState<Regra[]>(REGRAS_PADRAO);
  const [selectedDor, setSelectedDor] = useState<DorAtiId | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [modoAtual, setModoAtual] = useState<string>('audit');

  // Virtual RHEL 9 System State
  const [virtualSystem, setVirtualSystem] = useState<VirtualSystemState>({
    hostname: 'rhel9-vm-ati',
    plataforma: 'rhel9',
    isRoot: true,
    hasVmMarker: true,
    files: { ...INITIAL_FILES },
    services: {
      sshd: { active: true, validSyntax: true, simulatedReloadFailure: false },
      firewalld: { active: false, validSyntax: true, simulatedReloadFailure: false },
      sudoers: { active: true, validSyntax: true, simulatedReloadFailure: false },
    },
    simulatedSshdTFail: false,
    simulatedReloadFail: false,
  });

  const [backups, setBackups] = useState<BackupSession[]>([]);

  // Engine instance initialized with current system and backups
  const engine = useMemo(() => {
    return new HardenerEngine(virtualSystem, backups);
  }, [virtualSystem, backups]);

  // Initial audit on load
  const [resultados, setResultados] = useState<Resultado[]>(() => {
    const eng = new HardenerEngine(virtualSystem, backups);
    return eng.auditar(REGRAS_PADRAO);
  });

  const hasPendingBackups = backups.some((b) => !b.revertida && b.entradas.length > 0);

  // --- ACTIONS ---
  const handleAudit = useCallback(() => {
    setIsProcessing(true);
    setModoAtual('audit');
    setTimeout(() => {
      const res = engine.auditar(regras);
      setResultados(res);
      setIsProcessing(false);
    }, 200);
  }, [engine, regras]);

  const handleDryRun = useCallback(() => {
    setIsProcessing(true);
    setModoAtual('enforce --dry-run');
    setTimeout(() => {
      const res = engine.aplicarDryRun(regras);
      setResultados(res);
      setIsProcessing(false);
    }, 250);
  }, [engine, regras]);

  const handleApply = useCallback(() => {
    setIsProcessing(true);
    setModoAtual('enforce --apply');
    setTimeout(() => {
      const { resultados: res, erroTrava, sessaoCriada } = engine.aplicarApply(regras);
      if (erroTrava) {
        alert(`RECUSADO: ${erroTrava}`);
        setIsProcessing(false);
        return;
      }
      setResultados(res);
      setVirtualSystem({ ...engine.system });
      if (sessaoCriada) {
        setBackups([...engine.backups]);
      }
      setIsProcessing(false);
    }, 350);
  }, [engine, regras]);

  const handleRollback = useCallback((sessionId?: string) => {
    setIsProcessing(true);
    setTimeout(() => {
      const resRollback = engine.reverter(sessionId);
      if (!resRollback.sucesso) {
        alert(`Erro: ${resRollback.erro}`);
      } else {
        setVirtualSystem({ ...engine.system });
        setBackups([...engine.backups]);
        // Re-audit to update compliance state after rollback
        const resAudit = engine.auditar(regras);
        setResultados(resAudit);
        setModoAtual('audit (pós-rollback)');
      }
      setIsProcessing(false);
    }, 300);
  }, [engine, regras]);

  // Single rule audit / apply
  const handleAuditSingle = useCallback((regraId: string) => {
    const targetRegra = regras.find((r) => r.id === regraId);
    if (!targetRegra) return;
    const { resultado } = engine.verificarRegra(targetRegra);
    setResultados((prev) => prev.map((r) => (r.regra.id === regraId ? resultado : r)));
  }, [engine, regras]);

  const handleApplySingle = useCallback((regraId: string) => {
    const targetRegra = regras.find((r) => r.id === regraId);
    if (!targetRegra) return;
    const { resultados: res, erroTrava } = engine.aplicarApply([targetRegra]);
    if (erroTrava) {
      alert(`RECUSADO: ${erroTrava}`);
      return;
    }
    setVirtualSystem({ ...engine.system });
    setBackups([...engine.backups]);
    setResultados((prev) =>
      prev.map((r) => (r.regra.id === regraId && res[0] ? res[0] : r))
    );
  }, [engine, regras]);

  // Terminal CLI Command Execution Simulator
  const handleExecuteCommand = useCallback((cmd: string): { output: string; exitCode: number } => {
    const parts = cmd.trim().split(/\s+/);

    if (cmd === 'help' || cmd === '--help') {
      return {
        output: `Uso da CLI do Hardener:
  python -m hardener audit                     # verifica conformidade (não altera nada)
  python -m hardener enforce                   # dry-run: mostra o que mudaria
  python -m hardener enforce --apply           # aplica alterações (somente na VM autorizada)
  python -m hardener rollback [--sessao ID]    # restaura a última sessão de backup
  python -m hardener report [--formato json]   # exibe o último relatório
  python -m hardener validar                   # valida os YAML de regras da política
  
Opções: --regra <ID>, --dor <1-6>, --json <ARQ>`,
        exitCode: 0,
      };
    }

    if (cmd.startsWith('sudo touch /etc/hardener-vm')) {
      setVirtualSystem((prev) => ({
        ...prev,
        hasVmMarker: true,
        files: { ...prev.files, '/etc/hardener-vm': '# Marcador de segurança' },
      }));
      return {
        output: 'Marcador /etc/hardener-vm criado. Trava de segurança desarmada.',
        exitCode: 0,
      };
    }

    if (cmd.startsWith('sudo rm') && cmd.includes('hardener-vm')) {
      setVirtualSystem((prev) => {
        const nextFiles = { ...prev.files };
        delete nextFiles['/etc/hardener-vm'];
        return {
          ...prev,
          hasVmMarker: false,
          files: nextFiles,
        };
      });
      return {
        output: 'Marcador /etc/hardener-vm removido. Trava de segurança armada.',
        exitCode: 0,
      };
    }

    if (!cmd.includes('hardener')) {
      return {
        output: `bash: comando não reconhecido: '${cmd}'. Use os comandos do hardener ou 'help'.`,
        exitCode: 127,
      };
    }

    // Filter by rule or pain if specified in CLI args
    let regrasSelecionadas = [...regras];
    if (cmd.includes('--dor')) {
      const idx = parts.indexOf('--dor');
      const dorNum = parseInt(parts[idx + 1], 10) as DorAtiId;
      if (dorNum) {
        regrasSelecionadas = regrasSelecionadas.filter((r) => r.dor_ati.includes(dorNum));
      }
    }
    if (cmd.includes('--regra')) {
      const idx = parts.indexOf('--regra');
      const rid = parts[idx + 1];
      if (rid) {
        regrasSelecionadas = regrasSelecionadas.filter((r) => r.id === rid);
      }
    }

    // python -m hardener validar
    if (cmd.includes('validar')) {
      const pend = regras.filter((r) => r.referencia.includes('A CONFIRMAR'));
      let msg = `${regras.length} regra(s) válida(s) em rules/\n`;
      if (pend.length > 0) {
        msg += `${pend.length} regra(s) com referência CIS ainda A CONFIRMAR: ${pend.map((r) => r.id).join(', ')}`;
      }
      return { output: msg, exitCode: 0 };
    }

    // python -m hardener rollback
    if (cmd.includes('rollback')) {
      let sessaoId: string | undefined;
      if (cmd.includes('--sessao')) {
        const idx = parts.indexOf('--sessao');
        sessaoId = parts[idx + 1];
      }
      const res = engine.reverter(sessaoId);
      if (!res.sucesso) {
        return { output: `erro: ${res.erro}`, exitCode: 2 };
      }
      setVirtualSystem({ ...engine.system });
      setBackups([...engine.backups]);
      const resAudit = engine.auditar(regras);
      setResultados(resAudit);
      return { output: res.acoes.join('\n'), exitCode: 0 };
    }

    // python -m hardener offboarding --autorizados <file> [--apply]
    if (cmd.includes('offboarding')) {
      const isApply = cmd.includes('--apply');
      const csvSample = `usuario,nome,departamento,status\nroot,Superusuario Root,Sistemas,ativo\nadmin_ati,Administrador ATI,Infraestrutura,ativo\nsecops,Seguranca Operacional,SecOps,ativo\n`;
      const offRes = engine.executarOffboarding(csvSample, isApply);

      if (!offRes.sucesso && offRes.erro) {
        return {
          output: `RECUSADO: ${offRes.erro}`,
          exitCode: 2,
        };
      }

      if (isApply && offRes.sucesso) {
        setVirtualSystem({ ...engine.system });
        setBackups([...engine.backups]);
        const auditRes = engine.auditar(regras);
        setResultados(auditRes);
      }

      let out = `hardener ${HARDENER_VERSION} | modo: offboarding (${offRes.modo}) | plataforma: ${virtualSystem.plataforma}\n`;
      out += `Arquivo de autorizados: lista.csv (${offRes.autorizados.length} conta(s) homologada(s))\n`;
      out += `Contas autorizadas: [${offRes.autorizados.join(', ')}]\n\n`;

      if (offRes.contasNaoAutorizadas.length === 0) {
        out += `Conformidade total: nenhuma conta órfã ou não autorizada encontrada.\n`;
      } else {
        out += `Contas identificadas para revogação: [${offRes.contasNaoAutorizadas.join(', ')}]\n\n`;
        out += `Ações executadas:\n`;
        for (const acao of offRes.acoes) {
          out += `  - ${acao}\n`;
        }
        for (const mudanca of offRes.mudancas) {
          out += `  [ALTERADO] ${mudanca}\n`;
        }
      }

      return {
        output: out,
        exitCode: isApply ? 0 : 1,
      };
    }

    // python -m hardener report
    if (cmd.includes('report')) {
      const jsonReport = engine.gerarRelatorio(resultados, modoAtual);
      if (cmd.includes('json')) {
        return { output: JSON.stringify(jsonReport, null, 2), exitCode: 0 };
      }
      return { output: engine.relatorioTexto(jsonReport), exitCode: 0 };
    }

    // python -m hardener enforce
    if (cmd.includes('enforce')) {
      if (cmd.includes('--apply')) {
        const { resultados: res, erroTrava, sessaoCriada } = engine.aplicarApply(regrasSelecionadas);
        if (erroTrava) {
          return { output: `RECUSADO: ${erroTrava}`, exitCode: 2 };
        }
        setResultados(res);
        setVirtualSystem({ ...engine.system });
        if (sessaoCriada) {
          setBackups([...engine.backups]);
        }
        const rep = engine.gerarRelatorio(res, 'enforce --apply');
        return { output: engine.relatorioTexto(rep), exitCode: engine.codigoSaida(res) };
      } else {
        const res = engine.aplicarDryRun(regrasSelecionadas);
        setResultados(res);
        const rep = engine.gerarRelatorio(res, 'enforce --dry-run');
        return { output: engine.relatorioTexto(rep), exitCode: engine.codigoSaida(res) };
      }
    }

    // python -m hardener audit (default)
    if (cmd.includes('audit')) {
      const res = engine.auditar(regrasSelecionadas);
      setResultados(res);
      setModoAtual('audit');
      const rep = engine.gerarRelatorio(res, 'audit');
      return { output: engine.relatorioTexto(rep), exitCode: engine.codigoSaida(res) };
    }

    return { output: 'Comando não reconhecido.', exitCode: 2 };
  }, [engine, regras, resultados, modoAtual]);

  // System State Resets
  const handleResetSystem = useCallback(() => {
    setVirtualSystem({
      hostname: 'rhel9-vm-ati',
      plataforma: 'rhel9',
      isRoot: true,
      hasVmMarker: true,
      files: { ...INITIAL_FILES },
      services: {
        sshd: { active: true, validSyntax: true, simulatedReloadFailure: false },
        firewalld: { active: false, validSyntax: true, simulatedReloadFailure: false },
        sudoers: { active: true, validSyntax: true, simulatedReloadFailure: false },
      },
      simulatedSshdTFail: false,
      simulatedReloadFail: false,
    });
    setBackups([]);
    setTimeout(() => {
      const eng = new HardenerEngine(
        {
          hostname: 'rhel9-vm-ati',
          plataforma: 'rhel9',
          isRoot: true,
          hasVmMarker: true,
          files: { ...INITIAL_FILES },
          services: {
            sshd: { active: true, validSyntax: true, simulatedReloadFailure: false },
            firewalld: { active: false, validSyntax: true, simulatedReloadFailure: false },
            sudoers: { active: true, validSyntax: true, simulatedReloadFailure: false },
          },
          simulatedSshdTFail: false,
          simulatedReloadFail: false,
        },
        []
      );
      setResultados(eng.auditar(regras));
      setModoAtual('audit');
    }, 100);
  }, [regras]);

  const handleUpdateFile = useCallback((path: string, content: string) => {
    setVirtualSystem((prev) => ({
      ...prev,
      files: {
        ...prev.files,
        [path]: content,
      },
    }));
  }, []);

  const handleToggleSimulatedSshdTFail = useCallback(() => {
    setVirtualSystem((prev) => ({
      ...prev,
      simulatedSshdTFail: !prev.simulatedSshdTFail,
    }));
  }, []);

  const handleToggleSimulatedReloadFail = useCallback(() => {
    setVirtualSystem((prev) => ({
      ...prev,
      simulatedReloadFail: !prev.simulatedReloadFail,
    }));
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onAudit={handleAudit}
        onDryRun={handleDryRun}
        onApply={handleApply}
        onRollback={() => handleRollback()}
        onOffboarding={() => {
          setActiveTab('terminal');
        }}
        isProcessing={isProcessing}
        hasPendingBackups={hasPendingBackups}
        hasVmMarker={virtualSystem.hasVmMarker}
        isRoot={virtualSystem.isRoot}
      />

      {/* Safety Banner & VM Latch Status */}
      <StatusBanner
        isRoot={virtualSystem.isRoot}
        setIsRoot={(val) => setVirtualSystem((prev) => ({ ...prev, isRoot: val }))}
        hasVmMarker={virtualSystem.hasVmMarker}
        setHasVmMarker={(val) => setVirtualSystem((prev) => ({ ...prev, hasVmMarker: val }))}
        platform={virtualSystem.plataforma}
        setPlatform={(val) => setVirtualSystem((prev) => ({ ...prev, plataforma: val }))}
        hostname={virtualSystem.hostname}
      />

      {/* Main Tab Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <DashboardTab
            regras={regras}
            resultados={resultados}
            onAuditSingle={handleAuditSingle}
            onApplySingle={handleApplySingle}
            selectedDor={selectedDor}
            setSelectedDor={setSelectedDor}
            modoAtual={modoAtual}
          />
        )}

        {activeTab === 'terminal' && (
          <TerminalTab onExecuteCommand={handleExecuteCommand} />
        )}

        {activeTab === 'policy' && (
          <PolicyEditorTab regras={regras} onUpdateRegras={setRegras} />
        )}

        {activeTab === 'backups' && (
          <BackupsTab backups={backups} onRollbackSession={handleRollback} />
        )}

        {activeTab === 'system' && (
          <VirtualSystemTab
            system={virtualSystem}
            onUpdateFile={handleUpdateFile}
            onToggleSimulatedSshdTFail={handleToggleSimulatedSshdTFail}
            onToggleSimulatedReloadFail={handleToggleSimulatedReloadFail}
            onResetSystem={handleResetSystem}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-2">
          <span>
            Hardening RedHat ATI · Red Hat Enterprise Linux 9 & Rocky/Alma 9 · CIS Benchmark v1.0
          </span>
          <span className="font-mono text-[11px] text-slate-600">
            Escopo ATI Recife / PE · Contrato e motor declarativo em YAML
          </span>
        </div>
      </footer>
    </div>
  );
};

export default App;
