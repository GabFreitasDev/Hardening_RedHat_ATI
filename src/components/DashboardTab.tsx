import React, { useState } from 'react';
import {
  Shield,
  CheckCircle,
  AlertCircle,
  AlertTriangle,
  Clock,
  Filter,
  Search,
  ChevronDown,
  ChevronUp,
  FileText,
  RefreshCw,
  ExternalLink,
  Info
} from 'lucide-react';
import { DORES_INFO, DorAtiId, NOMES_DORES, Regra, Resultado, StatusRegra } from '../types';

interface DashboardTabProps {
  regras: Regra[];
  resultados: Resultado[];
  onAuditSingle: (regraId: string) => void;
  onApplySingle: (regraId: string) => void;
  selectedDor: DorAtiId | null;
  setSelectedDor: (dor: DorAtiId | null) => void;
  modoAtual: string;
}

export const DashboardTab: React.FC<DashboardTabProps> = ({
  regras,
  resultados,
  onAuditSingle,
  onApplySingle,
  selectedDor,
  setSelectedDor,
  modoAtual,
}) => {
  const [busca, setBusca] = useState('');
  const [filtroStatus, setFiltroStatus] = useState<string>('todos');
  const [filtroSeveridade, setFiltroSeveridade] = useState<string>('todos');
  const [expandedRegra, setExpandedRegra] = useState<string | null>(null);

  // Status mapping and counts
  const resultMap = new Map<string, Resultado>();
  resultados.forEach(r => resultMap.set(r.regra.id, r));

  const totalRegras = regras.length;
  let conformesCount = 0;
  let corrigidosCount = 0;
  let seriaCorrigidoCount = 0;
  let naoConformeCount = 0;
  let falhouCount = 0;
  let puladoCount = 0;
  let erroCount = 0;

  regras.forEach(r => {
    const res = resultMap.get(r.id);
    const status = res?.status || 'NAO_CONFORME';
    if (status === 'CONFORME') conformesCount++;
    else if (status === 'CORRIGIDO') corrigidosCount++;
    else if (status === 'SERIA_CORRIGIDO') seriaCorrigidoCount++;
    else if (status === 'NAO_CONFORME') naoConformeCount++;
    else if (status === 'FALHOU') falhouCount++;
    else if (status === 'PULADO') puladoCount++;
    else if (status === 'ERRO') erroCount++;
  });

  const totalAvaliadas = totalRegras - puladoCount;
  const scorePercent = totalAvaliadas > 0 ? Math.round(((conformesCount + corrigidosCount) / totalAvaliadas) * 100) : 0;

  // Filter rules
  const regrasFiltradas = regras.filter(regra => {
    const res = resultMap.get(regra.id);
    const status = res?.status || 'NAO_CONFORME';

    if (selectedDor && !regra.dor_ati.includes(selectedDor)) {
      return false;
    }
    if (filtroStatus !== 'todos' && status !== filtroStatus) {
      return false;
    }
    if (filtroSeveridade !== 'todos' && regra.severidade !== filtroSeveridade) {
      return false;
    }
    if (busca.trim()) {
      const termo = busca.toLowerCase();
      const matchId = regra.id.toLowerCase().includes(termo);
      const matchDesc = regra.descricao.toLowerCase().includes(termo);
      const matchRef = regra.referencia.toLowerCase().includes(termo);
      const matchPrim = regra.primitiva.toLowerCase().includes(termo);
      return matchId || matchDesc || matchRef || matchPrim;
    }
    return true;
  });

  const getStatusBadge = (status: StatusRegra) => {
    switch (status) {
      case 'CONFORME':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/60">
            <CheckCircle className="w-3 h-3 text-emerald-400" />
            CONFORME
          </span>
        );
      case 'CORRIGIDO':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
            <CheckCircle className="w-3 h-3 text-cyan-400" />
            CORRIGIDO
          </span>
        );
      case 'SERIA_CORRIGIDO':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/60">
            <Clock className="w-3 h-3 text-amber-400" />
            SERIA CORRIGIDO
          </span>
        );
      case 'NAO_CONFORME':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/60">
            <AlertCircle className="w-3 h-3 text-rose-400" />
            NÃO CONFORME
          </span>
        );
      case 'FALHOU':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-300 border border-red-700">
            <AlertTriangle className="w-3 h-3 text-red-400" />
            FALHOU
          </span>
        );
      case 'PULADO':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            PULADO
          </span>
        );
      case 'ERRO':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-950/80 text-purple-300 border border-purple-800/60">
            <AlertTriangle className="w-3 h-3 text-purple-400" />
            ERRO
          </span>
        );
    }
  };

  const getSeveridadeBadge = (severidade: string) => {
    switch (severidade) {
      case 'critica':
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-red-950 text-red-300 border border-red-800/60">crítica</span>;
      case 'alta':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold uppercase bg-orange-950 text-orange-300 border border-orange-800/60">alta</span>;
      case 'media':
        return <span className="px-2 py-0.5 rounded text-[11px] font-medium uppercase bg-amber-950 text-amber-300 border border-amber-800/60">média</span>;
      case 'baixa':
        return <span className="px-2 py-0.5 rounded text-[11px] font-medium uppercase bg-slate-800 text-slate-300 border border-slate-700">baixa</span>;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Compliance Overview Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Score & Gauge */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-sm">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Índice de Conformidade
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Modo: {modoAtual}
              </span>
            </div>
            <div className="mt-4 flex items-baseline gap-3">
              <span className={`text-4xl font-extrabold tracking-tight ${scorePercent >= 80 ? 'text-emerald-400' : scorePercent >= 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                {scorePercent}%
              </span>
              <span className="text-xs text-slate-400">
                {conformesCount + corrigidosCount} de {totalAvaliadas} conformes
              </span>
            </div>
            {/* Progress bar */}
            <div className="mt-3 w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
              <div
                className={`h-2.5 rounded-full transition-all duration-500 ${scorePercent >= 80 ? 'bg-emerald-500' : scorePercent >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`}
                style={{ width: `${scorePercent}%` }}
              ></div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs text-slate-400 flex items-center justify-between">
            <span>Código de saída esperado:</span>
            <span className={`font-mono font-bold px-2 py-0.5 rounded ${falhouCount > 0 || erroCount > 0 ? 'bg-red-950 text-red-300' : naoConformeCount > 0 || seriaCorrigidoCount > 0 ? 'bg-amber-950 text-amber-300' : 'bg-emerald-950 text-emerald-300'}`}>
              {falhouCount > 0 || erroCount > 0 ? 'rc=2 (erro/falha)' : naoConformeCount > 0 || seriaCorrigidoCount > 0 ? 'rc=1 (pendências)' : 'rc=0 (tudo conforme)'}
            </span>
          </div>
        </div>

        {/* Status Counters */}
        <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Conformes</span>
            <span className="text-2xl font-bold text-emerald-400 mt-2">{conformesCount}</span>
            <span className="text-[11px] text-slate-500">Já validados</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Corrigidos</span>
            <span className="text-2xl font-bold text-cyan-400 mt-2">{corrigidosCount}</span>
            <span className="text-[11px] text-slate-500">Aplicados via apply</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Seria Corrigido</span>
            <span className="text-2xl font-bold text-amber-400 mt-2">{seriaCorrigidoCount}</span>
            <span className="text-[11px] text-slate-500">Dry-run simulação</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Não Conformes</span>
            <span className="text-2xl font-bold text-rose-400 mt-2">{naoConformeCount}</span>
            <span className="text-[11px] text-slate-500">Requerem correção</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Falhas / Erros</span>
            <span className="text-2xl font-bold text-purple-400 mt-2">{falhouCount + erroCount}</span>
            <span className="text-[11px] text-slate-500">Validação / Syntax</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Pulados</span>
            <span className="text-2xl font-bold text-slate-400 mt-2">{puladoCount}</span>
            <span className="text-[11px] text-slate-500">Outra plataforma</span>
          </div>
        </div>
      </div>

      {/* ATI Pains Cards (Dores 1 a 6) */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider">
              Conformidade por Dores da ATI (Agência Estadual de TI)
            </h3>
          </div>
          {selectedDor && (
            <button
              onClick={() => setSelectedDor(null)}
              className="text-xs text-red-400 hover:text-red-300 font-medium underline"
            >
              Limpar filtro de dor
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {([1, 2, 3, 4, 5, 6] as DorAtiId[]).map(dorId => {
            const dor = DORES_INFO[dorId];
            const regrasDaDor = regras.filter(r => r.dor_ati.includes(dorId));
            const conformesNaDor = regrasDaDor.filter(r => {
              const res = resultMap.get(r.id);
              return res?.status === 'CONFORME' || res?.status === 'CORRIGIDO';
            }).length;
            const percent = regrasDaDor.length > 0 ? Math.round((conformesNaDor / regrasDaDor.length) * 100) : 0;
            const isSelected = selectedDor === dorId;

            return (
              <div
                key={dorId}
                onClick={() => setSelectedDor(isSelected ? null : dorId)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-slate-800/90 border-red-500 ring-2 ring-red-500/20 shadow-lg'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 rounded-md bg-slate-800 flex items-center justify-center font-bold text-xs text-red-400 border border-slate-700">
                      {dorId}
                    </span>
                    <span className="font-semibold text-sm text-white">{dor.nome}</span>
                  </div>
                  <span className="text-xs font-mono font-medium text-slate-300">
                    {conformesNaDor}/{regrasDaDor.length}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mt-2 line-clamp-2 min-h-[32px]">
                  {dor.descricao}
                </p>

                <div className="mt-3">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
                    <span>Progresso</span>
                    <span className="font-mono">{percent}%</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-1.5 rounded-full ${percent === 100 ? 'bg-emerald-500' : percent > 50 ? 'bg-amber-500' : 'bg-red-500'}`}
                      style={{ width: `${percent}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Rules Table & Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {/* Filter bar */}
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-900/60">
          <div className="flex items-center gap-2 flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={busca}
              onChange={(e) => setBusca(e.target.value)}
              placeholder="Buscar regra por ID (ex: SSH-001), descrição, primitiva..."
              className="bg-slate-800/80 border border-slate-700 text-slate-100 text-xs rounded-lg px-3 py-1.5 w-full focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs">
            {/* Filter by Status */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Status:</span>
              <select
                value={filtroStatus}
                onChange={(e) => setFiltroStatus(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-2 py-1 focus:outline-none"
              >
                <option value="todos">Todos ({totalRegras})</option>
                <option value="CONFORME">Conforme</option>
                <option value="CORRIGIDO">Corrigido</option>
                <option value="SERIA_CORRIGIDO">Seria Corrigido</option>
                <option value="NAO_CONFORME">Não Conforme</option>
                <option value="FALHOU">Falhou</option>
                <option value="PULADO">Pulado</option>
                <option value="ERRO">Erro</option>
              </select>
            </div>

            {/* Filter by Severity */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Severidade:</span>
              <select
                value={filtroSeveridade}
                onChange={(e) => setFiltroSeveridade(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-2 py-1 focus:outline-none"
              >
                <option value="todos">Todas</option>
                <option value="critica">Crítica</option>
                <option value="alta">Alta</option>
                <option value="media">Média</option>
                <option value="baixa">Baixa</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">ID / Regra</th>
                <th className="py-3 px-4">Severidade</th>
                <th className="py-3 px-4">Dores ATI</th>
                <th className="py-3 px-4">Estado Atual vs Esperado</th>
                <th className="py-3 px-4">CIS Benchmark</th>
                <th className="py-3 px-4 text-right">Ação</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {regrasFiltradas.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    Nenhuma regra corresponde aos filtros selecionados.
                  </td>
                </tr>
              ) : (
                regrasFiltradas.map(regra => {
                  const res = resultMap.get(regra.id);
                  const status = res?.status || 'NAO_CONFORME';
                  const isExpanded = expandedRegra === regra.id;
                  const isPendingCis = regra.referencia.includes('A CONFIRMAR');

                  return (
                    <React.Fragment key={regra.id}>
                      <tr className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 whitespace-nowrap">
                          {getStatusBadge(status)}
                        </td>

                        <td className="py-3 px-4">
                          <div className="font-mono font-bold text-white text-xs">{regra.id}</div>
                          <div className="text-slate-300 text-xs mt-0.5 line-clamp-1">{regra.descricao}</div>
                        </td>

                        <td className="py-3 px-4 whitespace-nowrap">
                          {getSeveridadeBadge(regra.severidade)}
                        </td>

                        <td className="py-3 px-4 whitespace-nowrap">
                          <div className="flex gap-1 flex-wrap">
                            {regra.dor_ati.map(d => (
                              <button
                                key={d}
                                onClick={() => setSelectedDor(d)}
                                className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 text-[10px] font-mono border border-slate-700"
                                title={`Dor ${d}: ${NOMES_DORES[d]}`}
                              >
                                Dor {d}
                              </button>
                            ))}
                          </div>
                        </td>

                        <td className="py-3 px-4 max-w-xs">
                          {res?.atual !== undefined ? (
                            <div className="font-mono text-[11px] truncate">
                              <span className="text-slate-400">atual: </span>
                              <span className={status === 'CONFORME' || status === 'CORRIGIDO' ? 'text-emerald-300' : 'text-rose-300'}>
                                {res.atual || '—'}
                              </span>
                              <br />
                              <span className="text-slate-400">esperado: </span>
                              <span className="text-slate-200">{res.esperado || '—'}</span>
                            </div>
                          ) : (
                            <span className="text-slate-500 italic">Não verificado</span>
                          )}
                        </td>

                        <td className="py-3 px-4 max-w-xs">
                          <div className="flex items-center gap-1.5">
                            <span className={`text-[11px] truncate ${isPendingCis ? 'text-amber-400 font-mono' : 'text-slate-300'}`}>
                              {regra.referencia}
                            </span>
                            {isPendingCis && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-950 text-amber-300 border border-amber-800">
                                pendente
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => setExpandedRegra(isExpanded ? null : regra.id)}
                              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                              title="Ver detalhes da regra"
                            >
                              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </button>
                            <button
                              onClick={() => onAuditSingle(regra.id)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] border border-slate-700"
                            >
                              Checar
                            </button>
                            <button
                              onClick={() => onApplySingle(regra.id)}
                              className="px-2 py-1 rounded bg-red-950/80 hover:bg-red-900/80 text-red-200 text-[11px] border border-red-800/60 font-semibold"
                            >
                              Aplicar
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Expanded Details Row */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              <div>
                                <h4 className="font-semibold text-slate-200 mb-1 flex items-center gap-1.5">
                                  <Info className="w-3.5 h-3.5 text-blue-400" />
                                  Detalhes Técnicos & Primitiva
                                </h4>
                                <div className="space-y-1 text-slate-300 bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-[11px]">
                                  <div><span className="text-slate-500">Primitiva:</span> {regra.primitiva}</div>
                                  <div><span className="text-slate-500">Plataforma alvo:</span> {regra.plataforma}</div>
                                  <div><span className="text-slate-500">Origem:</span> {regra.origem || 'rules/*.yaml'}</div>
                                  {regra.recarregar && (
                                    <div><span className="text-slate-500">Recarga após corrigir:</span> {regra.recarregar} (com validação prévia)</div>
                                  )}
                                  {res?.detalhe && (
                                    <div className="pt-1 text-amber-300 border-t border-slate-800">
                                      <span className="text-slate-500">Diagnóstico:</span> {res.detalhe}
                                    </div>
                                  )}
                                </div>
                              </div>

                              <div>
                                <h4 className="font-semibold text-slate-200 mb-1 flex items-center gap-1.5">
                                  <FileText className="w-3.5 h-3.5 text-emerald-400" />
                                  Parâmetros Declarados (YAML)
                                </h4>
                                <pre className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto">
                                  {JSON.stringify(regra.parametros, null, 2)}
                                </pre>
                              </div>
                            </div>

                            {res?.mudancas && res.mudancas.length > 0 && (
                              <div className="bg-cyan-950/40 border border-cyan-800/40 rounded-lg p-3 text-xs text-cyan-200">
                                <span className="font-semibold">Alterações realizadas na VM:</span>
                                <ul className="list-disc list-inside mt-1 font-mono text-[11px] text-cyan-300">
                                  {res.mudancas.map((m, idx) => (
                                    <li key={idx}>{m}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
