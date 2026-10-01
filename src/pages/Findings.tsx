import React, { useState } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Search,
  CheckCircle,
  Clock,
  Wrench,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { Finding, Severity } from '../types';
import { api } from '../api/client';

interface FindingsProps {
  findings: Finding[];
  onRefresh: () => void;
  onPlanRemediation: (findingId: string) => void;
}

export const Findings: React.FC<FindingsProps> = ({ findings, onRefresh, onPlanRemediation }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q) ||
        f.control.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleAcknowledge = async (id: string) => {
    await api.fetch(`/findings/${id}/acknowledge`, { method: 'POST' });
    onRefresh();
  };

  const handleResolve = async (id: string) => {
    await api.fetch(`/findings/${id}/resolve`, { method: 'POST' });
    onRefresh();
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings</h1>
          <p className="text-slate-400 text-sm mt-1">
            Detected configuration discrepancies and vulnerabilities mapped to benchmark rules.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1.5 rounded-md font-semibold transition ${
                selectedSeverity === sev
                  ? 'bg-cyan-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by Rule ID or Control..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Findings List */}
      {filtered.length === 0 ? (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 p-12 text-center space-y-2">
          <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <h3 className="text-sm font-semibold text-white">
            {findings.length === 0 ? 'No findings available' : 'No findings match filter'}
          </h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            {findings.length === 0
              ? 'Run a security assessment on an authorized target to detect compliance discrepancies.'
              : 'Try clearing the search query or adjusting the severity filter.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((f) => {
          const isExpanded = expandedFindingId === f.id;
          return (
            <div
              key={f.id}
              className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm transition"
            >
              {/* Row Header */}
              <div
                onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-850 select-none"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`px-2.5 py-1 rounded text-[10px] font-bold tracking-wider ${
                      f.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : f.severity === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-mono text-xs font-bold text-cyan-400">{f.rule_id}</span>
                  <span className="font-semibold text-xs text-slate-100">{f.title}</span>
                </div>

                <div className="flex items-center gap-4">
                  <span className="font-mono text-[11px] text-slate-400 hidden md:block">
                    {f.control}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      f.status === 'RESOLVED'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : f.status === 'ACKNOWLEDGED'
                        ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {f.status}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  )}
                </div>
              </div>

              {/* Expanded Detail Panel */}
              {isExpanded && (
                <div className="p-5 bg-slate-950/80 border-t border-slate-800/80 space-y-4 text-xs">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-1">
                        Observed State
                      </span>
                      <div className="font-mono text-rose-400 font-bold">
                        {String(f.actual_value)}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-1">
                        Benchmark Expected State
                      </span>
                      <div className="font-mono text-emerald-400 font-bold">
                        {String(f.expected_value)}
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-slate-300 font-semibold mb-1">Security Rationale</h4>
                    <p className="text-slate-400 leading-relaxed">{f.rationale}</p>
                  </div>

                  <div>
                    <h4 className="text-slate-300 font-semibold mb-1">Remediation Guidance</h4>
                    <p className="text-slate-400 font-mono text-[11px] bg-slate-900 p-2.5 rounded border border-slate-800">
                      {f.remediation_guidance}
                    </p>
                  </div>

                  <div className="pt-2 flex items-center justify-between border-t border-slate-800/80">
                    <div className="space-x-2">
                      {f.status === 'OPEN' && (
                        <button
                          onClick={() => handleAcknowledge(f.id)}
                          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
                        >
                          Acknowledge
                        </button>
                      )}
                      {f.status !== 'RESOLVED' && (
                        <button
                          onClick={() => handleResolve(f.id)}
                          className="px-3 py-1.5 rounded bg-emerald-700/80 hover:bg-emerald-600 text-white text-xs font-semibold transition"
                        >
                          Mark Resolved
                        </button>
                      )}
                    </div>

                    <button
                      onClick={() => onPlanRemediation(f.id)}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
                    >
                      <Wrench className="w-3.5 h-3.5" />
                      <span>Formulate Remediation Plan</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
        </div>
      )}
    </div>
  );
};
