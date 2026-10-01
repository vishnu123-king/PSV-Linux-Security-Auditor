import React, { useState, useEffect } from 'react';
import { GitCompare, ArrowRight, ShieldCheck, AlertCircle, Calendar, CheckCircle } from 'lucide-react';
import { DriftComparison, Host } from '../types';
import { api } from '../api/client';

interface DriftProps {
  hosts: Host[];
}

export const Drift: React.FC<DriftProps> = ({ hosts }) => {
  const [selectedHostId, setSelectedHostId] = useState(hosts[0]?.id || '');
  const [driftData, setDriftData] = useState<DriftComparison | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (hosts.length > 0 && !selectedHostId) {
      setSelectedHostId(hosts[0].id);
    }
  }, [hosts, selectedHostId]);

  useEffect(() => {
    if (!selectedHostId) {
      setDriftData(null);
      return;
    }
    setLoading(true);
    api.fetch<DriftComparison>(`/drift/compare?host_id=${selectedHostId}`)
      .then(setDriftData)
      .catch(() => setDriftData(null))
      .finally(() => setLoading(false));
  }, [selectedHostId]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Configuration Drift Detection</h1>
          <p className="text-slate-400 text-sm mt-1">
            Isolates unauthorized, ad-hoc, or accidental changes across historical assessments.
          </p>
        </div>

        {hosts.length > 0 && (
          <div className="flex items-center gap-3">
            <label className="text-xs text-slate-400 font-semibold">Select Host:</label>
            <select
              value={selectedHostId}
              onChange={(e) => setSelectedHostId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white"
            >
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.name} ({h.hostname})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {hosts.length === 0 ? (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 p-12 text-center space-y-2 max-w-md mx-auto">
          <GitCompare className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <h3 className="text-sm font-semibold text-white">No hosts available</h3>
          <p className="text-xs text-slate-400">
            Register a Linux host and run at least two assessments to compute configuration drift.
          </p>
        </div>
      ) : !driftData || driftData.total_changes === 0 ? (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 p-12 text-center space-y-2 max-w-md mx-auto">
          <CheckCircle className="w-8 h-8 text-emerald-500/50 mx-auto mb-2" />
          <h3 className="text-sm font-semibold text-white">No configuration drift detected</h3>
          <p className="text-xs text-slate-400">
            {loading ? 'Evaluating drift metrics...' : 'All monitored security controls match baseline state.'}
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Comparison Meta Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-4">
              <span className="text-slate-500 font-bold uppercase tracking-wider block mb-1">
                Baseline Assessment
              </span>
              <div className="font-mono text-cyan-400 font-bold">{driftData.baseline_assessment_id?.slice(0, 8)}</div>
              <div className="text-slate-400 mt-1 flex items-center gap-1.5 text-[11px]">
                <Calendar className="w-3.5 h-3.5" />
                <span>{driftData.baseline_date ? new Date(driftData.baseline_date).toLocaleDateString() : 'Baseline'}</span>
              </div>
            </div>

            <div className="rounded-xl bg-slate-900 border border-slate-800 p-4">
              <span className="text-slate-500 font-bold uppercase tracking-wider block mb-1">
                Current Assessment
              </span>
              <div className="font-mono text-cyan-400 font-bold">{driftData.target_assessment_id?.slice(0, 8)}</div>
              <div className="text-slate-400 mt-1 flex items-center gap-1.5 text-[11px]">
                <Calendar className="w-3.5 h-3.5" />
                <span>{driftData.target_date ? new Date(driftData.target_date).toLocaleDateString() : 'Target'}</span>
              </div>
            </div>

            <div className="rounded-xl bg-slate-900 border border-slate-800 p-4">
              <span className="text-slate-500 font-bold uppercase tracking-wider block mb-1">
                Total Control Drift
              </span>
              <div className="text-2xl font-black text-amber-400">{driftData.total_changes} Changes</div>
              <div className="text-slate-400 mt-1 text-[11px]">
                Modifications isolated between baselines
              </div>
            </div>
          </div>

          {/* Drift Diff Table */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-sm font-bold text-white">Observed Discrepancies</h2>
              <span className="text-xs text-slate-400">
                Notice: Configuration changes are reported objectively without assuming malice.
              </span>
            </div>

            <div className="divide-y divide-slate-800/80">
              {driftData.changes.map((c, i) => (
                <div key={i} className="p-5 space-y-3 hover:bg-slate-850 transition text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                        {c.category}
                      </span>
                      <span className="font-mono font-bold text-slate-100">{c.control}</span>
                    </div>
                    {c.severity && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {c.severity}
                      </span>
                    )}
                  </div>

                  <p className="text-slate-400">{c.description}</p>

                  {/* Visual Side-by-Side Diff */}
                  <div className="grid grid-cols-2 gap-4 pt-1 font-mono text-xs">
                    <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-slate-400">
                      <span className="text-[10px] text-slate-500 block mb-0.5 font-sans font-semibold uppercase">
                        Previous Value
                      </span>
                      <span className="text-rose-400 font-bold">{String(c.previous_value)}</span>
                    </div>

                    <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-slate-400">
                      <span className="text-[10px] text-slate-500 block mb-0.5 font-sans font-semibold uppercase">
                        Current Value
                      </span>
                      <span className="text-emerald-400 font-bold">{String(c.current_value)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
