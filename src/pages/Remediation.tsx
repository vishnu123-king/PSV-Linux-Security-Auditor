import React, { useState, useEffect } from 'react';
import {
  Wrench,
  CheckCircle,
  ShieldAlert,
  ArrowRight,
  RotateCcw,
  Lock,
  FileCheck2,
  Terminal,
} from 'lucide-react';
import { Finding, Remediation } from '../types';
import { api } from '../api/client';

interface RemediationProps {
  findings: Finding[];
  onRefresh: () => void;
}

export const RemediationPage: React.FC<RemediationProps> = ({ findings, onRefresh }) => {
  const [plans, setPlans] = useState<Remediation[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<Remediation | null>(null);

  const loadPlans = () => {
    api.fetch<Remediation[]>('/remediation').then((r) => {
      setPlans(r);
      if (r.length > 0) setSelectedPlan(r[0]);
    });
  };

  useEffect(() => {
    loadPlans();
  }, []);

  const handleApprove = async (planId: string) => {
    await api.fetch(`/remediation/${planId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved_by: 'Lead Security Architect' }),
    });
    loadPlans();
  };

  const handleExecute = async (planId: string) => {
    await api.fetch(`/remediation/${planId}/execute`, { method: 'POST' });
    loadPlans();
    onRefresh();
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Remediation & Hardening Controls
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Strict approval gatekeeper: Automated backup creation, dry-run diff inspection, and verified rollback.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Proposed Plans */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Active Hardening Plans ({plans.length})
          </h3>

          {plans.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-500">
              No remediation plans created yet. Formulate plans from the Findings panel.
            </div>
          ) : (
            plans.map((p) => {
              const isSelected = selectedPlan?.id === p.id;
              return (
                <div
                  key={p.id}
                  onClick={() => setSelectedPlan(p)}
                  className={`p-4 rounded-xl border cursor-pointer transition select-none ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/40'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-400">{p.id}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        p.status === 'APPLIED'
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : p.status === 'APPROVED'
                          ? 'bg-cyan-500/20 text-cyan-400'
                          : 'bg-amber-500/20 text-amber-400'
                      }`}
                    >
                      {p.status}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-200 line-clamp-1">{p.title}</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">{p.target_file}</div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Plan Approval & Execution Detail */}
        <div className="lg:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-6">
          {selectedPlan ? (
            <>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-white">{selectedPlan.title}</h2>
                  <p className="text-xs text-slate-400 mt-1">{selectedPlan.description}</p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase font-bold block">Status</span>
                  <span className="text-xs font-bold text-cyan-400 font-mono">
                    {selectedPlan.status}
                  </span>
                </div>
              </div>

              <div className="space-y-4 text-xs">
                {/* Proposed Diff */}
                <div>
                  <h4 className="text-slate-400 font-semibold mb-1">Proposed Configuration Diff</h4>
                  <pre className="p-3 rounded-lg bg-slate-950 text-slate-300 font-mono text-[11px] border border-slate-800 whitespace-pre-wrap">
                    {selectedPlan.proposed_diff || 'No text diff available'}
                  </pre>
                </div>

                {/* Commands */}
                <div>
                  <h4 className="text-slate-400 font-semibold mb-1">
                    Commands To Execute (Requires Explicit Sign-Off)
                  </h4>
                  <div className="p-3 rounded-lg bg-slate-950 font-mono text-[11px] text-emerald-400 border border-slate-800 space-y-1">
                    {selectedPlan.commands.map((cmd, i) => (
                      <div key={i} className="flex gap-2">
                        <span className="text-slate-600 select-none">$</span>
                        <span>{cmd}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Rollback & Backup Details */}
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1 text-slate-400">
                  <div>
                    <strong>Backup Location:</strong>{' '}
                    <span className="font-mono text-slate-300">{selectedPlan.backup_path}</span>
                  </div>
                  <div>
                    <strong>Rollback Safety:</strong> Configuration is restored automatically upon error.
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-400 text-xs">
                    <Lock className="w-4 h-4 text-amber-400" />
                    <span>Explicit approval required before applying changes.</span>
                  </div>

                  <div className="space-x-3">
                    {selectedPlan.status === 'PENDING_APPROVAL' && (
                      <button
                        onClick={() => handleApprove(selectedPlan.id)}
                        className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition"
                      >
                        Approve Hardening Plan
                      </button>
                    )}

                    {selectedPlan.status === 'APPROVED' && (
                      <button
                        onClick={() => handleExecute(selectedPlan.id)}
                        className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-md shadow-cyan-600/20 transition"
                      >
                        Execute Hardening on Target
                      </button>
                    )}

                    {selectedPlan.status === 'APPLIED' && (
                      <span className="flex items-center gap-2 text-emerald-400 font-semibold">
                        <CheckCircle className="w-4 h-4" />
                        <span>Hardening Successfully Applied</span>
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-20 text-slate-500 text-xs">
              Select or formulate a plan to review proposed hardening diffs.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
