import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  Play,
  RotateCw,
  Clock,
  CheckCircle,
  AlertTriangle,
  Server,
  Layers,
  Activity,
  AlertCircle,
} from 'lucide-react';
import { Assessment, Host } from '../types';
import { api } from '../api/client';

interface AssessmentsProps {
  assessments: Assessment[];
  hosts: Host[];
  onTriggerAudit: (hostId: string) => void;
  onRefresh: () => void;
}

export const Assessments: React.FC<AssessmentsProps> = ({
  assessments,
  hosts,
  onTriggerAudit,
  onRefresh,
}) => {
  const [selectedHostId, setSelectedHostId] = useState(hosts[0]?.id || '');
  const [selectedProfileId, setSelectedProfileId] = useState('cis-linux-server');
  const [isRunning, setIsRunning] = useState(false);
  const [activeStage, setActiveStage] = useState<string | null>(null);
  const [currentAssessmentId, setCurrentAssessmentId] = useState<string | null>(null);

  useEffect(() => {
    if (hosts.length > 0 && !selectedHostId) {
      setSelectedHostId(hosts[0].id);
    }
  }, [hosts, selectedHostId]);

  const COLLECTORS = [
    'system',
    'identity',
    'ssh',
    'sudo',
    'filesystem',
    'networking',
    'firewall',
    'services',
    'kernel',
    'pam',
    'logging',
    'containers',
  ];

  const handleStartAudit = async () => {
    if (!selectedHostId) return;

    setIsRunning(true);
    setActiveStage('Dispatching Assessment Job...');

    try {
      const res = await api.fetch<any>('/assessments', {
        method: 'POST',
        body: JSON.stringify({
          host_id: selectedHostId,
          profile_id: selectedProfileId,
        }),
      });

      const assessmentId = res.id;
      setCurrentAssessmentId(assessmentId);

      // Poll real worker status from control plane
      const pollInterval = setInterval(async () => {
        try {
          const current = await api.fetch<any>(`/assessments/${assessmentId}`);
          const status = current.status;
          const collector = current.current_collector;

          if (collector) {
            setActiveStage(`Collector: ${collector} (${current.progress_percent || 0}%)`);
          } else {
            setActiveStage(`Status: ${status} (${current.progress_percent || 0}%)`);
          }

          if (status === 'COMPLETED' || status === 'FAILED' || status === 'CANCELLED') {
            clearInterval(pollInterval);
            setIsRunning(false);
            setActiveStage(null);
            setCurrentAssessmentId(null);
            onRefresh();
          }
        } catch {
          // Continue polling
        }
      }, 1000);
    } catch (e: any) {
      alert(`Failed to start assessment: ${e.message}`);
      setIsRunning(false);
      setActiveStage(null);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Assessments</h1>
          <p className="text-slate-400 text-sm mt-1">
            Automated compliance scans executing against authorized endpoints.
          </p>
        </div>
      </div>

      {/* Trigger Assessment Wizard Box */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-sm">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <span>Launch New Assessment</span>
        </h2>

        {hosts.length === 0 ? (
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>No authorized Linux hosts registered yet. Please onboard a host in the Targets tab first.</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Target Host</label>
              <select
                value={selectedHostId}
                onChange={(e) => setSelectedHostId(e.target.value)}
                disabled={isRunning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
              >
                {hosts.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.name} ({h.hostname}:{h.port})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">Compliance Profile</label>
              <select
                value={selectedProfileId}
                onChange={(e) => setSelectedProfileId(e.target.value)}
                disabled={isRunning}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
              >
                <option value="cis-linux-server">CIS Linux Server Benchmark (Level 1)</option>
                <option value="cis-linux-workstation">CIS Linux Workstation Benchmark</option>
                <option value="essential-eight-hardened">Essential Eight Baseline</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={handleStartAudit}
                disabled={isRunning || !selectedHostId}
                className="w-full h-[38px] flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
              >
                {isRunning ? (
                  <>
                    <RotateCw className="w-4 h-4 animate-spin text-cyan-300" />
                    <span>{activeStage || 'Auditing...'}</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Execute Audit</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Live Collector Pipeline Indicators */}
        {isRunning && (
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="flex justify-between text-xs text-slate-400">
              <span className="font-mono text-cyan-300">{activeStage}</span>
              <span className="text-cyan-400 font-semibold">12 Collectors Active</span>
            </div>
            <div className="grid grid-cols-6 sm:grid-cols-12 gap-1.5 pt-1">
              {COLLECTORS.map((c) => {
                const isActive = activeStage?.toLowerCase().includes(c);
                return (
                  <div
                    key={c}
                    className={`py-1.5 px-1 rounded text-center text-[10px] font-mono border transition-all ${
                      isActive
                        ? 'bg-cyan-500 text-black font-bold border-cyan-400 scale-105'
                        : 'bg-slate-950 text-slate-500 border-slate-800'
                    }`}
                  >
                    {c}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Historical Assessment Runs */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white">Assessment History</h2>
          <span className="text-xs text-slate-400">{assessments.length} runs recorded</span>
        </div>

        {assessments.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            <FileCheck2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <span>No assessments have been executed yet.</span>
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase text-[11px] font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Run ID</th>
                <th className="py-3 px-4">Host</th>
                <th className="py-3 px-4">Profile</th>
                <th className="py-3 px-4">Compliance Score</th>
                <th className="py-3 px-4">Passed / Total</th>
                <th className="py-3 px-4">Critical / High</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {assessments.map((a) => (
                <tr key={a.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-3.5 px-4 font-mono font-semibold text-cyan-400">#{a.id.slice(0, 8)}</td>
                  <td className="py-3.5 px-4 text-slate-200 font-medium">{a.host_name || a.host_id.slice(0, 8)}</td>
                  <td className="py-3.5 px-4 text-slate-400">{a.profile_id}</td>
                  <td className="py-3.5 px-4">
                    <span className="font-bold text-sm text-emerald-400">{a.compliance_score}%</span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-300">
                    {a.passed_rules} / {a.total_rules}
                  </td>
                  <td className="py-3.5 px-4 font-mono">
                    <span className="text-rose-400 font-bold">{a.critical_count}</span>
                    <span className="text-slate-500"> / </span>
                    <span className="text-amber-400 font-bold">{a.high_count}</span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-400">
                    {a.duration_seconds ? `${a.duration_seconds.toFixed(1)}s` : 'N/A'}
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        a.status === 'COMPLETED'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : a.status === 'FAILED'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                          : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
