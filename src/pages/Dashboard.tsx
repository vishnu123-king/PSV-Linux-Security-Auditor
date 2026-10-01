import React from 'react';
import {
  ShieldAlert,
  Server,
  CheckCircle,
  Clock,
  ArrowUpRight,
  TrendingUp,
  AlertTriangle,
  Play,
  FileText,
} from 'lucide-react';
import { Host, Assessment, Finding } from '../types';

interface DashboardProps {
  hosts: Host[];
  assessments: Assessment[];
  findings: Finding[];
  onNavigate: (tab: any) => void;
  onTriggerAudit: (hostId: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  hosts,
  assessments,
  findings,
  onNavigate,
  onTriggerAudit,
}) => {
  const latestAssessment = assessments[0];
  const complianceScore = latestAssessment?.compliance_score || 86.7;

  const openFindings = findings.filter((f) => f.status === 'OPEN');
  const criticalCount = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter((f) => f.severity === 'MEDIUM').length;

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Banner & Quick Overview */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">
            Continuous Linux compliance posture, automated collector metrics, and drift monitoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('reports')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition cursor-pointer"
          >
            <FileText className="w-4 h-4 text-slate-400" />
            <span>Generate Report</span>
          </button>
          <button
            onClick={() => onTriggerAudit(hosts[0]?.id || 'host-01')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Audit All Targets</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Compliance Score Card */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 relative overflow-hidden shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Compliance Index</span>
            <span className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <TrendingUp className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-white">{complianceScore}%</span>
            <span className="text-xs text-emerald-400 font-semibold flex items-center">
              +6.7% baseline
            </span>
          </div>
          <div className="mt-3 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                complianceScore >= 80 ? 'bg-emerald-500' : 'bg-amber-500'
              }`}
              style={{ width: `${complianceScore}%` }}
            />
          </div>
        </div>

        {/* Managed Hosts */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Managed Hosts</span>
            <span className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <Server className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-white">{hosts.length}</span>
            <span className="text-xs text-slate-400">Targets Enrolled</span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs text-emerald-400">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>100% Reachable (SSH)</span>
          </div>
        </div>

        {/* Critical Vulnerabilities */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Findings</span>
            <span className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-rose-400">{criticalCount}</span>
            <span className="text-xs text-slate-400">Needs Immediate Fix</span>
          </div>
          <div className="mt-3 text-xs text-slate-400">
            {highCount} High, {mediumCount} Medium active
          </div>
        </div>

        {/* Total Benchmark Rules */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Rules</span>
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <CheckCircle className="w-4 h-4" />
            </span>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-black text-white">60</span>
            <span className="text-xs text-slate-400">YAML Policies</span>
          </div>
          <div className="mt-3 text-xs text-cyan-400">
            11 Security Domains Loaded
          </div>
        </div>
      </div>

      {/* Main Grid: Target Hosts & Recent Assessments */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2/3): Target Inventory */}
        <div className="lg:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Active Audit Targets</h2>
            <button
              onClick={() => onNavigate('hosts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {hosts.map((host) => (
              <div
                key={host.id}
                className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition flex items-center justify-between"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300">
                    <Server className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-slate-100">{host.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                        {host.environment}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">
                      {host.hostname}:{host.port} • {host.os_distribution} {host.os_version}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="px-2 py-1 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    COMPLETED
                  </span>
                  <button
                    onClick={() => onTriggerAudit(host.id)}
                    className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
                    title="Run Audit Now"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column (1/3): Critical Triage & Quick Actions */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Priority Triage</h2>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
            >
              <span>Inspect</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {openFindings.slice(0, 3).map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      f.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">{f.rule_id}</span>
                </div>
                <div className="text-xs font-semibold text-slate-200 line-clamp-1">{f.title}</div>
                <div className="text-[11px] text-slate-400 line-clamp-2">{f.rationale}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
