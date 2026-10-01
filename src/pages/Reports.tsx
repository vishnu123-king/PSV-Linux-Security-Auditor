import React, { useState, useEffect } from 'react';
import { FileText, Download, Printer, CheckCircle2, ShieldCheck, AlertCircle } from 'lucide-react';
import { Assessment } from '../types';
import { api } from '../api/client';

interface ReportsProps {
  assessments: Assessment[];
}

export const Reports: React.FC<ReportsProps> = ({ assessments }) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState(assessments[0]?.id || '');
  const [reportFormat, setReportFormat] = useState<'html' | 'json'>('html');
  const [generated, setGenerated] = useState(false);
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    if (assessments.length > 0 && !selectedAssessmentId) {
      setSelectedAssessmentId(assessments[0].id);
    }
  }, [assessments, selectedAssessmentId]);

  useEffect(() => {
    if (!selectedAssessmentId) return;
    api.fetch<any[]>(`/assessments/${selectedAssessmentId}/findings`)
      .then(setFindings)
      .catch(() => setFindings([]));
  }, [selectedAssessmentId]);

  const currentAssessment = assessments.find((a) => a.id === selectedAssessmentId) || assessments[0];

  const handleDownload = () => {
    if (!currentAssessment) return;
    const reportData = {
      meta: {
        generator: 'PSV Linux Security Auditor v1.0',
        generated_at: new Date().toISOString(),
        assessment_id: currentAssessment.id,
        host_name: currentAssessment.host_name || currentAssessment.host_id,
        profile_id: currentAssessment.profile_id,
        compliance_score: currentAssessment.compliance_score,
      },
      executive_summary: {
        total_rules: currentAssessment.total_rules,
        passed_rules: currentAssessment.passed_rules,
        failed_rules: currentAssessment.failed_rules,
        warn_rules: currentAssessment.warn_rules,
        critical_count: currentAssessment.critical_count,
        high_count: currentAssessment.high_count,
        medium_count: currentAssessment.medium_count,
        low_count: currentAssessment.low_count,
      },
      findings: findings,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `psv-audit-report-${currentAssessment.id.slice(0, 8)}.json`;
    a.click();
    setGenerated(true);
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Compliance Audit Reports</h1>
          <p className="text-slate-400 text-sm mt-1">
            Export formal security audit assessments with executive summaries and evidence artifacts.
          </p>
        </div>
      </div>

      {assessments.length === 0 ? (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 p-12 text-center space-y-2 max-w-md mx-auto">
          <FileText className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <h3 className="text-sm font-semibold text-white">No completed assessments</h3>
          <p className="text-xs text-slate-400">
            Execute a security assessment against an enrolled target to generate formal compliance reports.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Generator Controls */}
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white">Report Configuration</h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Assessment Run</label>
                <select
                  value={selectedAssessmentId}
                  onChange={(e) => setSelectedAssessmentId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                >
                  {assessments.map((a) => (
                    <option key={a.id} value={a.id}>
                      #{a.id.slice(0, 8)} - {a.host_name || a.host_id.slice(0, 8)} ({a.compliance_score}%)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Export Format</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportFormat('html')}
                    className={`py-2 rounded-lg border font-semibold text-center transition cursor-pointer ${
                      reportFormat === 'html'
                        ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    HTML / Print
                  </button>
                  <button
                    type="button"
                    onClick={() => setReportFormat('json')}
                    className={`py-2 rounded-lg border font-semibold text-center transition cursor-pointer ${
                      reportFormat === 'json'
                        ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                        : 'bg-slate-950 text-slate-400 border-slate-800'
                    }`}
                  >
                    JSON Artifact
                  </button>
                </div>
              </div>

              <div className="pt-2">
                <button
                  onClick={handleDownload}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Report</span>
                </button>
              </div>
            </div>
          </div>

          {/* Report Preview */}
          <div className="md:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-white">Executive Compliance Summary</h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                  Target: {currentAssessment?.host_name || currentAssessment?.host_id} • Profile: {currentAssessment?.profile_id}
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-black text-emerald-400 font-mono">
                  {currentAssessment?.compliance_score}%
                </span>
                <span className="text-[10px] text-slate-500 block uppercase font-semibold">Score</span>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-3 text-center text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Passed</span>
                <span className="text-emerald-400 font-black text-lg">{currentAssessment?.passed_rules || 0}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Failed</span>
                <span className="text-rose-400 font-black text-lg">{currentAssessment?.failed_rules || 0}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Critical</span>
                <span className="text-rose-400 font-black text-lg">{currentAssessment?.critical_count || 0}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase font-bold">High</span>
                <span className="text-amber-400 font-black text-lg">{currentAssessment?.high_count || 0}</span>
              </div>
            </div>

            <div className="space-y-2 pt-2">
              <h4 className="text-xs font-semibold text-slate-300">Open Findings Summary ({findings.length})</h4>
              {findings.length === 0 ? (
                <div className="p-4 rounded-lg bg-slate-950 text-xs text-slate-500 text-center">
                  No findings recorded for this assessment.
                </div>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {findings.map((f) => (
                    <div key={f.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'
                        }`}>
                          {f.severity}
                        </span>
                        <span className="font-mono text-cyan-400">{f.rule_id}</span>
                        <span className="text-slate-200">{f.title}</span>
                      </div>
                      <span className="text-slate-500 font-mono text-[11px]">{f.status}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
