import React, { useState } from 'react';
import { FileText, Download, Printer, CheckCircle2, ShieldCheck } from 'lucide-react';
import { Assessment } from '../types';

interface ReportsProps {
  assessments: Assessment[];
}

export const Reports: React.FC<ReportsProps> = ({ assessments }) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState(assessments[0]?.id || 'ass-101');
  const [reportFormat, setReportFormat] = useState<'html' | 'json'>('html');
  const [generated, setGenerated] = useState(false);

  const handleDownload = () => {
    const ass = assessments.find((a) => a.id === selectedAssessmentId) || assessments[0];
    const dummyJson = JSON.stringify(
      {
        meta: {
          generator: 'PSV Linux Security Auditor v1.0',
          generated_at: new Date().toISOString(),
          assessment_id: ass?.id,
          compliance_score: ass?.compliance_score,
        },
        executive_summary: {
          passed_rules: ass?.passed_rules,
          failed_rules: ass?.failed_rules,
          critical_count: ass?.critical_count,
        },
      },
      null,
      2
    );

    const blob = new Blob([dummyJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `psv-audit-report-${ass?.id}.json`;
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Generator Controls */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <h3 className="text-sm font-bold text-white">Report Configuration</h3>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Select Assessment</label>
              <select
                value={selectedAssessmentId}
                onChange={(e) => setSelectedAssessmentId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    #{a.id} - {a.host_name || a.host_id} ({a.compliance_score}%)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">Export Format</label>
              <div className="flex gap-4">
                <label className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="radio"
                    checked={reportFormat === 'html'}
                    onChange={() => setReportFormat('html')}
                  />
                  <span>Printable HTML / PDF</span>
                </label>
                <label className="flex items-center gap-1.5 text-slate-300">
                  <input
                    type="radio"
                    checked={reportFormat === 'json'}
                    onChange={() => setReportFormat('json')}
                  />
                  <span>Machine-Readable JSON</span>
                </label>
              </div>
            </div>

            <button
              onClick={handleDownload}
              className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Download Formal Report</span>
            </button>
          </div>
        </div>

        {/* Report Preview */}
        <div className="md:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Report Executive Preview</span>
            </h3>
            <span className="text-xs font-mono text-emerald-400 font-semibold">
              Ready for Download
            </span>
          </div>

          <div className="bg-slate-950 p-6 rounded-lg border border-slate-800 space-y-4 text-xs">
            <div className="flex justify-between items-center pb-3 border-b border-slate-800">
              <div>
                <div className="font-bold text-base text-white">PSV Linux Security Auditor</div>
                <div className="text-slate-400">Host Compliance & Hardening Verification</div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-black text-emerald-400">86.7%</div>
                <div className="text-[10px] text-slate-500 uppercase font-bold">Compliance Score</div>
              </div>
            </div>

            <div className="text-slate-300 leading-relaxed">
              Assessment evaluated <strong>60 benchmark controls</strong>. 52 controls PASSED, 6 controls FAILED, and 2 WARN. 1 CRITICAL finding regarding sudo wildcard privilege escalation was isolated.
            </div>

            <div className="grid grid-cols-4 gap-2 pt-2 text-center">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Critical</span>
                <span className="text-rose-400 font-bold text-sm">1</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">High</span>
                <span className="text-amber-400 font-bold text-sm">3</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Medium</span>
                <span className="text-yellow-400 font-bold text-sm">2</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Passed</span>
                <span className="text-emerald-400 font-bold text-sm">52</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
