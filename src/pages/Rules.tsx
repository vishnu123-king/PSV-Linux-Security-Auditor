import React, { useState, useEffect } from 'react';
import { BookOpen, Search, Filter, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { Rule } from '../types';
import { api } from '../api/client';

export const Rules: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);

  useEffect(() => {
    api.fetch<Rule[]>('/rules').then((r) => {
      setRules(r);
      if (r.length > 0) setSelectedRule(r[0]);
    });
  }, []);

  const CATEGORIES = [
    'ALL',
    'ssh',
    'identity',
    'sudo',
    'filesystem',
    'network',
    'firewall',
    'services',
    'kernel',
    'pam',
    'logging',
    'containers',
  ];

  const filtered = rules.filter((r) => {
    if (selectedCategory !== 'ALL' && r.category !== selectedCategory) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        r.name.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        r.control.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Benchmark Rules</h1>
          <p className="text-slate-400 text-sm mt-1">
            External YAML-defined compliance policies evaluated deterministically by the rule engine.
          </p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          {rules.length} Rules Active
        </span>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2.5 py-1 rounded-md font-semibold transition ${
                selectedCategory === cat
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Rules Grid & Detail Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Rule List */}
        <div className="lg:col-span-1 rounded-xl bg-slate-900 border border-slate-800 max-h-[700px] overflow-y-auto divide-y divide-slate-800/80">
          {filtered.map((r) => {
            const isSelected = selectedRule?.id === r.id;
            return (
              <div
                key={r.id}
                onClick={() => setSelectedRule(r)}
                className={`p-3.5 cursor-pointer transition select-none ${
                  isSelected ? 'bg-cyan-500/10 border-l-4 border-cyan-400' : 'hover:bg-slate-850'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-cyan-400">{r.id}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      r.severity === 'CRITICAL'
                        ? 'text-rose-400 bg-rose-500/10'
                        : r.severity === 'HIGH'
                        ? 'text-amber-400 bg-amber-500/10'
                        : 'text-yellow-400 bg-yellow-500/10'
                    }`}
                  >
                    {r.severity}
                  </span>
                </div>
                <div className="text-xs font-semibold text-slate-200 line-clamp-1">{r.name}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-0.5">{r.control}</div>
              </div>
            );
          })}
        </div>

        {/* Right Column: Full Rule Specification */}
        <div className="lg:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-5">
          {selectedRule ? (
            <>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-500/20 text-cyan-400">
                      {selectedRule.id}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">v{selectedRule.version}</span>
                  </div>
                  <h2 className="text-lg font-bold text-white">{selectedRule.name}</h2>
                </div>
                <span
                  className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider ${
                    selectedRule.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {selectedRule.severity}
                </span>
              </div>

              <div className="space-y-4 text-xs">
                <div>
                  <h4 className="text-slate-400 font-bold uppercase tracking-wider text-[11px] mb-1">
                    Target Control Key
                  </h4>
                  <div className="p-2.5 rounded bg-slate-950 font-mono text-cyan-400 border border-slate-800">
                    {selectedRule.control}
                  </div>
                </div>

                <div>
                  <h4 className="text-slate-400 font-bold uppercase tracking-wider text-[11px] mb-1">
                    Security Rationale
                  </h4>
                  <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800/80">
                    {selectedRule.rationale}
                  </p>
                </div>

                <div>
                  <h4 className="text-slate-400 font-bold uppercase tracking-wider text-[11px] mb-1">
                    Deterministic Condition Logic (YAML Spec)
                  </h4>
                  <pre className="p-3 rounded bg-slate-950 text-emerald-400 font-mono text-[11px] overflow-x-auto border border-slate-800">
                    {JSON.stringify(selectedRule.condition, null, 2)}
                  </pre>
                </div>

                <div>
                  <h4 className="text-slate-400 font-bold uppercase tracking-wider text-[11px] mb-1">
                    Hardening & Remediation Guidance
                  </h4>
                  <div className="p-3 rounded bg-slate-950 text-slate-300 font-mono text-[11px] border border-slate-800">
                    {selectedRule.remediation_guidance}
                  </div>
                </div>

                <div>
                  <h4 className="text-slate-400 font-bold uppercase tracking-wider text-[11px] mb-1">
                    Post-Hardening Verification Command
                  </h4>
                  <div className="p-2.5 rounded bg-slate-950 font-mono text-amber-400 text-[11px] border border-slate-800">
                    $ {selectedRule.verification_method}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-20 text-slate-500">Select a rule to view specification.</div>
          )}
        </div>
      </div>
    </div>
  );
};
