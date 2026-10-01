import React, { useState, useEffect } from 'react';
import { Layers, ShieldCheck, CheckCircle2, Star } from 'lucide-react';
import { Profile } from '../types';
import { api } from '../api/client';

export const Profiles: React.FC = () => {
  const [profiles, setProfiles] = useState<Profile[]>([]);

  useEffect(() => {
    api.fetch<Profile[]>('/profiles').then(setProfiles);
  }, []);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Audit Compliance Profiles</h1>
          <p className="text-slate-400 text-sm mt-1">
            Curated collections of benchmark rules mapped to enterprise compliance standards.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {profiles.map((p) => (
          <div
            key={p.id}
            className="rounded-xl bg-slate-900 border border-slate-800 p-6 flex flex-col justify-between shadow-sm hover:border-slate-700 transition"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-cyan-400">{p.id}</span>
                {p.is_system_default && (
                  <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    <Star className="w-3 h-3 fill-current" />
                    <span>SYSTEM DEFAULT</span>
                  </span>
                )}
              </div>
              <h3 className="text-base font-bold text-white">{p.name}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{p.description}</p>
            </div>

            <div className="pt-6 mt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
              <span className="text-slate-400">
                Contains <strong className="text-white">{p.rule_count || 60}</strong> benchmark controls
              </span>
              <button className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold border border-slate-700 transition cursor-pointer">
                Inspect Profile
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
