import React, { useState, useEffect } from 'react';
import { History, Shield, User, Clock, Terminal } from 'lucide-react';
import { AuditEvent } from '../types';
import { api } from '../api/client';

export const AuditLog: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);

  useEffect(() => {
    api.fetch<AuditEvent[]>('/audit-logs').then(setEvents);
  }, []);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">System Audit Trail</h1>
          <p className="text-slate-400 text-sm mt-1">
            Tamper-evident record of security assessments, finding triages, and administrator approvals.
          </p>
        </div>
      </div>

      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/80 text-slate-400 uppercase text-[11px] font-semibold border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Action</th>
              <th className="py-3 px-4">Resource</th>
              <th className="py-3 px-4">Resource ID</th>
              <th className="py-3 px-4">Details</th>
              <th className="py-3 px-4">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {events.map((e) => (
              <tr key={e.id} className="hover:bg-slate-800/40 transition">
                <td className="py-3.5 px-4 font-mono font-semibold text-cyan-400">
                  {e.action}
                </td>
                <td className="py-3.5 px-4 text-slate-300 uppercase text-[10px] font-bold">
                  {e.resource_type}
                </td>
                <td className="py-3.5 px-4 font-mono text-slate-400">
                  {e.resource_id}
                </td>
                <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                  {JSON.stringify(e.details)}
                </td>
                <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                  {new Date(e.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
