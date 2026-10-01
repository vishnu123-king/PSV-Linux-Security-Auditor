import React from 'react';
import { Shield, Terminal, Activity, Server, Bell, CheckCircle2 } from 'lucide-react';

interface NavbarProps {
  onOpenTerminal: () => void;
  onQuickAudit: () => void;
  serverStatus: 'connected' | 'simulated';
}

export const Navbar: React.FC<NavbarProps> = ({ onOpenTerminal, onQuickAudit, serverStatus }) => {
  return (
    <header className="h-16 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-white tracking-tight text-lg">PSV</span>{' '}
          <span className="text-slate-400 text-sm font-medium">Linux Security Auditor</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Server State Indicator */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-xs">
          <span className={`w-2 h-2 rounded-full ${serverStatus === 'connected' ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
          <span className="text-slate-300 font-mono">
            {serverStatus === 'connected' ? 'FastAPI :8000' : 'Live Preview Engine'}
          </span>
        </div>

        {/* Interactive Diagnostic Console Trigger */}
        <button
          onClick={onOpenTerminal}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition-colors shadow-sm"
          title="Open safe Diagnostic Console"
        >
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>Diagnostic Console</span>
          <span className="bg-slate-950 px-1.5 py-0.5 rounded text-[10px] text-slate-400 border border-slate-800">`</span>
        </button>

        {/* Quick Audit Action */}
        <button
          onClick={onQuickAudit}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition-all cursor-pointer"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Run Security Audit</span>
        </button>

        {/* Admin Role Tag */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-300">
            SA
          </div>
          <div className="hidden sm:block text-left text-xs">
            <div className="font-semibold text-slate-200 leading-tight">SecArch</div>
            <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-mono">ADMIN</div>
          </div>
        </div>
      </div>
    </header>
  );
};
