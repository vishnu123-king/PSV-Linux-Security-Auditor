import React from 'react';
import {
  LayoutDashboard,
  Server,
  FileCheck2,
  AlertTriangle,
  BookOpen,
  Layers,
  GitCompare,
  Wrench,
  FileText,
  History,
  Settings,
  Terminal,
} from 'lucide-react';

export type NavItem =
  | 'dashboard'
  | 'hosts'
  | 'assessments'
  | 'findings'
  | 'rules'
  | 'profiles'
  | 'drift'
  | 'remediation'
  | 'reports'
  | 'audit-log'
  | 'settings';

interface SidebarProps {
  currentTab: NavItem;
  onSelectTab: (tab: NavItem) => void;
  openCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, openCount = 0 }) => {
  const links = [
    { id: 'dashboard' as NavItem, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'hosts' as NavItem, label: 'Target Hosts', icon: Server },
    { id: 'assessments' as NavItem, label: 'Assessments', icon: FileCheck2 },
    { id: 'findings' as NavItem, label: 'Findings', icon: AlertTriangle, badge: openCount },
    { id: 'rules' as NavItem, label: 'Security Rules', icon: BookOpen },
    { id: 'profiles' as NavItem, label: 'Audit Profiles', icon: Layers },
    { id: 'drift' as NavItem, label: 'Drift Detection', icon: GitCompare },
    { id: 'remediation' as NavItem, label: 'Remediation', icon: Wrench },
    { id: 'reports' as NavItem, label: 'Reports', icon: FileText },
    { id: 'audit-log' as NavItem, label: 'Audit Trail', icon: History },
    { id: 'settings' as NavItem, label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-slate-900/90 border-r border-slate-800 flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
          Core Workflows
        </div>
        {links.map((link) => {
          const Icon = link.icon;
          const isActive = currentTab === link.id;
          return (
            <button
              key={link.id}
              onClick={() => onSelectTab(link.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{link.label}</span>
              </div>
              {link.badge ? (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  {link.badge}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div className="p-4 border-t border-slate-800/80">
        <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-3 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="font-mono text-[11px]">PSV Engine</span>
            <span className="text-[10px] text-emerald-400 font-bold">ACTIVE</span>
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            12 Collectors loaded. 60 benchmark rules active.
          </p>
        </div>
      </div>
    </aside>
  );
};
