import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavItem } from './components/Sidebar';
import { TerminalModal } from './components/TerminalModal';
import { Dashboard } from './pages/Dashboard';
import { Hosts } from './pages/Hosts';
import { Assessments } from './pages/Assessments';
import { Findings } from './pages/Findings';
import { Rules } from './pages/Rules';
import { Profiles } from './pages/Profiles';
import { Drift } from './pages/Drift';
import { RemediationPage } from './pages/Remediation';
import { Reports } from './pages/Reports';
import { AuditLog } from './pages/AuditLog';
import { SettingsPage } from './pages/Settings';
import { Host, Assessment, Finding } from './types';
import { api } from './api/client';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavItem>('dashboard');
  const [isTerminalOpen, setIsTerminalOpen] = useState(false);
  const [serverStatus, setServerStatus] = useState<'connected' | 'simulated'>('connected');

  const [hosts, setHosts] = useState<Host[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  const loadData = async () => {
    try {
      const [h, a, f] = await Promise.all([
        api.fetch<Host[]>('/hosts'),
        api.fetch<Assessment[]>('/assessments'),
        api.fetch<Finding[]>('/findings'),
      ]);
      setHosts(h || []);
      setAssessments(a || []);
      setFindings(f || []);
    } catch {
      // API error handled
    }
  };

  useEffect(() => {
    loadData();

    // Check if real FastAPI backend is online
    api.fetch('/health')
      .then(() => setServerStatus('connected'))
      .catch(() => setServerStatus('simulated'));

    // Global shortcut for opening diagnostic console (backtick)
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '`' && !['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName)) {
        e.preventDefault();
        setIsTerminalOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleTriggerAudit = async (hostId: string) => {
    if (!hostId) {
      setCurrentTab('hosts');
      return;
    }
    setCurrentTab('assessments');
    await api.fetch('/assessments', {
      method: 'POST',
      body: JSON.stringify({ host_id: hostId, profile_id: 'cis-linux-server' }),
    }).catch(() => {});
    loadData();
  };

  const handlePlanRemediation = async (findingId: string) => {
    await api.fetch('/remediation/plan', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId }),
    }).catch(() => {});
    setCurrentTab('remediation');
  };

  const openFindingsCount = findings.filter((f) => f.status === 'OPEN').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        onOpenTerminal={() => setIsTerminalOpen(true)}
        onQuickAudit={() => (hosts.length > 0 ? handleTriggerAudit(hosts[0].id) : setCurrentTab('hosts'))}
        serverStatus={serverStatus}
      />

      {/* Main Layout Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          openCount={openFindingsCount}
        />

        {/* Dynamic Content Pane */}
        <main className="flex-1 overflow-y-auto">
          {currentTab === 'dashboard' && (
            <Dashboard
              hosts={hosts}
              assessments={assessments}
              findings={findings}
              onNavigate={setCurrentTab}
              onTriggerAudit={handleTriggerAudit}
            />
          )}

          {currentTab === 'hosts' && (
            <Hosts
              hosts={hosts}
              onRefresh={loadData}
              onTriggerAudit={handleTriggerAudit}
            />
          )}

          {currentTab === 'assessments' && (
            <Assessments
              assessments={assessments}
              hosts={hosts}
              onTriggerAudit={handleTriggerAudit}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'findings' && (
            <Findings
              findings={findings}
              onRefresh={loadData}
              onPlanRemediation={handlePlanRemediation}
            />
          )}

          {currentTab === 'rules' && <Rules />}

          {currentTab === 'profiles' && <Profiles />}

          {currentTab === 'drift' && <Drift hosts={hosts} />}

          {currentTab === 'remediation' && (
            <RemediationPage
              findings={findings}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'reports' && <Reports assessments={assessments} />}

          {currentTab === 'audit-log' && <AuditLog />}

          {currentTab === 'settings' && <SettingsPage onRefreshAll={loadData} />}
        </main>
      </div>

      {/* Restricted Diagnostic Console Modal */}
      <TerminalModal
        isOpen={isTerminalOpen}
        onClose={() => setIsTerminalOpen(false)}
      />
    </div>
  );
};

export default App;
