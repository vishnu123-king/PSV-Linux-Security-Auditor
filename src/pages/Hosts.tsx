import React, { useState, useEffect } from 'react';
import { Server, Plus, ShieldCheck, Play, Trash2, CheckCircle2, XCircle, Terminal, Laptop, RefreshCw } from 'lucide-react';
import { Host } from '../types';
import { api, LocalDiscoveryData } from '../api/client';

interface HostsProps {
  hosts: Host[];
  onRefresh: () => void;
  onTriggerAudit: (hostId: string) => void;
}

export const Hosts: React.FC<HostsProps> = ({ hosts, onRefresh, onTriggerAudit }) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [modalMode, setModalMode] = useState<'local' | 'remote'>('local');
  const [testingHostId, setTestingHostId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; msg: string; success: boolean } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Local Discovery State
  const [discovery, setDiscovery] = useState<LocalDiscoveryData | null>(null);
  const [loadingDiscovery, setLoadingDiscovery] = useState(false);

  // Form State
  const [name, setName] = useState('');
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(22);
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development'>('production');
  const [username, setUsername] = useState('root');
  const [authType, setAuthType] = useState<'local' | 'ssh_key' | 'password'>('local');
  const [secret, setSecret] = useState('');

  const fetchDiscovery = async () => {
    setLoadingDiscovery(true);
    try {
      const data = await api.getLocalDiscovery();
      setDiscovery(data);
      if (!name) setName(data.hostname || 'local-linux');
      if (!hostname) setHostname(data.default_address || '127.0.0.1');
    } catch {
      // Fallback
    } finally {
      setLoadingDiscovery(false);
    }
  };

  const openAddModal = (mode: 'local' | 'remote') => {
    setModalMode(mode);
    setTestResult(null);
    if (mode === 'local') {
      setAuthType('local');
      setName('local-linux');
      setHostname('127.0.0.1');
      fetchDiscovery();
    } else {
      setAuthType('ssh_key');
      setName('');
      setHostname('');
    }
    setShowAddModal(true);
  };

  const handleTestConnection = async (hostId: string) => {
    setTestingHostId(hostId);
    setTestResult(null);
    try {
      const res = await api.fetch<any>(`/hosts/${hostId}/test`, { method: 'POST' });
      setTestResult({
        id: hostId,
        msg: res.message || 'Connected successfully',
        success: res.success ?? true,
      });
    } catch (e: any) {
      setTestResult({
        id: hostId,
        msg: e.message || 'Connection failed',
        success: false,
      });
    } finally {
      setTestingHostId(null);
    }
  };

  const handleDeleteHost = async (hostId: string, hostName: string) => {
    if (!confirm(`Are you sure you want to remove host '${hostName}'?`)) return;
    try {
      await api.fetch(`/hosts/${hostId}`, { method: 'DELETE' });
      onRefresh();
    } catch (err: any) {
      alert(`Error deleting host: ${err.message}`);
    }
  };

  const handleAddHost = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const tags: Record<string, any> = { added_via: 'web_ui' };
      if (modalMode === 'local' || authType === 'local') {
        tags.local = true;
        tags.connector = 'local';
      }

      const payload: Record<string, any> = {
        name: name || (modalMode === 'local' ? 'local-linux' : 'linux-target'),
        hostname: hostname || '127.0.0.1',
        port: port || 22,
        environment,
        tags,
      };

      if (authType !== 'local') {
        payload.username = username;
        if (authType === 'ssh_key') {
          payload.private_key = secret;
        } else {
          payload.password = secret;
        }
      }

      const res = await api.fetch<any>('/hosts', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      // Automatically run quick test on newly added host
      if (res?.id) {
        await api.fetch(`/hosts/${res.id}/test`, { method: 'POST' }).catch(() => {});
      }

      setShowAddModal(false);
      setName('');
      setHostname('');
      setSecret('');
      onRefresh();
    } catch (err: any) {
      alert(`Error creating host: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Authorized Linux Targets</h1>
          <p className="text-slate-400 text-sm mt-1">
            Manage Linux targets audited by the PSV fact collection engine.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => openAddModal('local')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition cursor-pointer"
          >
            <Laptop className="w-4 h-4 text-cyan-400" />
            <span>Add This Machine</span>
          </button>
          <button
            onClick={() => openAddModal('remote')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Onboard Remote Target</span>
          </button>
        </div>
      </div>

      {/* Connectivity Test Toast Alert */}
      {testResult && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
            testResult.success
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
              : 'bg-rose-950/40 border-rose-800 text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {testResult.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span>
              <strong>Target Diagnostics & Reachability:</strong> {testResult.msg}
            </span>
          </div>
          <button
            onClick={() => setTestResult(null)}
            className="text-slate-400 hover:text-slate-200"
          >
            ✕
          </button>
        </div>
      )}

      {/* Targets Table / Empty State */}
      {hosts.length === 0 ? (
        <div className="rounded-2xl bg-slate-900/80 border border-slate-800 p-12 text-center space-y-4 max-w-xl mx-auto">
          <div className="w-14 h-14 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
            <Server className="w-7 h-7" />
          </div>
          <div className="space-y-1">
            <h3 className="text-base font-bold text-white">No hosts registered</h3>
            <p className="text-slate-400 text-xs leading-relaxed max-w-sm mx-auto">
              Add this Linux machine to begin auditing local benchmark rules, or onboard a remote server via SSH.
            </p>
          </div>
          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              onClick={() => openAddModal('local')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
            >
              <Laptop className="w-4 h-4" />
              <span>Add This Machine</span>
            </button>
            <button
              onClick={() => openAddModal('remote')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition cursor-pointer"
            >
              <Plus className="w-4 h-4 text-slate-400" />
              <span>Onboard Remote Host</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase text-[11px] font-semibold border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Target Name</th>
                <th className="py-3 px-4">Hostname / Port</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">Operating System</th>
                <th className="py-3 px-4">Audit Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {hosts.map((h) => {
                const isLocal = Boolean(h.tags?.local || h.tags?.connector === 'local');
                const status = h.last_assessment_status || 'Never Assessed';
                const isCompleted = status === 'COMPLETED';

                return (
                  <tr key={h.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4 font-semibold text-slate-100 flex items-center gap-2.5">
                      {isLocal ? (
                        <Laptop className="w-4 h-4 text-cyan-400 shrink-0" />
                      ) : (
                        <Server className="w-4 h-4 text-slate-400 shrink-0" />
                      )}
                      <div>
                        <span>{h.name}</span>
                        {isLocal && (
                          <span className="ml-2 text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-800 text-cyan-400">
                            Local Machine
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {h.hostname}:{h.port}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                        {h.environment}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      {h.os_distribution || 'Linux'} {h.os_version || ''}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          isCompleted
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <button
                        onClick={() => handleTestConnection(h.id)}
                        disabled={testingHostId === h.id}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition cursor-pointer"
                      >
                        {testingHostId === h.id ? 'Testing...' : 'Test Connection'}
                      </button>
                      <button
                        onClick={() => onTriggerAudit(h.id)}
                        className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition cursor-pointer"
                      >
                        Run Audit
                      </button>
                      <button
                        onClick={() => handleDeleteHost(h.id, h.name)}
                        className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition cursor-pointer inline-flex items-center"
                        title="Remove Host"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Onboard Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {modalMode === 'local' ? (
                  <Laptop className="w-5 h-5 text-cyan-400" />
                ) : (
                  <Server className="w-5 h-5 text-cyan-400" />
                )}
                <h2 className="text-base font-bold text-white">
                  {modalMode === 'local' ? 'Add This Machine (Local Audit)' : 'Onboard Remote Linux Host'}
                </h2>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {/* Mode Switch Tabs */}
            <div className="grid grid-cols-2 border-b border-slate-800 text-xs font-semibold">
              <button
                type="button"
                onClick={() => openAddModal('local')}
                className={`py-2.5 flex items-center justify-center gap-1.5 transition cursor-pointer ${
                  modalMode === 'local'
                    ? 'bg-slate-800/80 text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Laptop className="w-3.5 h-3.5" />
                <span>Local Machine</span>
              </button>
              <button
                type="button"
                onClick={() => openAddModal('remote')}
                className={`py-2.5 flex items-center justify-center gap-1.5 transition cursor-pointer ${
                  modalMode === 'remote'
                    ? 'bg-slate-800/80 text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>Remote SSH Host</span>
              </button>
            </div>

            <form onSubmit={handleAddHost} className="p-6 space-y-4 text-xs">
              {modalMode === 'local' && discovery && (
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="font-semibold text-slate-300">Detected System Facts:</span>
                    <button
                      type="button"
                      onClick={fetchDiscovery}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      <RefreshCw className={`w-3 h-3 ${loadingDiscovery ? 'animate-spin' : ''}`} />
                      <span>Refresh</span>
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300 font-mono">
                    <div>OS: <span className="text-white">{discovery.os_distribution} {discovery.os_version}</span></div>
                    <div>Kernel: <span className="text-white">{discovery.kernel_version}</span></div>
                    <div>Hostname: <span className="text-white">{discovery.hostname}</span></div>
                    <div>Arch: <span className="text-white">{discovery.arch}</span></div>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Host Display Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={modalMode === 'local' ? 'local-linux' : 'e.g. prod-gateway-01'}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-slate-300 font-semibold mb-1">
                    {modalMode === 'local' ? 'Target Address' : 'IP Address / FQDN'}
                  </label>
                  {modalMode === 'local' && discovery && discovery.addresses.length > 1 ? (
                    <select
                      value={hostname}
                      onChange={(e) => setHostname(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                    >
                      {discovery.addresses.map((addr) => (
                        <option key={addr} value={addr}>
                          {addr} {addr === '127.0.0.1' ? '(Loopback)' : '(Local Interface)'}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      required
                      value={hostname}
                      onChange={(e) => setHostname(e.target.value)}
                      placeholder="127.0.0.1 or 192.168.1.100"
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                    />
                  )}
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Port</label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Environment</label>
                  <select
                    value={environment}
                    onChange={(e: any) => setEnvironment(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
                {modalMode === 'remote' && (
                  <div>
                    <label className="block text-slate-300 font-semibold mb-1">SSH Username</label>
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                    />
                  </div>
                )}
              </div>

              {modalMode === 'remote' && (
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Authentication Credential</label>
                  <div className="flex gap-4 mb-2">
                    <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                      <input
                        type="radio"
                        checked={authType === 'ssh_key'}
                        onChange={() => setAuthType('ssh_key')}
                      />
                      <span>SSH Private Key</span>
                    </label>
                    <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                      <input
                        type="radio"
                        checked={authType === 'password'}
                        onChange={() => setAuthType('password')}
                      />
                      <span>Password</span>
                    </label>
                  </div>
                  <textarea
                    rows={3}
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder={authType === 'ssh_key' ? '-----BEGIN OPENSSH PRIVATE KEY-----...' : 'SSH Password'}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono text-[11px]"
                  />
                </div>
              )}

              <div className="pt-2 flex justify-end gap-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 font-medium hover:bg-slate-700 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-cyan-600 text-white font-semibold hover:bg-cyan-500 shadow-md shadow-cyan-600/20 cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Registering...' : 'Save & Authorize Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
