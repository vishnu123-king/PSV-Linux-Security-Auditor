import React, { useState } from 'react';
import { Server, Plus, ShieldCheck, Play, Trash2, CheckCircle2, XCircle, Terminal } from 'lucide-react';
import { Host } from '../types';
import { api } from '../api/client';

interface HostsProps {
  hosts: Host[];
  onRefresh: () => void;
  onTriggerAudit: (hostId: string) => void;
}

export const Hosts: React.FC<HostsProps> = ({ hosts, onRefresh, onTriggerAudit }) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [testingHostId, setTestingHostId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; msg: string; success: boolean } | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(22);
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development'>('production');
  const [username, setUsername] = useState('root');
  const [authType, setAuthType] = useState<'ssh_key' | 'password'>('ssh_key');
  const [secret, setSecret] = useState('');

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

  const handleAddHost = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.fetch('/hosts', {
        method: 'POST',
        body: JSON.stringify({
          name,
          hostname,
          port,
          environment,
          username,
          [authType === 'ssh_key' ? 'private_key' : 'password']: secret,
          tags: { added_via: 'web_ui' },
        }),
      });
      setShowAddModal(false);
      setName('');
      setHostname('');
      setSecret('');
      onRefresh();
    } catch (err: any) {
      alert(`Error creating host: ${err.message}`);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Authorized Linux Targets</h1>
          <p className="text-slate-400 text-sm mt-1">
            Manage target endpoints audited by the PSV collector engine via verified SSH.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Onboard New Target</span>
        </button>
      </div>

      {/* Targets Table */}
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
            {hosts.map((h) => (
              <tr key={h.id} className="hover:bg-slate-800/40 transition">
                <td className="py-3.5 px-4 font-semibold text-slate-100 flex items-center gap-2.5">
                  <Server className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span>{h.name}</span>
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
                  {h.os_distribution || 'Ubuntu'} {h.os_version || '24.04'}
                </td>
                <td className="py-3.5 px-4">
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {h.last_assessment_status || 'READY'}
                  </span>
                </td>
                <td className="py-3.5 px-4 text-right space-x-2">
                  <button
                    onClick={() => handleTestConnection(h.id)}
                    disabled={testingHostId === h.id}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
                  >
                    {testingHostId === h.id ? 'Testing...' : 'Test SSH'}
                  </button>
                  <button
                    onClick={() => onTriggerAudit(h.id)}
                    className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
                  >
                    Run Audit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
              <strong>SSH Reachability Test:</strong> {testResult.msg}
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

      {/* Onboard Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-base font-bold text-white">Onboard Linux Target Host</h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleAddHost} className="p-6 space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Host Display Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. prod-db-replica-01"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-slate-300 font-semibold mb-1">IP Address / FQDN</label>
                  <input
                    type="text"
                    required
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="192.168.1.100"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">SSH Port</label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
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
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">SSH Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Authentication Credential</label>
                <div className="flex gap-4 mb-2">
                  <label className="flex items-center gap-1.5 text-slate-300">
                    <input
                      type="radio"
                      checked={authType === 'ssh_key'}
                      onChange={() => setAuthType('ssh_key')}
                    />
                    <span>SSH Private Key</span>
                  </label>
                  <label className="flex items-center gap-1.5 text-slate-300">
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
                  placeholder={authType === 'ssh_key' ? '-----BEGIN OPENSSH PRIVATE KEY-----...' : 'Password'}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono text-[11px]"
                />
              </div>

              <div className="pt-2 flex justify-end gap-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 font-medium hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 text-white font-semibold hover:bg-cyan-500 shadow-md shadow-cyan-600/20"
                >
                  Save & Authorize Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
