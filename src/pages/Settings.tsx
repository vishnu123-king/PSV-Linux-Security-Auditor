import React from 'react';
import { Settings as SettingsIcon, Server, Shield, Database, Terminal, Cpu } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-2xl font-bold text-white tracking-tight">System Configuration & Security</h1>
        <p className="text-slate-400 text-sm mt-1">
          Auditor backend parameters, SSH execution timeouts, and AI assistant interfaces.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
        {/* Connection & Ports */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>FastAPI Control Plane</span>
          </div>

          <div className="space-y-3 text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">API Base URL</span>
              <span className="font-mono text-slate-200">http://localhost:8000/api/v1</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Worker Concurrency</span>
              <span className="font-mono text-slate-200">4 concurrent assessments</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">SSH Connect / Command Timeout</span>
              <span className="font-mono text-slate-200">15s / 30s</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Output Size Cap</span>
              <span className="font-mono text-slate-200">1,048,576 bytes (1 MB max per execution)</span>
            </div>
          </div>
        </div>

        {/* Database & Broker */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Storage & Messaging Infrastructure</span>
          </div>

          <div className="space-y-3 text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Active Database</span>
              <span className="font-mono text-slate-200">PostgreSQL (prod) / SQLite async (dev)</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Message Broker</span>
              <span className="font-mono text-slate-200">RabbitMQ (prod) / In-Memory Async Queue (dev)</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">CLI Binary</span>
              <span className="font-mono text-slate-200">psv (Typer CLI via pip install -e ./cli)</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Rule Engine Version</span>
              <span className="font-mono text-slate-200">v1.0.0 (60 Benchmark Rules)</span>
            </div>
          </div>
        </div>

        {/* AI Security Analyst (Requirements #51 & #52) */}
        <div className="md:col-span-2 rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>AI Security Analyst & MCP Tool Interface (Requirements #51 & #52)</span>
          </div>
          <p className="text-slate-400 text-xs leading-relaxed">
            The PSV platform exposes a strictly bounded tool contract for AI assistants and Model Context Protocol (MCP) agents:
            it can explain findings, summarize assessment impact, and generate dry-run remediation plans.
            <strong> Under no circumstances does the AI layer execute arbitrary shell commands or bypass administrator sign-off.</strong>
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
            <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300">get_assessment</div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300">get_findings</div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300">compare_drift</div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300">create_remediation_plan</div>
          </div>
        </div>
      </div>
    </div>
  );
};
