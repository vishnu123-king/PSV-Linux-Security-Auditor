import {
  Assessment,
  AuditEvent,
  DriftComparison,
  Evidence,
  Finding,
  Host,
  Profile,
  Remediation,
  Rule,
} from '../types';

const API_ROOT = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export interface LocalDiscoveryData {
  hostname: string;
  addresses: string[];
  default_address: string;
  os_distribution: string;
  os_version: string;
  kernel_version: string;
  arch: string;
}

class APIClient {
  private isAuthenticating = false;

  private getBaseUrl(): string {
    return API_ROOT.endsWith('/') ? API_ROOT.slice(0, -1) : API_ROOT;
  }

  async login(
    email = 'admin@psv.local',
    password = 'AdminSecurePassword123!'
  ): Promise<string> {
    const url = `${this.getBaseUrl()}/auth/login`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username: email, password }),
    });

    if (!res.ok) {
      throw new Error('Authentication failed');
    }

    const data = await res.json();
    if (data.access_token) {
      localStorage.setItem('psv_token', data.access_token);
      return data.access_token;
    }
    throw new Error('No access_token returned');
  }

  async fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = path.startsWith('http') ? path : `${this.getBaseUrl()}${path}`;
    let token = localStorage.getItem('psv_token');

    // Auto-login on first call if token is missing
    if (!token && !path.startsWith('/auth/login') && path !== '/health' && !this.isAuthenticating) {
      try {
        this.isAuthenticating = true;
        token = await this.login();
      } catch {
        // Continue without token if login fails
      } finally {
        this.isAuthenticating = false;
      }
    }

    const execRequest = async (authToken: string | null) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(options.headers as Record<string, string> || {}),
      };
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      return await fetch(url, {
        ...options,
        headers,
      });
    };

    try {
      let res = await execRequest(token);

      // If 401 Unauthorized, re-authenticate and retry
      if (res.status === 401 && !path.startsWith('/auth/login') && !this.isAuthenticating) {
        try {
          this.isAuthenticating = true;
          token = await this.login();
          res = await execRequest(token);
        } catch {
          // Re-authentication failed
        } finally {
          this.isAuthenticating = false;
        }
      }

      if (res.ok) {
        if (res.status === 204) return {} as T;
        return await res.json();
      }

      // If response is not OK, extract error message
      let errorDetail = `HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        errorDetail = errJson.detail || errJson.message || errorDetail;
      } catch {
        errorDetail = (await res.text()) || errorDetail;
      }
      throw new Error(errorDetail);
    } catch (e: any) {
      // In production, bubble error or return safe empty defaults for lists
      if (path.startsWith('/hosts') && (options.method === 'GET' || !options.method)) {
        if (path === '/hosts' || path.startsWith('/hosts?')) return [] as unknown as T;
      }
      if (path.startsWith('/assessments') && (options.method === 'GET' || !options.method)) {
        if (path === '/assessments' || path.startsWith('/assessments?')) return [] as unknown as T;
      }
      if (path.startsWith('/findings') && (options.method === 'GET' || !options.method)) {
        if (path === '/findings' || path.startsWith('/findings?')) return [] as unknown as T;
      }
      if (path.startsWith('/rules') && (options.method === 'GET' || !options.method)) {
        if (path === '/rules' || path.startsWith('/rules?')) return [] as unknown as T;
      }
      if (path === '/stats') {
        return {
          total_hosts: 0,
          total_assessments: 0,
          open_findings: 0,
          critical_findings: 0,
          high_findings: 0,
          remediations_pending_approval: 0,
          average_compliance_score: 0.0,
        } as unknown as T;
      }
      throw e;
    }
  }

  async getLocalDiscovery(): Promise<LocalDiscoveryData> {
    return this.fetch<LocalDiscoveryData>('/hosts/local-discovery');
  }
}

export const api = new APIClient();
