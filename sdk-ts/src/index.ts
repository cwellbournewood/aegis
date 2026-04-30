/**
 * AEGIS — Authenticated Execution Gateway for Injection Security.
 *
 * TypeScript client for the AEGIS sidecar proxy.
 */

export type Decision = "ALLOW" | "WARN" | "BLOCK";
export type Upstream = "anthropic" | "openai" | "google";
export type ConstraintKind = "eq" | "in" | "regex" | "prefix" | "max_len" | "any";

export interface Constraint {
  kind: ConstraintKind;
  value?: unknown;
}

export interface SessionResponse {
  session_id: string;
  upstream: Upstream;
  user_intent?: string;
  canary_count: number;
  expires_at?: number;
  aegis_version: string;
}

export interface CapabilityResponse {
  token: string;
  tool: string;
  expires_at: number;
  nonce: string;
}

export interface DecisionRecord {
  seq: number;
  timestamp: number;
  hash: string;
  prev_hash: string;
  payload: {
    request_id: string;
    session_id: string;
    upstream: string;
    decision: Decision;
    reason: string;
    score: number;
    mode: string;
    votes: Record<string, { verdict: Decision; reason: string; confidence?: number }>;
    [k: string]: unknown;
  };
}

export interface AegisClientOptions {
  baseUrl?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
}

export class AegisError extends Error {
  status?: number;
  body?: unknown;
  constructor(message: string, status?: number, body?: unknown) {
    super(message);
    this.name = "AegisError";
    this.status = status;
    this.body = body;
  }
}

export class AegisClient {
  readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: AegisClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "http://localhost:8080").replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private headers(): HeadersInit {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) h["authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const resp = await this.fetchImpl(this.baseUrl + path, {
      ...init,
      headers: { ...this.headers(), ...(init.headers ?? {}) },
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      let parsed: unknown = text;
      try {
        parsed = JSON.parse(text);
      } catch {
        /* ignore */
      }
      throw new AegisError(`AEGIS request failed: ${resp.status} ${resp.statusText}`, resp.status, parsed);
    }
    return resp.json() as Promise<T>;
  }

  health(): Promise<Record<string, unknown>> {
    return this.request("/aegis/health", { method: "GET" });
  }

  async createSession(opts: {
    userIntent?: string;
    upstream?: Upstream;
    ttlSeconds?: number;
  } = {}): Promise<Session> {
    const body: Record<string, unknown> = { upstream: opts.upstream ?? "anthropic" };
    if (opts.userIntent !== undefined) body.user_intent = opts.userIntent;
    if (opts.ttlSeconds !== undefined) body.ttl_seconds = opts.ttlSeconds;
    const resp = await this.request<SessionResponse>("/aegis/session", {
      method: "POST",
      body: JSON.stringify(body),
    });
    return new Session(this, resp);
  }

  async getDecision(requestId: string): Promise<DecisionRecord> {
    return this.request<DecisionRecord>(`/aegis/decisions/${encodeURIComponent(requestId)}`, {
      method: "GET",
    });
  }

  async listDecisions(limit = 50): Promise<{ count: number; entries: DecisionRecord[] }> {
    return this.request(`/aegis/decisions?limit=${limit}`, { method: "GET" });
  }

  async _mintCapability(req: {
    sessionId: string;
    tool: string;
    constraints?: Record<string, Constraint>;
    ttlSeconds?: number;
    singleUse?: boolean;
    metadata?: Record<string, unknown>;
  }): Promise<CapabilityResponse> {
    const body: Record<string, unknown> = {
      session_id: req.sessionId,
      tool: req.tool,
      constraints: req.constraints ?? {},
      single_use: req.singleUse ?? true,
      metadata: req.metadata ?? {},
    };
    if (req.ttlSeconds !== undefined) body.ttl_seconds = req.ttlSeconds;
    return this.request<CapabilityResponse>("/aegis/capability", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }
}

export class Session {
  readonly sessionId: string;
  readonly upstream: Upstream;
  readonly userIntent?: string;
  readonly canaryCount: number;
  readonly expiresAt?: number;
  private readonly client: AegisClient;
  private readonly tokens: CapabilityResponse[] = [];

  constructor(client: AegisClient, resp: SessionResponse) {
    this.client = client;
    this.sessionId = resp.session_id;
    this.upstream = resp.upstream;
    this.userIntent = resp.user_intent;
    this.canaryCount = resp.canary_count;
    this.expiresAt = resp.expires_at;
  }

  /** URL to point an upstream-compatible client at. */
  get proxyUrl(): string {
    return `${this.client.baseUrl}/v1/${this.upstream}`;
  }

  capabilityTokens(): string[] {
    return this.tokens.map((t) => t.token);
  }

  async mintCapability(
    tool: string,
    opts: {
      constraints?: Record<string, Constraint>;
      ttlSeconds?: number;
      singleUse?: boolean;
      metadata?: Record<string, unknown>;
    } = {},
  ): Promise<CapabilityResponse> {
    const cap = await this.client._mintCapability({
      sessionId: this.sessionId,
      tool,
      constraints: opts.constraints,
      ttlSeconds: opts.ttlSeconds,
      singleUse: opts.singleUse,
      metadata: opts.metadata,
    });
    this.tokens.push(cap);
    return cap;
  }

  /** Augment an upstream request body with AEGIS extensions (session_id + capability tokens). */
  augmentBody<T extends Record<string, unknown>>(body: T): T & { aegis: Record<string, unknown> } {
    const existing = (body as { aegis?: Record<string, unknown> }).aegis ?? {};
    return {
      ...body,
      aegis: {
        ...existing,
        session_id: this.sessionId,
        capability_tokens: this.capabilityTokens(),
        ...(this.userIntent ? { user_intent: this.userIntent } : {}),
      },
    };
  }
}

// Convenience constraint builders.
export const c = {
  eq: (value: unknown): Constraint => ({ kind: "eq", value }),
  in: (values: unknown[]): Constraint => ({ kind: "in", value: values }),
  regex: (pattern: string): Constraint => ({ kind: "regex", value: pattern }),
  prefix: (prefix: string): Constraint => ({ kind: "prefix", value: prefix }),
  maxLen: (n: number): Constraint => ({ kind: "max_len", value: n }),
  any: (): Constraint => ({ kind: "any" }),
};

export default AegisClient;
