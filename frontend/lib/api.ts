/**
 * API client.
 *
 * The access token lives in a module-level variable and nowhere else. It is never
 * written to localStorage or sessionStorage: any successful XSS can read those
 * synchronously, and a token there is a token stolen. Holding it in a closure means an
 * attacker needs code execution *at the right moment* rather than a one-line read.
 *
 * The refresh token is never visible to this file at all — it is an HttpOnly cookie
 * scoped to /api/v1/auth, so script cannot read it and the browser only attaches it to
 * the refresh call itself.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api/v1";

let accessToken: string | null = null;
let expiresAt = 0;
let refreshInFlight: Promise<boolean> | null = null;
let currentUser: { id: string; displayName: string } | null = null;

export type Session = {
  access_token: string;
  expires_in: number;
  user_id: string;
  display_name: string;
  is_new_account: boolean;
};

export function setSession(session: Session): void {
  accessToken = session.access_token;
  expiresAt = Date.now() + session.expires_in * 1000;
  currentUser = { id: session.user_id, displayName: session.display_name };
}

export function clearSession(): void {
  accessToken = null;
  expiresAt = 0;
  currentUser = null;
}

/** Identity for rendering only — who "my" messages belong to. Never an authorization
 *  input: the server derives the caller from the token on every request. */
export function sessionUser(): { id: string; displayName: string } | null {
  return currentUser;
}

export function hasSession(): boolean {
  return accessToken !== null;
}

function csrfToken(): string {
  // Readable-by-script half of the double-submit pair. Its secrecy is not the point —
  // the point is that a cross-site attacker cannot read the cookie to echo it back.
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function refresh(): Promise<boolean> {
  // Collapse concurrent refreshes. Two parallel 401s must not both rotate: the second
  // would present an already-rotated token and trip reuse detection, killing the
  // session family and logging the user out for no reason.
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include", // the only call that sends the cookie
        headers: { "X-CSRF-Token": csrfToken() },
      });
      if (!response.ok) {
        clearSession();
        return false;
      }
      setSession(await response.json());
      return true;
    } catch {
      clearSession();
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

export async function api<T>(
  path: string,
  options: RequestInit & { retryOnAuthFailure?: boolean } = {},
): Promise<T> {
  const { retryOnAuthFailure = true, ...init } = options;

  // Refresh slightly early rather than waiting for a 401, so a long-composed message
  // does not fail on send.
  if (accessToken && Date.now() > expiresAt - 30_000) await refresh();

  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: "omit", // bearer only; no ambient cookie authority on data routes
  });

  if (response.status === 401 && retryOnAuthFailure) {
    if (await refresh()) {
      return api<T>(path, { ...options, retryOnAuthFailure: false });
    }
    throw new ApiError("reauthentication_required", 401);
  }

  if (!response.ok) {
    let detail = "request_failed";
    try {
      detail = (await response.json()).detail ?? detail;
    } catch {
      /* non-JSON error body; keep the generic code */
    }
    throw new ApiError(detail, response.status);
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
    this.name = "ApiError";
  }
}

// ---------------------------------------------------------------- endpoints
export const auth = {
  requestOtp: (phone: string) =>
    api<{ challenge_id: string; expires_in: number }>("/auth/otp/request", {
      method: "POST",
      body: JSON.stringify({ phone }),
      retryOnAuthFailure: false,
    }),

  verifyOtp: async (challengeId: string, code: string, phone: string) => {
    const response = await fetch(`${API_BASE}/auth/otp/verify`, {
      method: "POST",
      credentials: "include", // needed so the refresh cookie is stored
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_id: challengeId, code, phone, platform: "WEB" }),
    });
    if (!response.ok) throw new ApiError("verification_failed", response.status);
    const session: Session = await response.json();
    setSession(session);
    return session;
  },

  logout: () => api<void>("/auth/logout", { method: "POST" }),
  devices: () => api<Device[]>("/auth/devices"),
  revokeDevice: (id: string) => api<void>(`/auth/devices/${id}`, { method: "DELETE" }),
  restore: refresh, // used once on mount to recover a session from the cookie
};

export const chat = {
  conversations: () => api<Conversation[]>("/conversations"),
  createDirect: (userId: string) =>
    api<{ id: string }>("/conversations/direct", {
      method: "POST",
      body: JSON.stringify({ user_id: userId }),
    }),
  messages: (id: string, before?: number) =>
    api<{ messages: Message[] }>(
      `/conversations/${id}/messages?limit=50${before ? `&before=${before}` : ""}`,
    ),
  send: (id: string, clientMsgId: string, body: string, replyTo?: string) =>
    api<{ message: Message; created: boolean }>(`/conversations/${id}/messages`, {
      method: "POST",
      body: JSON.stringify({ client_msg_id: clientMsgId, body, reply_to_id: replyTo }),
    }),
  markRead: (id: string, upToSeq: number) =>
    api<void>(`/conversations/${id}/read`, {
      method: "POST",
      body: JSON.stringify({ up_to_seq: upToSeq }),
    }),
  search: (q: string) => api<{ results: Message[] }>(`/search?q=${encodeURIComponent(q)}`),
  sync: (after: number) =>
    api<{ events: SyncEvent[]; cursor: number }>(`/sync?after=${after}`),
  wsTicket: () => api<{ ticket: string }>("/ws/ticket", { method: "POST" }),
};

// ------------------------------------------------------------------- types
export type Conversation = {
  id: string;
  kind: "DIRECT" | "GROUP" | "CHANNEL";
  title: string | null;
  last_seq: number;
  unread: number;
  role: string;
  muted: boolean;
};

export type Message = {
  id: string;
  seq: number;
  conversation_id: string;
  sender_id: string | null;
  kind: string;
  body: string | null;
  client_msg_id: string;
  reply_to_id: string | null;
  edited_at: string | null;
  deleted: boolean;
  created_at: string;
};

export type Device = {
  id: string;
  platform: string;
  label: string;
  created_at: string;
  last_active_at: string;
  is_current: boolean;
};

export type SyncEvent = {
  event_id: number;
  type: string;
  conversation_id: string;
  payload: Record<string, unknown>;
};
