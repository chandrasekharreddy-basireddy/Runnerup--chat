/**
 * WebSocket client.
 *
 * Reconnection uses exponential backoff with full jitter. Plain exponential backoff is
 * not enough: when a server restarts, every client's timer is aligned to the same
 * disconnect instant and they all retry in lockstep, producing a thundering herd that
 * knocks the server over again. Randomising each delay across the whole window spreads
 * them out.
 *
 * The handshake fetches a single-use ticket rather than putting a token in the URL.
 * WebSocket URLs land in proxy logs and browser history exactly like any other URL.
 */
import { chat } from "./api";

export type WsEvent = {
  type: string;
  conversation_id?: string;
  message?: unknown;
  [key: string]: unknown;
};

type Listener = (event: WsEvent) => void;

const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30_000;

export class ChatSocket {
  private socket: WebSocket | null = null;
  private listeners = new Set<Listener>();
  private subscribed = new Set<string>();
  private attempt = 0;
  private closedByUs = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private url: string) {}

  on(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(event: WsEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  async connect(): Promise<void> {
    this.closedByUs = false;
    let ticket: string;
    try {
      ticket = (await chat.wsTicket()).ticket;
    } catch {
      // Usually an expired session. Back off and let the API client's refresh
      // recover it on the next attempt.
      this.scheduleReconnect();
      return;
    }

    const socket = new WebSocket(`${this.url}?ticket=${encodeURIComponent(ticket)}`);
    this.socket = socket;

    socket.onopen = () => {
      this.attempt = 0;
      this.emit({ type: "connection.open" });
      // Re-subscribe: the server authorizes subscriptions per connection and keeps no
      // memory of the previous one.
      for (const id of this.subscribed) this.sendRaw({ type: "subscribe", conversation_id: id });
    };

    socket.onmessage = (raw) => {
      let event: WsEvent;
      try {
        event = JSON.parse(raw.data);
      } catch {
        return; // ignore anything unparseable rather than throwing in the handler
      }
      if (event.type === "ping") {
        this.sendRaw({ type: "pong" });
        return;
      }
      if (event.type === "session.revoked") {
        // The server closed us out deliberately. Reconnecting would be wrong.
        this.closedByUs = true;
        this.emit(event);
        return;
      }
      this.emit(event);
    };

    socket.onclose = () => {
      this.socket = null;
      this.emit({ type: "connection.closed" });
      if (!this.closedByUs) this.scheduleReconnect();
    };

    socket.onerror = () => socket.close();
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    const ceiling = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** this.attempt);
    const delay = Math.random() * ceiling; // full jitter
    this.attempt += 1;
    this.emit({ type: "connection.reconnecting", delay_ms: Math.round(delay) });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.connect();
    }, delay);
  }

  private sendRaw(payload: Record<string, unknown>): void {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(payload));
    }
  }

  subscribe(conversationId: string): void {
    this.subscribed.add(conversationId);
    this.sendRaw({ type: "subscribe", conversation_id: conversationId });
  }

  unsubscribe(conversationId: string): void {
    this.subscribed.delete(conversationId);
    this.sendRaw({ type: "unsubscribe", conversation_id: conversationId });
  }

  typing(conversationId: string, active: boolean): void {
    this.sendRaw({ type: active ? "typing.start" : "typing.stop", conversation_id: conversationId });
  }

  close(): void {
    this.closedByUs = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.close();
  }
}

export function defaultSocketUrl(): string {
  if (process.env.NEXT_PUBLIC_WS_URL) return process.env.NEXT_PUBLIC_WS_URL;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws`;
}
