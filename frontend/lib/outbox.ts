/**
 * Optimistic send with retry.
 *
 * Each outgoing message carries a client-generated UUID that the server treats as an
 * idempotency key. That is what makes retrying safe: if the first attempt actually
 * reached the server and only the response was lost, the retry returns the original
 * message instead of creating a duplicate.
 *
 * Nothing is ever dropped silently. A message that exhausts its retries stays visible
 * in FAILED state with the text intact, so the user can retry it or copy it out.
 */
import { chat, type Message } from "./api";

export type SendState = "SENDING" | "SENT" | "DELIVERED" | "READ" | "FAILED";

export type PendingMessage = {
  clientMsgId: string;
  conversationId: string;
  body: string;
  state: SendState;
  attempts: number;
  createdAt: number;
  serverMessage?: Message;
};

const MAX_ATTEMPTS = 4;

export function newClientMsgId(): string {
  return crypto.randomUUID();
}

export async function sendWithRetry(
  pending: PendingMessage,
  onStateChange: (update: PendingMessage) => void,
): Promise<void> {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      const result = await chat.send(pending.conversationId, pending.clientMsgId, pending.body);
      onStateChange({ ...pending, state: "SENT", attempts: attempt, serverMessage: result.message });
      return;
    } catch (error) {
      const status = (error as { status?: number }).status;
      // A rejection on the merits will not become valid by repeating it.
      if (status && status >= 400 && status < 500 && status !== 429) {
        onStateChange({ ...pending, state: "FAILED", attempts: attempt });
        return;
      }
      if (attempt === MAX_ATTEMPTS) {
        onStateChange({ ...pending, state: "FAILED", attempts: attempt });
        return;
      }
      const delay = Math.random() * Math.min(8000, 400 * 2 ** attempt);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
