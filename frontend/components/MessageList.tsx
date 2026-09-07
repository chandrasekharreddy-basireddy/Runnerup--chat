"use client";

/**
 * Virtualized message list.
 *
 * Only the rows near the viewport are mounted, so a conversation with 100,000 messages
 * costs the same as one with fifty. Rendering everything is not merely slow — past a
 * few thousand nodes the browser stops responding to input entirely.
 *
 * Message bodies are rendered as text children. There is no dangerouslySetInnerHTML
 * anywhere in this project; React escapes these by construction, which is what makes a
 * message containing markup harmless.
 */
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useLayoutEffect, useRef } from "react";
import type { Message } from "@/lib/api";
import type { PendingMessage } from "@/lib/outbox";

export type Row =
  | { kind: "server"; message: Message }
  | { kind: "pending"; pending: PendingMessage };

type Props = {
  rows: Row[];
  currentUserId: string;
  onRetry: (clientMsgId: string) => void;
  onLoadOlder: () => void;
  hasMore: boolean;
};

function statusLabel(state: PendingMessage["state"]): string {
  switch (state) {
    case "SENDING": return "Sending";
    case "SENT": return "Sent";
    case "DELIVERED": return "Delivered";
    case "READ": return "Read";
    case "FAILED": return "Not sent";
  }
}

export default function MessageList({
  rows, currentUserId, onRetry, onLoadOlder, hasMore,
}: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 64,
    overscan: 12,
    getItemKey: (index) => {
      const row = rows[index];
      return row.kind === "server" ? row.message.id : row.pending.clientMsgId;
    },
  });

  // Only auto-scroll when the user is already at the bottom. Yanking the viewport while
  // someone is reading history is one of the most irritating things a chat app can do.
  useLayoutEffect(() => {
    if (stickToBottom.current && rows.length > 0) {
      virtualizer.scrollToIndex(rows.length - 1, { align: "end" });
    }
  }, [rows.length, virtualizer]);

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const onScroll = () => {
      const distanceFromBottom =
        element.scrollHeight - element.scrollTop - element.clientHeight;
      stickToBottom.current = distanceFromBottom < 80;
      if (element.scrollTop < 200 && hasMore) onLoadOlder();
    };
    element.addEventListener("scroll", onScroll, { passive: true });
    return () => element.removeEventListener("scroll", onScroll);
  }, [hasMore, onLoadOlder]);

  return (
    <div
      ref={scrollRef}
      role="log"
      aria-live="polite"
      aria-label="Messages"
      className="h-full overflow-y-auto px-4 py-3"
    >
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((item) => {
          const row = rows[item.index];
          const isPending = row.kind === "pending";
          const senderId = isPending ? currentUserId : row.message.sender_id;
          const mine = senderId === currentUserId;
          const body = isPending ? row.pending.body : row.message.body;
          const deleted = !isPending && row.message.deleted;

          return (
            <div
              key={item.key}
              ref={virtualizer.measureElement}
              data-index={item.index}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${item.start}px)`,
              }}
              className={`flex py-1 ${mine ? "justify-end" : "justify-start"}`}
            >
              <div className={`max-w-[78%] ${mine ? "items-end" : "items-start"} flex flex-col`}>
                <div
                  className={[
                    "rounded-2xl px-3.5 py-2 text-[15px] leading-snug break-words",
                    deleted
                      ? "bg-surface-sunk italic text-ink-faint"
                      : mine
                        ? "bg-accent text-white"
                        : "bg-surface text-ink border border-surface-edge",
                    isPending && row.pending.state === "FAILED" ? "opacity-60" : "",
                  ].join(" ")}
                >
                  {/* Text child, not HTML. This is the XSS boundary. */}
                  {deleted ? "This message was deleted" : body}
                </div>

                <div className="mt-0.5 flex items-center gap-2 px-1 text-[11px] text-ink-faint">
                  {!isPending && row.message.edited_at && <span>edited</span>}
                  {isPending && <span>{statusLabel(row.pending.state)}</span>}
                  {isPending && row.pending.state === "FAILED" && (
                    <button
                      onClick={() => onRetry(row.pending.clientMsgId)}
                      className="font-medium text-danger underline underline-offset-2"
                    >
                      Retry
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
