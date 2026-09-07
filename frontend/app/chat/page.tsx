"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Composer from "@/components/Composer";
import MessageList, { type Row } from "@/components/MessageList";
import { auth, chat, hasSession, sessionUser, type Conversation, type Message } from "@/lib/api";
import { newClientMsgId, sendWithRetry, type PendingMessage } from "@/lib/outbox";
import { ChatSocket, defaultSocketUrl, type WsEvent } from "@/lib/ws";

type ConnectionState = "connecting" | "online" | "reconnecting" | "offline";

export default function ChatPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [userId, setUserId] = useState("");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [pending, setPending] = useState<PendingMessage[]>([]);
  const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const socketRef = useRef<ChatSocket | null>(null);
  const activeIdRef = useRef<string | null>(null);

  activeIdRef.current = activeId;

  // ---- session restore -----------------------------------------------------
  // The access token is in memory only, so a page reload always starts without one.
  // The HttpOnly refresh cookie is what makes the session survive; if it is missing or
  // its family was revoked, this fails and we land on the login screen.
  useEffect(() => {
    (async () => {
      if (!hasSession() && !(await auth.restore())) {
        router.replace("/login");
        return;
      }
      // Populated by setSession on both fresh login and cookie-based restore.
      setUserId(sessionUser()?.id ?? "");
      const list = await chat.conversations();
      setConversations(list);
      setReady(true);
    })().catch(() => router.replace("/login"));
  }, [router]);

  // ---- realtime ------------------------------------------------------------
  useEffect(() => {
    if (!ready) return;
    const socket = new ChatSocket(defaultSocketUrl());
    socketRef.current = socket;

    const off = socket.on((event: WsEvent) => {
      switch (event.type) {
        case "connection.open":
          setConnection("online");
          break;
        case "connection.reconnecting":
          setConnection("reconnecting");
          break;
        case "connection.closed":
          setConnection((s) => (s === "online" ? "reconnecting" : s));
          break;
        case "session.revoked":
          // Another device revoked this session. Do not silently retry.
          setConnection("offline");
          router.replace("/login");
          break;
        case "message.created": {
          const incoming = event.message as Message;
          if (incoming.conversation_id !== activeIdRef.current) {
            setConversations((list) =>
              list.map((c) =>
                c.id === incoming.conversation_id
                  ? { ...c, unread: c.unread + 1, last_seq: incoming.seq }
                  : c,
              ),
            );
            return;
          }
          setMessages((current) =>
            current.some((m) => m.id === incoming.id) ? current : [...current, incoming],
          );
          break;
        }
        case "message.deleted":
          setMessages((current) =>
            current.map((m) =>
              m.id === event.id ? { ...m, deleted: true, body: null } : m,
            ),
          );
          break;
        case "typing": {
          const who = String(event.user_id);
          setTypingUsers((current) => {
            const next = new Set(current);
            if (event.active) next.add(who);
            else next.delete(who);
            return next;
          });
          break;
        }
      }
    });

    void socket.connect();
    return () => { off(); socket.close(); };
  }, [ready, router]);

  // ---- conversation switching ---------------------------------------------
  const openConversation = useCallback(async (id: string) => {
    setActiveId(id);
    setMessages([]);
    setTypingUsers(new Set());
    socketRef.current?.subscribe(id);
    const { messages: page } = await chat.messages(id);
    // The API returns newest-first for cursor efficiency; display is oldest-first.
    const ordered = [...page].reverse();
    setMessages(ordered);
    const newest = ordered.at(-1);
    if (newest) {
      await chat.markRead(id, newest.seq);
      setConversations((list) =>
        list.map((c) => (c.id === id ? { ...c, unread: 0 } : c)),
      );
    }
  }, []);

  const loadOlder = useCallback(async () => {
    const id = activeIdRef.current;
    const oldest = messages[0];
    if (!id || !oldest) return;
    const { messages: page } = await chat.messages(id, oldest.seq);
    if (page.length) setMessages((current) => [...[...page].reverse(), ...current]);
  }, [messages]);

  // ---- sending -------------------------------------------------------------
  const send = useCallback((body: string) => {
    const id = activeIdRef.current;
    if (!id) return;
    const entry: PendingMessage = {
      clientMsgId: newClientMsgId(),
      conversationId: id,
      body,
      state: "SENDING",
      attempts: 0,
      createdAt: Date.now(),
    };
    setPending((current) => [...current, entry]);

    void sendWithRetry(entry, (updated) => {
      if (updated.state === "SENT" && updated.serverMessage) {
        // Swap the optimistic row for the authoritative one, which carries the real
        // seq and server timestamp.
        const confirmed = updated.serverMessage;
        setPending((current) => current.filter((p) => p.clientMsgId !== updated.clientMsgId));
        setMessages((current) =>
          current.some((m) => m.id === confirmed.id) ? current : [...current, confirmed],
        );
      } else {
        setPending((current) =>
          current.map((p) => (p.clientMsgId === updated.clientMsgId ? updated : p)),
        );
      }
    });
  }, []);

  const retry = useCallback((clientMsgId: string) => {
    setPending((current) => {
      const entry = current.find((p) => p.clientMsgId === clientMsgId);
      if (entry) {
        // Same clientMsgId deliberately: the server deduplicates, so a retry after a
        // lost response returns the original rather than posting twice.
        void sendWithRetry({ ...entry, state: "SENDING" }, (updated) =>
          setPending((list) =>
            updated.state === "SENT"
              ? list.filter((p) => p.clientMsgId !== updated.clientMsgId)
              : list.map((p) => (p.clientMsgId === updated.clientMsgId ? updated : p)),
          ),
        );
      }
      return current.map((p) =>
        p.clientMsgId === clientMsgId ? { ...p, state: "SENDING" as const } : p,
      );
    });
  }, []);

  const rows: Row[] = useMemo(
    () => [
      ...messages.map((message) => ({ kind: "server" as const, message })),
      ...pending
        .filter((p) => p.conversationId === activeId)
        .map((p) => ({ kind: "pending" as const, pending: p })),
    ],
    [messages, pending, activeId],
  );

  if (!ready) {
    return (
      <main className="flex min-h-screen items-center justify-center text-sm text-ink-faint">
        Loading…
      </main>
    );
  }

  const active = conversations.find((c) => c.id === activeId);

  return (
    <main className="flex h-screen flex-col md:flex-row">
      <aside
        className={`${activeId ? "hidden md:flex" : "flex"} w-full flex-col border-r border-surface-edge bg-surface md:w-80`}
      >
        <header className="flex items-center justify-between border-b border-surface-edge px-4 py-3">
          <h1 className="text-base font-semibold">Chats</h1>
          <button
            onClick={async () => { await auth.logout(); router.replace("/login"); }}
            className="text-sm text-ink-faint underline underline-offset-2"
          >
            Sign out
          </button>
        </header>
        <ul className="flex-1 overflow-y-auto">
          {conversations.length === 0 && (
            <li className="px-4 py-6 text-sm text-ink-faint">No conversations yet.</li>
          )}
          {conversations.map((c) => (
            <li key={c.id}>
              <button
                onClick={() => openConversation(c.id)}
                className={`flex w-full items-center justify-between px-4 py-3 text-left hover:bg-surface-sunk ${
                  c.id === activeId ? "bg-accent-soft" : ""
                }`}
              >
                <span className="truncate text-[15px]">
                  {c.title ?? (c.kind === "DIRECT" ? "Direct message" : "Untitled")}
                </span>
                {c.unread > 0 && (
                  <span className="ml-2 shrink-0 rounded-full bg-accent px-2 py-0.5 text-xs font-medium text-white">
                    {c.unread}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <section className={`${activeId ? "flex" : "hidden md:flex"} flex-1 flex-col`}>
        {activeId ? (
          <>
            <header className="flex items-center gap-3 border-b border-surface-edge bg-surface px-4 py-3">
              <button
                onClick={() => setActiveId(null)}
                className="text-sm text-ink-faint md:hidden"
                aria-label="Back to conversations"
              >
                Back
              </button>
              <h2 className="flex-1 truncate text-[15px] font-medium">
                {active?.title ?? "Direct message"}
              </h2>
              {connection !== "online" && (
                <span className="text-xs text-ink-faint" role="status">
                  {connection === "reconnecting" ? "Reconnecting…" : "Offline"}
                </span>
              )}
            </header>

            <div className="min-h-0 flex-1">
              <MessageList
                rows={rows}
                currentUserId={userId}
                onRetry={retry}
                onLoadOlder={loadOlder}
                hasMore={messages.length >= 50}
              />
            </div>

            {typingUsers.size > 0 && (
              <p className="px-4 pb-1 text-xs text-ink-faint" aria-live="polite">
                {typingUsers.size === 1 ? "Typing…" : `${typingUsers.size} people are typing…`}
              </p>
            )}

            <Composer
              onSend={send}
              onTyping={(activeState) =>
                activeId && socketRef.current?.typing(activeId, activeState)
              }
              disabled={connection === "offline"}
            />
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-ink-faint">
            Select a conversation
          </div>
        )}
      </section>
    </main>
  );
}
