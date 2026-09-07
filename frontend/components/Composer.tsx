"use client";

import { useEffect, useRef, useState } from "react";

type Props = {
  onSend: (body: string) => void;
  onTyping: (active: boolean) => void;
  disabled?: boolean;
};

export default function Composer({ onSend, onTyping, disabled }: Props) {
  const [value, setValue] = useState("");
  const typingActive = useRef(false);
  const stopTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const textarea = useRef<HTMLTextAreaElement>(null);

  // Emit typing.start once and let it lapse, rather than firing per keystroke. A
  // per-keystroke event is a Redis write and a fan-out for every character typed.
  function handleChange(next: string) {
    setValue(next);
    if (!typingActive.current && next.length > 0) {
      typingActive.current = true;
      onTyping(true);
    }
    if (stopTimer.current) clearTimeout(stopTimer.current);
    stopTimer.current = setTimeout(() => {
      typingActive.current = false;
      onTyping(false);
    }, 3000);
  }

  function submit() {
    const body = value.trim();
    if (!body || disabled) return;
    onSend(body);
    setValue("");
    typingActive.current = false;
    onTyping(false);
    textarea.current?.focus();
  }

  useEffect(() => () => { if (stopTimer.current) clearTimeout(stopTimer.current); }, []);

  return (
    <div className="border-t border-surface-edge bg-surface px-3 py-2.5">
      <div className="flex items-end gap-2">
        <textarea
          ref={textarea}
          rows={1}
          value={value}
          disabled={disabled}
          placeholder="Message"
          aria-label="Message"
          onChange={(e) => handleChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
          className="max-h-32 min-h-[42px] flex-1 resize-none rounded-2xl border border-surface-edge px-3.5 py-2.5 text-[15px] outline-none focus:border-accent disabled:opacity-50"
        />
        <button
          onClick={submit}
          disabled={disabled || value.trim().length === 0}
          className="h-[42px] shrink-0 rounded-2xl bg-accent px-4 text-[15px] font-medium text-white disabled:opacity-40"
        >
          Send
        </button>
      </div>
    </div>
  );
}
