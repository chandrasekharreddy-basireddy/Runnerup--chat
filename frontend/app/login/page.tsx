"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { auth, ApiError } from "@/lib/api";

type Step = "phone" | "code";

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("phone");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const codeInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (step === "code") codeInput.current?.focus();
  }, [step]);

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const timer = setTimeout(() => setSecondsLeft((s) => s - 1), 1000);
    return () => clearTimeout(timer);
  }, [secondsLeft]);

  async function requestCode() {
    setBusy(true);
    setError(null);
    try {
      const { challenge_id, expires_in } = await auth.requestOtp(phone);
      setChallengeId(challenge_id);
      setSecondsLeft(expires_in);
      setStep("code");
    } catch (e) {
      // The server gives the same answer for a registered and an unregistered number,
      // so there is nothing here that could reveal whether the account exists.
      setError(
        e instanceof ApiError && e.status === 429
          ? "Too many attempts. Wait a few minutes before trying again."
          : "Check the number and try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function submitCode() {
    setBusy(true);
    setError(null);
    try {
      await auth.verifyOtp(challengeId, code, phone);
      router.replace("/chat");
    } catch {
      // Deliberately one message. The API does not distinguish wrong, expired and
      // already-used codes, and neither should the interface.
      setError("That code did not work. Request a new one if it has expired.");
      setCode("");
      codeInput.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-5">
      <div className="w-full max-w-sm">
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="mt-1.5 text-sm text-ink-faint">
          {step === "phone"
            ? "We'll text you a six-digit code."
            : `Enter the code sent to ${phone}.`}
        </p>

        <div className="mt-7 rounded-xl border border-surface-edge bg-surface p-5">
          {step === "phone" ? (
            <>
              <label htmlFor="phone" className="block text-sm font-medium">
                Phone number
              </label>
              <input
                id="phone"
                type="tel"
                inputMode="tel"
                autoComplete="tel"
                placeholder="+91 98765 43210"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && phone && requestCode()}
                className="mt-1.5 w-full rounded-lg border border-surface-edge px-3 py-2.5 text-[15px] outline-none focus:border-accent"
              />
              <button
                onClick={requestCode}
                disabled={busy || phone.length < 6}
                className="mt-4 w-full rounded-lg bg-accent px-4 py-2.5 text-[15px] font-medium text-white disabled:opacity-40"
              >
                {busy ? "Sending…" : "Send code"}
              </button>
            </>
          ) : (
            <>
              <label htmlFor="code" className="block text-sm font-medium">
                Verification code
              </label>
              <input
                ref={codeInput}
                id="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                onKeyDown={(e) => e.key === "Enter" && code.length === 6 && submitCode()}
                className="mt-1.5 w-full rounded-lg border border-surface-edge px-3 py-2.5 text-center text-xl tracking-[0.4em] outline-none focus:border-accent"
              />
              <button
                onClick={submitCode}
                disabled={busy || code.length !== 6}
                className="mt-4 w-full rounded-lg bg-accent px-4 py-2.5 text-[15px] font-medium text-white disabled:opacity-40"
              >
                {busy ? "Verifying…" : "Verify"}
              </button>
              <button
                onClick={() => { setStep("phone"); setCode(""); setError(null); }}
                className="mt-3 w-full text-sm text-ink-faint underline underline-offset-2"
              >
                Use a different number
              </button>
              {secondsLeft > 0 && (
                <p className="mt-3 text-center text-xs text-ink-faint">
                  Code expires in {Math.floor(secondsLeft / 60)}:
                  {String(secondsLeft % 60).padStart(2, "0")}
                </p>
              )}
            </>
          )}

          {error && (
            <p role="alert" className="mt-3 text-sm text-danger">
              {error}
            </p>
          )}
        </div>

        <p className="mt-5 text-center text-xs leading-relaxed text-ink-faint">
          Messages are encrypted in transit. They are not end-to-end encrypted.
        </p>
      </div>
    </main>
  );
}
