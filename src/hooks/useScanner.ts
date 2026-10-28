import { useCallback, useEffect, useRef, useState } from "react";
import { scanText } from "../lib/api";
import type { ScanResult } from "../types/scan";

export type ScanStatus = "idle" | "scanning" | "clean" | "findings";

export const DEBOUNCE_MS = 500;
export const DEBOUNCE_LARGE_MS = 1000;
export const LARGE_INPUT_CHARS = 1_000_000;

export interface UseScannerOptions {
  /** Redact high-entropy values beyond the listing cap. */
  redactOverflow?: boolean;
}

export function useScanner({ redactOverflow = true }: UseScannerOptions = {}) {
  const [text, setTextState] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const dismissedRef = useRef<Set<number>>(new Set());
  const textRef = useRef("");
  const overflowRef = useRef(redactOverflow);

  const runScan = useCallback(async (t: string, ignored: number[]) => {
    const mySeq = ++seq.current;
    setStatus("scanning");
    setError(null);
    try {
      const res = await scanText(t, ignored, overflowRef.current);
      if (mySeq !== seq.current) return; // stale response
      setResult(res);
      setStatus(
        res.findings.length > 0 || res.stats.entropyOverflowRedacted
          ? "findings"
          : "clean",
      );
    } catch (e) {
      if (mySeq !== seq.current) return;
      setError(String(e));
      setStatus("idle");
    }
  }, []);

  const rescan = useCallback(() => {
    if (textRef.current) {
      void runScan(textRef.current, [...dismissedRef.current]);
    }
  }, [runScan]);

  const setText = useCallback(
    (t: string, opts?: { immediate?: boolean }) => {
      setTextState(t);
      textRef.current = t;
      dismissedRef.current = new Set(); // edits invalidate finding ids
      if (timer.current) clearTimeout(timer.current);
      if (!t) {
        seq.current++;
        setResult(null);
        setStatus("idle");
        setError(null);
        return;
      }
      const delay = opts?.immediate
        ? 0
        : t.length > LARGE_INPUT_CHARS
          ? DEBOUNCE_LARGE_MS
          : DEBOUNCE_MS;
      timer.current = setTimeout(() => void runScan(t, []), delay);
    },
    [runScan],
  );

  // Re-scan when the overflow option flips (keeps dismissals: ids are
  // unaffected because overflow values are never listed).
  useEffect(() => {
    if (overflowRef.current === redactOverflow) return;
    overflowRef.current = redactOverflow;
    rescan();
  }, [redactOverflow, rescan]);

  useEffect(() => () => clearTimeout(timer.current), []);

  const dismissMany = useCallback(
    (ids: number[]) => {
      ids.forEach((id) => dismissedRef.current.add(id));
      rescan();
    },
    [rescan],
  );

  const undismissMany = useCallback(
    (ids: number[]) => {
      ids.forEach((id) => dismissedRef.current.delete(id));
      rescan();
    },
    [rescan],
  );

  const dismiss = useCallback((id: number) => dismissMany([id]), [dismissMany]);
  const undismiss = useCallback(
    (id: number) => undismissMany([id]),
    [undismissMany],
  );

  const clear = useCallback(() => setText(""), [setText]);

  return {
    text,
    setText,
    result,
    status,
    error,
    dismiss,
    undismiss,
    dismissMany,
    undismissMany,
    clear,
  };
}
