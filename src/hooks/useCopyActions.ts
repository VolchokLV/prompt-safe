import { useCallback, useEffect, useRef, useState } from "react";
import { copyText } from "../lib/clipboard";

export const AUTO_CLEAR_MS = 60_000;

export type CopyState = "sanitized" | "original" | "error" | null;

interface Args {
  originalText: string;
  redactedText: string | null;
  activeFindingsCount: number;
  autoClear: boolean;
}

export function useCopyActions({
  originalText,
  redactedText,
  activeFindingsCount,
  autoClear,
}: Args) {
  const [copied, setCopied] = useState<CopyState>(null);
  const [confirmingOriginal, setConfirmingOriginal] = useState(false);
  const confirmTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(null), copied === "error" ? 4000 : 2000);
    return () => clearTimeout(t);
  }, [copied]);

  useEffect(() => () => clearTimeout(confirmTimer.current), []);

  const doCopy = useCallback(
    async (text: string, kind: "sanitized" | "original") => {
      try {
        await copyText(text, autoClear ? AUTO_CLEAR_MS : undefined);
        setCopied(kind);
      } catch {
        setCopied("error");
      }
    },
    [autoClear],
  );

  const copySanitized = useCallback(async () => {
    if (redactedText == null) return;
    await doCopy(redactedText, "sanitized");
  }, [doCopy, redactedText]);

  const copyOriginal = useCallback(async () => {
    if (!originalText) return;
    if (activeFindingsCount > 0 && !confirmingOriginal) {
      setConfirmingOriginal(true);
      clearTimeout(confirmTimer.current);
      confirmTimer.current = setTimeout(() => setConfirmingOriginal(false), 3000);
      return;
    }
    setConfirmingOriginal(false);
    await doCopy(originalText, "original");
  }, [activeFindingsCount, confirmingOriginal, doCopy, originalText]);

  return { copied, confirmingOriginal, copySanitized, copyOriginal };
}
