import { useEffect } from "react";

export interface ToastMessage {
  id: number;
  tone: "success" | "info" | "error";
  text: string;
}

const TONE: Record<ToastMessage["tone"], string> = {
  success: "border-emerald-700 bg-emerald-950 text-emerald-100",
  info: "border-neutral-700 bg-neutral-900 text-neutral-100",
  error: "border-red-800 bg-red-950 text-red-100",
};

export default function Toast({
  toast,
  onDone,
}: {
  toast: ToastMessage | null;
  onDone: () => void;
}) {
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(onDone, toast.tone === "error" ? 6000 : 3500);
    return () => clearTimeout(t);
  }, [toast, onDone]);

  return (
    <div
      role="status"
      aria-live="polite"
      className="pointer-events-none fixed bottom-20 left-1/2 z-50 -translate-x-1/2"
    >
      {toast && (
        <div
          key={toast.id}
          className={`pointer-events-auto max-w-md rounded-md border px-4 py-2.5 text-sm shadow-lg ${TONE[toast.tone]}`}
        >
          {toast.text}
        </div>
      )}
    </div>
  );
}
