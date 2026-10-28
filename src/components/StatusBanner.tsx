import { useEffect, useState } from "react";
import type { ScanStatus } from "../hooks/useScanner";
import type { ScanResult } from "../types/scan";

interface Props {
  status: ScanStatus;
  result: ScanResult | null;
  error: string | null;
}

export default function StatusBanner({ status, result, error }: Props) {
  // Only surface the "scanning" state if it lasts longer than 300ms,
  // so quick scans don't flash the banner.
  const [showScanning, setShowScanning] = useState(false);
  useEffect(() => {
    if (status !== "scanning") {
      setShowScanning(false);
      return;
    }
    const t = setTimeout(() => setShowScanning(true), 300);
    return () => clearTimeout(t);
  }, [status]);

  if (error) {
    return (
      <Banner className="bg-red-950 border-red-800 text-red-200">
        <Dot className="bg-red-400" />
        Scan failed: {error}
      </Banner>
    );
  }

  if (status === "scanning" && showScanning) {
    return (
      <Banner className="bg-amber-950 border-amber-800 text-amber-200">
        <Dot className="bg-amber-400 animate-pulse" />
        Scanning…
      </Banner>
    );
  }

  if (status === "idle" || (status === "scanning" && !result)) {
    return (
      <Banner className="bg-neutral-900 border-neutral-800 text-neutral-400">
        <Dot className="bg-neutral-500" />
        Paste text below to scan it for secrets before sending it to an AI
        agent.
      </Banner>
    );
  }

  const findings = result?.findings ?? [];
  const active = findings.filter((f) => !f.dismissed);
  const categories = new Set(active.map((f) => f.category)).size;

  if (findings.length === 0) {
    const overflow = result?.stats.entropyOverflowRedacted ?? false;
    return (
      <Banner className="bg-emerald-950 border-emerald-800 text-emerald-200">
        <Dot className="bg-emerald-400" />
        <span className="font-semibold">No known secrets detected.</span>
        <span className="text-emerald-300/80">
          {overflow
            ? "Some high-entropy strings were redacted anyway — use the sanitized copy."
            : "Heuristic scan — give it a quick read before sharing."}
        </span>
      </Banner>
    );
  }

  if (active.length === 0) {
    return (
      <Banner className="bg-amber-950 border-amber-800 text-amber-200">
        <Dot className="bg-amber-400" />
        All {findings.length} finding{findings.length === 1 ? "" : "s"}{" "}
        dismissed — copy at your own risk.
      </Banner>
    );
  }

  return (
    <Banner className="bg-red-950 border-red-800 text-red-200">
      <Dot className="bg-red-400" />
      <span className="font-semibold">
        {active.length} secret{active.length === 1 ? "" : "s"} found
      </span>
      <span className="text-red-300">
        across {categories} type{categories === 1 ? "" : "s"} — do not paste
        this into an agent. Use the sanitized copy.
      </span>
    </Banner>
  );
}

function Banner({
  className,
  children,
}: {
  className: string;
  children: React.ReactNode;
}) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={`flex items-center gap-2.5 border-b px-4 py-2.5 text-sm ${className}`}
    >
      {children}
    </div>
  );
}

function Dot({ className }: { className: string }) {
  return (
    <span
      aria-hidden
      className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${className}`}
    />
  );
}
