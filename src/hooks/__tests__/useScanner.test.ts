import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanResult } from "../../types/scan";
import { DEBOUNCE_MS, useScanner } from "../useScanner";

const scanText = vi.fn();
vi.mock("../../lib/api", () => ({
  scanText: (...args: unknown[]) => scanText(...args),
}));

function fakeResult(n: number, dismissed: number[] = []): ScanResult {
  return {
    findings: Array.from({ length: n }, (_, id) => ({
      id,
      category: "openai_api_key",
      label: "OpenAI API Key",
      severity: "critical" as const,
      line: 1,
      col: 1,
      endLine: 1,
      start: 0,
      end: 1,
      maskedPreview: "sk-p…34 (40 chars)",
      placeholder: `[REDACTED_OPENAI_KEY_${id + 1}]`,
      source: "pattern" as const,
      dismissed: dismissed.includes(id),
    })),
    redactedText: "redacted",
    stats: {
      totalLines: 1,
      inputBytes: 1,
      durationMs: 0,
      entropyFindingsCapped: false,
      entropySuppressedCount: 0,
      entropyOverflowRedacted: false,
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  scanText.mockReset();
});
afterEach(() => vi.useRealTimers());

describe("useScanner", () => {
  it("debounces typing into a single scan", async () => {
    scanText.mockResolvedValue(fakeResult(1));
    const { result } = renderHook(() => useScanner());
    act(() => {
      result.current.setText("a");
      result.current.setText("ab");
      result.current.setText("abc");
    });
    expect(scanText).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    });
    expect(scanText).toHaveBeenCalledTimes(1);
    expect(scanText).toHaveBeenCalledWith("abc", [], true);
    expect(result.current.status).toBe("findings");
  });

  it("scans immediately on paste", async () => {
    scanText.mockResolvedValue(fakeResult(0));
    const { result } = renderHook(() => useScanner());
    await act(async () => {
      result.current.setText("pasted", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(scanText).toHaveBeenCalledWith("pasted", [], true);
    expect(result.current.status).toBe("clean");
  });

  it("drops stale responses that resolve after a newer scan", async () => {
    let resolveFirst!: (r: ScanResult) => void;
    scanText
      .mockImplementationOnce(() => new Promise<ScanResult>((r) => (resolveFirst = r)))
      .mockResolvedValueOnce(fakeResult(0));
    const { result } = renderHook(() => useScanner());
    await act(async () => {
      result.current.setText("first", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      result.current.setText("second", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      resolveFirst(fakeResult(5));
    });
    expect(result.current.result?.findings).toHaveLength(0);
    expect(result.current.status).toBe("clean");
  });

  it("re-scans with dismissed ids and resets them on edit", async () => {
    scanText.mockResolvedValue(fakeResult(3));
    const { result } = renderHook(() => useScanner());
    await act(async () => {
      result.current.setText("text", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      result.current.dismissMany([0, 2]);
    });
    expect(scanText).toHaveBeenLastCalledWith("text", [0, 2], true);
    await act(async () => {
      result.current.undismiss(0);
    });
    expect(scanText).toHaveBeenLastCalledWith("text", [2], true);
    await act(async () => {
      result.current.setText("edited", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(scanText).toHaveBeenLastCalledWith("edited", [], true);
  });

  it("clearing resets to idle without scanning", () => {
    const { result } = renderHook(() => useScanner());
    act(() => result.current.clear());
    expect(result.current.status).toBe("idle");
    expect(scanText).not.toHaveBeenCalled();
  });

  it("re-scans when the overflow option flips", async () => {
    scanText.mockResolvedValue(fakeResult(1));
    const { result, rerender } = renderHook(
      ({ redactOverflow }) => useScanner({ redactOverflow }),
      { initialProps: { redactOverflow: true } },
    );
    await act(async () => {
      result.current.setText("text", { immediate: true });
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      rerender({ redactOverflow: false });
    });
    expect(scanText).toHaveBeenLastCalledWith("text", [], false);
  });
});
