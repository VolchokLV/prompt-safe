import { beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_PREFS, loadPrefs, savePrefs } from "../prefs";
import { buildRows } from "../redactedRows";
import { countLines, formatBytes, plural } from "../text";

describe("countLines", () => {
  it("matches split-based counting", () => {
    for (const s of ["", "a", "a\n", "a\nb", "\n\n\n", "x\ny\nz\n"]) {
      expect(countLines(s)).toBe(s ? s.split("\n").length : 0);
    }
  });
});

describe("formatting helpers", () => {
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
  it("pluralizes", () => {
    expect(plural(1, "secret")).toBe("1 secret");
    expect(plural(3, "secret")).toBe("3 secrets");
  });
});

describe("buildRows", () => {
  it("renders every line under the limit", () => {
    const rows = buildRows("a\nb\nc", 10);
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.kind === "line")).toBe(true);
  });

  it("windows huge input to placeholder lines ±1 with gap markers", () => {
    const lines = Array.from({ length: 20 }, (_, i) => `line ${i}`);
    lines[10] = "key = [REDACTED_OPENAI_KEY_1]";
    const rows = buildRows(lines.join("\n"), 5);
    expect(rows).toEqual([
      { kind: "gap", count: 9, key: 0 },
      { kind: "line", lineNo: 10, text: "line 9" },
      { kind: "line", lineNo: 11, text: "key = [REDACTED_OPENAI_KEY_1]" },
      { kind: "line", lineNo: 12, text: "line 11" },
      { kind: "gap", count: 8, key: 12 },
    ]);
  });
});

describe("prefs", () => {
  beforeEach(() => localStorage.clear());

  it("returns defaults when nothing is stored", () => {
    expect(loadPrefs()).toEqual(DEFAULT_PREFS);
  });

  it("round-trips and ignores malformed fields", () => {
    savePrefs({ ...DEFAULT_PREFS, autoClearClipboard: true, lastTab: "settings" });
    expect(loadPrefs().autoClearClipboard).toBe(true);
    expect(loadPrefs().lastTab).toBe("settings");

    localStorage.setItem(
      "prompt-safe.prefs.v1",
      JSON.stringify({ clipboardHotkey: "yes", redactEntropyOverflow: false }),
    );
    const p = loadPrefs();
    expect(p.clipboardHotkey).toBe(DEFAULT_PREFS.clipboardHotkey);
    expect(p.redactEntropyOverflow).toBe(false);
  });

  it("survives corrupt JSON", () => {
    localStorage.setItem("prompt-safe.prefs.v1", "{not json");
    expect(loadPrefs()).toEqual(DEFAULT_PREFS);
  });
});
