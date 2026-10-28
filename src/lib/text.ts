/** Counts lines without allocating (split() on a 5 MB paste would create
 *  ~50k strings on every keystroke). */
export function countLines(text: string): number {
  if (!text) return 0;
  let n = 1;
  let i = -1;
  while ((i = text.indexOf("\n", i + 1)) !== -1) n++;
  return n;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function plural(n: number, word: string, pluralWord = `${word}s`) {
  return `${n.toLocaleString()} ${n === 1 ? word : pluralWord}`;
}
