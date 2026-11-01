// Pure, DOM-free helpers. Anything that touches an element, xterm or the Wails
// bindings stays in main.js; these are the pieces that can be tested with
// `node --test` without a browser, which is the only frontend coverage the app
// has ever had. Keep this file free of imports.

export const DEFAULT_PORT = 22;
export const MIN_PORT = 1;
export const MAX_PORT = 65535;

// fmtSize is the file-listing counterpart of the backend's transfer.FormatSize,
// so a 4 GB file never reads "4096.0MB" in one pane and "4.00 GB" in another.
// A missing or unreadable size prints as a dash rather than "NaNMB".
export function fmtSize(n) {
  if (!Number.isFinite(n)) return '-';
  if (n < 1024) return n + 'B';
  if (n < 1048576) return (n / 1024).toFixed(1) + 'KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + 'MB';
  return (n / 1073741824).toFixed(2) + 'GB';
}

// parsePort reads one port field. A blank field takes the fallback (the connect
// form defaults to 22); anything that is not a whole number within 1-65535
// returns null so the caller can refuse. Without this, "abc" became NaN and the
// app dialled "host:NaN" or bound a forward to port 0.
export function parsePort(value, fallback = 0) {
  const raw = String(value === null || value === undefined ? '' : value).trim();
  if (raw === '') return isPort(fallback) ? fallback : null;
  if (!/^\d+$/.test(raw)) return null;
  const n = Number(raw);
  return isPort(n) ? n : null;
}

function isPort(n) {
  return Number.isInteger(n) && n >= MIN_PORT && n <= MAX_PORT;
}

// osc7Path turns an OSC 7 "file://host/path" report into a local path. The
// percent escapes are decoded, and a malformed sequence yields '' so the caller
// leaves the pane alone.
export function osc7Path(data) {
  const m = /^file:\/\/[^/]*\/(.*)$/.exec(String(data || ''));
  if (!m) return '';
  let p = '/' + m[1];
  try { p = decodeURIComponent(p); } catch (e) { /* keep the raw text */ }
  return p;
}

// joinWrappedRows stitches the screen rows one logical command line was echoed
// onto. A line wider than the terminal continues on the next row, and those
// continuation rows carry no prompt of their own: reading only the row under
// the cursor hands back the tail of a long path and the "cd" in front of it is
// gone. rows are screen rows in display order, each { text, isWrapped }, where
// isWrapped means the row continues the one above it (xterm's own flag).
export function joinWrappedRows(rows) {
  const list = Array.isArray(rows) ? rows : [];
  // One logical line is a first row that wraps into the rows below it, so the
  // last row that does not continue another is where this line began. Anything
  // before it belongs to an earlier line and is dropped.
  let start = 0;
  for (let i = 0; i < list.length; i++) {
    if (!list[i] || !list[i].isWrapped) start = i;
  }
  let out = '';
  for (let i = start; i < list.length; i++) out += (list[i] && list[i].text) || '';
  return out.replace(/\s+$/, '');
}

// logicalLine returns the whole command line the cursor row belongs to, gathered
// and stitched. read(row) is the caller's view of the screen: it answers with
// { text, isWrapped } for that row and with nothing for a row that is not there.
// The walk goes up from the cursor while each row continues the one above it and
// stops at the row that starts a line of its own, because that is where the
// prompt - and the "cd" - is. limit only bounds the work: no real line is taller
// than the screen, so reaching it means a stray flag marked a whole page wrapped.
export function logicalLine(read, cursorRow, limit = 32) {
  const rows = [];
  if (typeof read !== 'function' || !Number.isInteger(cursorRow)) return '';
  for (let r = cursorRow; r >= 0 && rows.length <= limit; r--) {
    const line = read(r);
    if (!line) break;
    rows.unshift({ text: line.text, isWrapped: !!line.isWrapped });
    if (!line.isWrapped) break;
  }
  return joinWrappedRows(rows);
}

// stripPrompt cuts the shell prompt off a screen line: "#" for root, "$" for a
// normal user, "%" for zsh. Customised prompts defeat this, which is why the
// OSC 7 handler is the primary path and the typed line only a fallback.
export function stripPrompt(text) {
  const t = String(text || '');
  const i = Math.max(t.lastIndexOf('# '), t.lastIndexOf('$ '), t.lastIndexOf('% '));
  return i >= 0 ? t.slice(i + 2) : t;
}

// parentPath is the ".." button's arithmetic: the last component is dropped, and
// the root is its own parent so the button can never escape the filesystem.
export function parentPath(p) {
  const t = String(p || '');
  const i = t.replace(/\/+$/, '').lastIndexOf('/');
  return i <= 0 ? '/' : t.substring(0, i);
}
