// terminals.js – per-session xterm instance helpers (browser-only module).
//
// This file owns the xterm/DOM lifecycle. main.js owns the Wails bindings
// (App.WriteInput, App.ResizeSession, EventsOn/Off). Splitting them keeps this
// module importable and its helpers reusable without touching the IPC layer.
//
// The module cannot be covered by `node --test` because xterm.js requires a
// browser DOM. Correctness is verified through the real app instead.

import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon } from '@xterm/addon-search';

const SCROLLBACK = 8000;
const FONT_FAMILY = 'Consolas, monospace';

// makeEntry creates one xterm + FitAddon + SearchAddon inside hostEl.
// Callers own onData / onResize wiring; this function only creates and opens.
export function makeEntry(hostEl, fontSize, theme) {
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: FONT_FAMILY,
    fontSize,
    scrollback: SCROLLBACK,
    theme,
  });
  const fit = new FitAddon();
  const search = new SearchAddon();
  term.loadAddon(fit);
  term.loadAddon(search);
  term.open(hostEl);
  return { term, fit, search, host: hostEl };
}

// createSessionPane appends a new hidden .termPane div inside wrap and returns
// the entry. The caller must call showPane(sid) (which flips display) when the
// session becomes active.
export function createSessionPane(wrap, fontSize, theme) {
  const host = document.createElement('div');
  host.className = 'termPane';
  host.style.display = 'none';
  wrap.appendChild(host);
  return makeEntry(host, fontSize, theme);
}

// disposeEntry cleanly removes an xterm instance and its DOM node.
// Safe to call with null (no-op).
export function disposeEntry(entry) {
  if (!entry) return;
  try { entry.term.dispose(); } catch (_) { /* already disposed */ }
  try { entry.host.remove(); } catch (_) { /* already detached */ }
}

// addKeyboardScroll installs a capture-phase Shift+PageUp/PageDown scroll
// handler on hostEl — xterm leaves those keys to the shell, so without this
// a keyboard user has no scrollback navigation. getTerm is a zero-argument
// function that returns the xterm Terminal to scroll (or null).
export function addKeyboardScroll(hostEl, getTerm) {
  hostEl.addEventListener('keydown', (e) => {
    if (!e.shiftKey || e.ctrlKey || e.altKey) return;
    if (e.key !== 'PageUp' && e.key !== 'PageDown') return;
    const term = getTerm();
    if (!term) return;
    e.preventDefault();
    e.stopPropagation();
    const rows = term.rows || 24;
    try { term.scrollLines(e.key === 'PageUp' ? -rows : rows); } catch (_) {}
  }, true);
}

// setThemeAll applies a new theme object to every entry in the entries map.
// Entries whose term has already been disposed are silently skipped.
export function setThemeAll(entries, theme) {
  for (const e of Object.values(entries)) {
    try { e.term.options.theme = theme; } catch (_) {}
  }
}

// setFontSizeAll updates the font size on every entry in the entries map.
export function setFontSizeAll(entries, px) {
  for (const e of Object.values(entries)) {
    try { e.term.options.fontSize = px; } catch (_) {}
  }
}
