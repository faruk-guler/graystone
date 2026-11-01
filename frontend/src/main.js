import './style.css';
import '@xterm/xterm/css/xterm.css';

import * as App from '../wailsjs/go/main/App';
import { EventsOn, EventsOff, BrowserOpenURL, OnFileDrop } from '../wailsjs/runtime/runtime';
// The DOM-free helpers live apart so `node --test` in frontend/test can cover
// them without a browser, xterm or the Wails bindings.
import { DEFAULT_PORT, fmtSize, logicalLine, osc7Path, parentPath, parsePort, stripPrompt } from './utils.js';
// The tunnel row editor's rules live apart for the same reason utils.js does:
// they are pure, and `node --test` covers them without a browser.
import { draftOf, draftProblem, draftValues } from './tunnelDraft.js';
// The ssh/PuTTY one-line form for a forward, parsed apart from the UI so the
// dialog can say which line it refused.
import { parseForwardLines } from './forwardSpec.js';
import { clampInt } from './clamp.js';
import { PERM_BITS, PERM_ROWS, bitOn, modeFromFlags, octalText, parseOctal } from './perm.js';
import { queueActions, queueBarIsError, queueBarPct, queueStatusText, batchSummaries, batchSummaryText } from './queueView.js';
// Each tab owns its own xterm instance; terminals.js builds and tears them
// down, so switching tabs only flips which pane is displayed and nothing a
// session has printed - scrollback, colours, a running vim or htop - is lost.
import { makeEntry, createSessionPane, disposeEntry, addKeyboardScroll, setThemeAll, setFontSizeAll } from './terminals.js';
import { searchState, openSearchBar, closeSearchBar, updateSearchTerm, updateSearchCount, searchResultText } from './searchBar.js';

const state = {
  view: 'session',
  sessions: [],
  profiles: [],
  tunnels: [],
  currentSid: '',
  selectedProfile: null,
  // loginEntry is the terminal the PuTTY-style login flow prints into while no
  // session owns the screen; terms maps a session id to its own terminal entry.
  loginEntry: null,
  terms: {},
  editingTunnel: '',
  // A new forward is a row of its own at the foot of the table (creatingTunnel),
  // and the values being typed into whichever row is open live in tunnelDraft.
  creatingTunnel: false,
  tunnelDraft: null,
  pendingNew: false,
  cwds: {},
  prevCwds: {},
  // retryConnect is the attempt a TOFU prompt interrupted: a thunk that dials
  // again (plain Connect or duplicate-terminal) once the key is trusted.
  retryConnect: null,
};
const authMode = { active: false, echo: false, buffer: '' };
// lineBuf accumulates what is typed at the shell prompt so a submitted line can
// be inspected for "cd". Tab-completed text never reaches us as input, so a line
// containing a tab is flagged and ignored rather than resolved to a prefix.
const lineBuf = { text: '', tab: false };
const FOLLOW_KEY = 'gravel.followTerminalFolder';
const HIDDEN_KEY = 'gravel.showHidden';
const THEME_KEY = 'gravel.theme';

function $(s) { return document.querySelector(s); }
function cwd() { return state.cwds[state.currentSid] || '/'; }
// Every message goes to the backend log, so the Logs tab has a single source for
// its lines and Dump exports exactly what the user saw there. The bottom strip is
// the window's edge, not a message line: it deliberately shows nothing.
function msg(t) { try { App.LogUI(t); } catch (e) {} }

// writeNotice paints a one-off status line into the terminal the user is
// looking at: the login screen while an attempt is in flight, otherwise the
// current session's own terminal. Connection failures arrive after the running
// session has been handed the view back, so writing here - rather than during
// the attempt - is what keeps the reason on screen.
function writeNotice(text) {
  const term = activeTerm();
  if (!term) return;
  try { term.write('\r\n\x1b[2m' + text + '\x1b[0m\r\n'); } catch (e) {}
}
function followOn() { const el = $('#followTerm'); return !!(el && el.checked); }
function showHiddenOn() { const el = $('#showHidden'); return !!(el && el.checked); }

// ---------- view switching ----------
function switchView(name) {
  state.view = name;
  document.querySelectorAll('.navitem').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
  if (name === 'terminal') {
    ensureLoginTerminal();
    loadFiles(cwd());
    startQueuePoll();
    // Reveal the pane that belongs to the session on screen and re-measure it:
    // a hidden xterm cannot be fitted, so the fit has to wait until it is shown.
    showPane(state.pendingNew ? '' : state.currentSid);
    requestAnimationFrame(() => { showPane(state.pendingNew ? '' : state.currentSid); focusActive(); });
  } else { stopQueuePoll(); }
  if (name === 'tunnels') refreshTunnels();
  if (name === 'settings') refreshSettings();
  if (name === 'logs') refreshLogs();
  if (name === 'session') { refreshProfiles(); refreshSessions(); }
}

// ---------- terminal ----------
// Bounded font size, set from the Settings tab (no wheel/keyboard zoom: a
// resize the remote has not acknowledged garbles its line wrapping - the
// Settings change always pushes the new size through refitTerminal).
const ZOOM_KEY = 'gravel.termFontSize';
const CONFLICT_KEY = 'gravel.conflictPolicy';
const FONT_MIN = 10, FONT_MAX = 30, FONT_DEFAULT = 14;

function termFontSize() {
  return clampInt(localStorage.getItem(ZOOM_KEY), FONT_MIN, FONT_MAX, FONT_DEFAULT);
}

function setTermFont(px) {
  const size = clampInt(px, FONT_MIN, FONT_MAX, FONT_DEFAULT);
  // Every live terminal takes the new size, not just the visible one, so a
  // tab switch never lands on a stale font.
  if (state.loginEntry) { try { state.loginEntry.term.options.fontSize = size; } catch (e) {} }
  setFontSizeAll(state.terms, size);
  refitTerminal();
  try { localStorage.setItem(ZOOM_KEY, String(size)); } catch (e) {}
  return size;
}

// The palette lives in CSS custom properties, so the terminal and the rest of
// the UI can never disagree about which theme is active.
function termTheme() {
  const css = getComputedStyle(document.documentElement);
  const v = (name, fallback) => (css.getPropertyValue(name) || fallback).trim();
  return { background: v('--bg', '#1e1e1e'), foreground: v('--fg', '#e0e0e0'), cursor: v('--accent', '#7c8cff') };
}

// ---------- terminal core: one xterm per tab ----------
//
// The login screen and every session own a Terminal instance in a .termPane of
// their own inside #termWrap. Selecting a tab changes only which pane is
// displayed, so a session keeps its scrollback, its colours and the screen state
// of a running full-program (vim, htop, tmux). The previous design shared one
// widget and re-painted it from a plaintext snapshot of a Go-side vt10x model:
// that discarded all of the above on every switch and made the backend parse the
// same byte stream a second time.
function loginHost() { return $('#term'); }
function termWrap() { return $('#termWrap'); }

// activeEntry is the pane the user is looking at: the login screen while an
// attempt is authenticating (or while nothing is connected), otherwise the
// current session's own entry.
function activeEntry() {
  if (state.pendingNew || !state.currentSid) return state.loginEntry;
  return state.terms[state.currentSid] || state.loginEntry;
}
function activeTerm() { const e = activeEntry(); return e ? e.term : null; }
function focusActive() { const t = activeTerm(); if (t) { try { t.focus(); } catch (e) {} } }

// wireSelectionCopy keeps the PuTTY mouse model: finishing a selection copies it
// to the clipboard. Each pane reads from its own buffer, never from a sibling's.
function wireSelectionCopy(e) {
  e.term.onSelectionChange(() => {
    try {
      const sel = e.term.getSelection();
      if (sel) navigator.clipboard.writeText(sel).catch(() => {});
    } catch (err) {}
  });
}

// refitEntry measures one pane and pushes its size. A hidden pane measures zero,
// so a pane is always refitted at the moment it is shown.
function refitEntry(e, sid) {
  if (!e) return;
  try { e.fit.fit(); } catch (err) {}
  // The size is pushed even when xterm's own onResize did not fire: it only
  // fires on a cols change, so a stale fit could leave the remote wrapping at a
  // width the screen no longer shows - the clipped lines and blank gaps this
  // prevents.
  if (sid) App.ResizeSession(sid, e.term.cols, e.term.rows);
}

// ensureLoginTerminal builds the login screen once. This is the pane the
// PuTTY-style prompts ("login as:", password, OTP) print into before any
// session exists, and the one a reconnect reuses.
function ensureLoginTerminal() {
  if (state.loginEntry) return;
  const host = loginHost();
  if (!host) return;
  const e = makeEntry(host, termFontSize(), termTheme());
  state.loginEntry = e;
  // Typing here answers the waiting prompt; there is no PTY to forward to yet.
  e.term.onData((d) => { if (authMode.active) handleAuthKey(d); });
  wireSelectionCopy(e);
  wireSearch(e);
  addKeyboardScroll(host, () => (state.loginEntry ? state.loginEntry.term : null));
  // The native webview menu is suppressed so right-click keeps one meaning; on
  // the login screen there is simply no session to paste into.
  host.addEventListener('contextmenu', (ev) => {
    ev.preventDefault();
    if (authMode.active) { msg('answer the login prompt first'); return; }
    msg('connect first');
  });
  setTimeout(() => { refitEntry(e, ''); }, 60);
  window.addEventListener('resize', () => { if (state.view === 'terminal') refitTerminal(); });
}

// ensureSessionTerminal builds (or returns) the terminal that owns one session,
// subscribes it to that session's raw PTY stream and wires its input. Its output
// lands here whether or not the tab is on screen, which is what keeps a
// background session's scrollback and its running programs current.
function ensureSessionTerminal(sid) {
  if (!sid) return null;
  const existing = state.terms[sid];
  if (existing) return existing;
  const wrap = termWrap();
  if (!wrap) return null;
  const e = createSessionPane(wrap, termFontSize(), termTheme());
  state.terms[sid] = e;
  e.term.onData((d) => { feedLine(d); App.WriteInput(sid, d).catch(() => {}); });
  e.term.onResize((s) => { App.ResizeSession(sid, s.cols, s.rows); });
  wireSelectionCopy(e);
  wireSearch(e);
  addKeyboardScroll(e.host, () => { const x = state.terms[sid]; return x ? x.term : null; });
  e.host.addEventListener('contextmenu', async (ev) => {
    ev.preventDefault();
    // While a login prompt owns the keyboard, pasting into the PTY would bypass
    // it; refuse rather than misroute the clipboard.
    if (authMode.active) { msg('answer the login prompt first'); return; }
    try {
      const text = await navigator.clipboard.readText();
      if (text) App.WriteInput(sid, text).catch(() => {});
    } catch (err) {
      msg('right-click paste unavailable - use Ctrl+V');
    }
  });
  // OSC 7 ("file://host/path") is emitted by prompt integrations some distros
  // ship and reports the real cwd, so it wins over our own reading of the typed
  // line. We only listen - nothing is injected into the remote shell. The id is
  // captured per pane, so a background tab can never move the visible pane.
  try {
    e.term.parser.registerOscHandler(7, (data) => {
      const p = osc7Path(data);
      if (p && followOn()) moveTo(sid, p);
      return true;
    });
  } catch (err) { /* xterm build without parser access: cd tracking still works */ }
  // The live byte stream. EventsOff first: a reconnect can reuse an id, and a
  // stale listener would print the old session's tail into the new pane.
  EventsOff('pty:' + sid);
  e.unsub = EventsOn('pty:' + sid, (data) => { try { e.term.write(data); } catch (err) {} });
  return e;
}

// showPane reveals exactly one pane - a session's own, or the login screen for
// '' - and hides the rest. Nothing is reset and no snapshot is replayed; that is
// the whole point of giving each tab its own terminal.
function showPane(sid) {
  const want = sid && state.terms[sid] ? sid : '';
  if (state.loginEntry) state.loginEntry.host.style.display = want === '' ? '' : 'none';
  Object.keys(state.terms).forEach((id) => {
    state.terms[id].host.style.display = id === want ? '' : 'none';
  });
  // A search belongs to the pane it was started in; carrying the strip over to a
  // different terminal would leave it pointing at text the user cannot see.
  if (searchState.isOpen) closeSearchUI();
  refitEntry(want === '' ? state.loginEntry : state.terms[want], want);
}

// disposeSessionTerminal drops one session's terminal and its subscription. The
// backend has already torn the session down, so the pane and its byte stream are
// the only things left to release.
function disposeSessionTerminal(sid) {
  const e = state.terms[sid];
  if (!e) return;
  if (e.unsub) { try { e.unsub(); } catch (err) {} e.unsub = null; }
  EventsOff('pty:' + sid);
  delete state.terms[sid];
  disposeEntry(e);
}

// ---------- terminal search (Ctrl+F) ----------
// One strip in #termWrap serves whichever pane is on screen, so a search opened
// in one tab never follows the user into the next. The state machine itself lives
// in searchBar.js, which `node --test` covers without a browser.

function searchTarget() {
  const e = activeEntry();
  return e ? { term: e.term, search: e.search } : null;
}

function openSearchUI() {
  openSearchBar();
  const bar = $('#searchBar');
  if (bar) bar.classList.add('open');
  const inp = $('#searchInput');
  if (inp) { inp.value = searchState.term; inp.focus(); inp.select(); }
}

function closeSearchUI() {
  closeSearchBar();
  const bar = $('#searchBar');
  if (bar) bar.classList.remove('open');
  const t = searchTarget();
  if (t) { try { t.search.clearSearch(); } catch (e) {} }
  renderSearchCount();
  focusActive();
}

// runSearch asks the active pane's SearchAddon for the next or previous match.
// The match total is not read back here: addon-search reports it through
// onDidChangeResults (see wireSearch), which also fires for the incremental
// search driven by the input field.
function runSearch(direction) {
  const t = searchTarget();
  if (!t) return;
  const inp = $('#searchInput');
  const term = inp ? inp.value : '';
  updateSearchTerm(term);
  if (!term) { updateSearchCount(0); renderSearchCount(); return; }
  const opts = { caseSensitive: false, incremental: false };
  try {
    if (direction < 0) t.search.findPrevious(term, opts);
    else t.search.findNext(term, opts);
  } catch (e) { msg('search: ' + e); }
}

// wireSearch keeps the strip's counter honest for one pane. The callback checks
// that the event came from the pane on screen, so a search left behind in a
// background tab cannot rewrite the count the user is reading.
function wireSearch(e) {
  if (!e || !e.search || !e.search.onDidChangeResults) return;
  try {
    e.search.onDidChangeResults(({ resultCount }) => {
      if (activeEntry() !== e) return;
      updateSearchCount(resultCount);
      renderSearchCount();
    });
  } catch (err) { /* addon build without the results event: find still works */ }
}

function renderSearchCount() {
  const el = $('#searchCount');
  if (el) el.textContent = searchState.isOpen ? searchResultText(searchState.count) : '';
}

function initSearchBar() {
  document.addEventListener('keydown', (ev) => {
    // Ctrl+F anywhere in the terminal view opens the strip; Esc closes it from
    // any focus, including inside the input itself.
    if (ev.key === 'f' && (ev.ctrlKey || ev.metaKey) && !ev.shiftKey && !ev.altKey) {
      if (state.view !== 'terminal') return;
      ev.preventDefault(); ev.stopPropagation();
      openSearchUI();
      return;
    }
    if (ev.key === 'Escape' && searchState.isOpen) { ev.preventDefault(); closeSearchUI(); }
  }, true);
  const inp = $('#searchInput');
  if (inp) {
    // Typing searches as you go, forwards; clearing the field clears the hits.
    inp.addEventListener('input', () => { if (inp.value) runSearch(1); else { updateSearchCount(0); renderSearchCount(); } });
    inp.addEventListener('keydown', (ev) => {
      // Stop the keystrokes reaching the terminal: Enter and Esc in the strip are
      // navigation, not a command line.
      ev.stopPropagation();
      if (ev.key === 'Enter') { ev.preventDefault(); runSearch(ev.shiftKey ? -1 : 1); }
      else if (ev.key === 'Escape') { ev.preventDefault(); closeSearchUI(); }
    });
  }
  const nx = $('#searchNext'); if (nx) nx.addEventListener('click', () => runSearch(1));
  const pv = $('#searchPrev'); if (pv) pv.addEventListener('click', () => runSearch(-1));
  const cl = $('#searchClose'); if (cl) cl.addEventListener('click', closeSearchUI);
}

// ---------- follow the terminal's folder ----------
function resetLine() { lineBuf.text = ''; lineBuf.tab = false; }

function feedLine(d) {
  for (const ch of d) {
    const code = ch.charCodeAt(0);
    if (ch === '\r' || ch === '\n') { submitLine(); }
    else if (ch === '\x7f' || code === 8) { lineBuf.text = lineBuf.text.slice(0, -1); }
    else if (code === 3 || code === 21) { resetLine(); } // ^C and ^U abandon the line
    else if (ch === '\t') { lineBuf.tab = true; }
    else if (code >= 32) { lineBuf.text += ch; }
  }
}

// shellLineFromScreen reads back the line the shell actually accepted, from the
// terminal's own buffer. History recall and tab completion are written to the
// screen by the remote shell and never pass through our input stream, so the
// typed buffer alone cannot be trusted for those. Only the visible pane can be
// typed into, so the active terminal is the one that ran the command.
//
// A long line - a deep path completed with Tab is the usual case - is echoed
// across several screen rows, and only the first of them carries the prompt, so
// the rows it spans are stitched together before the prompt is cut. Reading the
// cursor row alone would hand back the tail of the path with the "cd" missing.
function shellLineFromScreen() {
  const term = activeTerm();
  if (!term) return '';
  try {
    const b = term.buffer.active;
    const y = b.baseY + b.cursorY;
    // Only the row under the cursor is right-trimmed: past the caret the buffer
    // is blank, while on the rows above it a space the line broke on is part of
    // the command and must not be trimmed away.
    const readRow = (r) => {
      const line = b.getLine(r);
      if (!line) return null;
      return { text: line.translateToString(r === y), isWrapped: line.isWrapped };
    };
    return stripPrompt(logicalLine(readRow, y));
  } catch (e) { return ''; }
}

async function submitLine() {
  const sid = state.currentSid;
  const typed = lineBuf.text;
  const unreliable = lineBuf.tab;
  resetLine();
  if (!followOn() || !sid) return;
  // An empty buffer means the line came from history; the tab flag means it was
  // completed. Both cases have to be read back off the screen.
  const line = (unreliable || !typed.trim()) ? shellLineFromScreen() : typed;
  if (!line.trim()) return;
  let next = '';
  try { next = await App.FollowCwd(sid, line); } catch (e) { return; }
  // "cd -" is the one case only our own history can answer.
  if (!next && /^\s*(cd|pushd)\s+-\s*$/.test(line) && state.prevCwds[sid]) next = state.prevCwds[sid];
  await moveTo(sid, next);
}

// moveTo re-points the browser pane, remembering where it was for "cd -". The
// session is passed in because the IPC round trip may outlive the user's click
// on another tab; the pane only ever follows the session that is on screen.
async function moveTo(sid, next) {
  if (!sid || sid !== state.currentSid) return;
  const cur = state.cwds[sid] || '/';
  if (!next || next === cur) return;
  state.prevCwds[sid] = cur;
  await loadFiles(next);
  msg('following: ' + next);
}

// ---------- in-terminal auth prompt (PuTTY-style) ----------
EventsOn('auth:prompt', (p) => {
  switchView('terminal');
  ensureLoginTerminal();
  resetLine();
  authMode.active = true; authMode.echo = !!p.echo; authMode.buffer = '';
  // The question carries no leading newline: the Enter that finished the
  // previous answer already moved down a line (see handleAuthKey), and a fresh
  // terminal starts at the top. Adding one here was the blank gap PuTTY does
  // not show between "login as:" and the password prompt.
  // Prompts always belong to the login pane, never to a session's own terminal.
  showPane('');
  const term = state.loginEntry ? state.loginEntry.term : null;
  if (!term) return;
  term.write(p.question + ' ');
  term.focus();
});
// Authentication status lines (a rejected password, giving up) belong in the
// terminal where the user is typing, not only in the bottom status line. The
// line owns its trailing newline so the prompt that follows starts fresh; it
// also claims a fresh row when a prompt is mid-line, so a FATAL ERROR can never
// append itself behind a waiting "login as: ".
EventsOn('auth:notice', (t) => {
  const term = state.loginEntry ? state.loginEntry.term : null;
  if (!term) return;
  try {
    if (authMode.active) { term.write('\r\n'); authMode.active = false; authMode.buffer = ''; }
    term.write(t + '\r\n');
  } catch (e) {}
});
// A newer Connect attempt superseded a waiting prompt: the backend answered it
// with a cancellation, so drop the input mode here too.
EventsOn('auth:cancel', () => {
  const term = state.loginEntry ? state.loginEntry.term : null;
  if (term && authMode.active) { try { term.write('\r\n'); } catch (e) {} }
  authMode.active = false; authMode.echo = false; authMode.buffer = '';
});

// The remote shell exited ("exit"/logout) or the link dropped. The backend has
// already torn the session down, so drop the tab and move on.
EventsOn('session:exit', (sid) => {
  const gone = state.sessions.find((s) => s.id === sid);
  msg(gone ? 'session ended: ' + gone.name : 'session ended');
  afterSessionGone(sid).catch(() => {});
});

// A dead link, unlike a logout: the backend says the transport failed, so the
// user gets a chance to get the session back. With the reconnect preference on
// (the default) it happens by itself; with it off nobody is typing into a
// frozen terminal, so asking is safer than dialling behind their back.
EventsOn('session:dropped', async (info) => {
  const gone = state.sessions.find((s) => s.id === info.sid);
  const label = gone ? (gone.name || gone.host) : (info.host + ':' + info.port);
  msg('connection lost: ' + label);
  await afterSessionGone(info.sid);
  if (authMode.active) return; // a login prompt owns the terminal; do not hijack it
  if (!autoReconnect() && !confirm('Reconnect to ' + label + '?')) return;
  runReconnect(info);
});

function autoReconnect() {
  try { return localStorage.getItem('gravel.autoReconnect') !== 'off'; } catch (e) { return true; }
}

// prepareLogin puts the login pane on screen, cleared and ready for a fresh
// prompt. reset() now only ever touches the login terminal: a session's own
// scrollback, colours and running programs are no longer thrown away to make
// room for a prompt, because the prompt has somewhere else to live.
function prepareLogin(farewell) {
  ensureLoginTerminal();
  const e = state.loginEntry;
  if (e) {
    try { e.term.reset(); } catch (err) {}
    if (farewell) { try { e.term.write('\x1b[2m' + farewell + '\x1b[0m\r\n'); } catch (err) {} }
  }
  showPane('');
}

// runReconnect dials the dropped target again through the same interactive
// Connect/ConnectKey path a fresh session uses, so the credential rules never
// change: the terminal asks for the login again, and nothing is remembered.
async function runReconnect(info) {
  switchView('terminal');
  state.pendingNew = true;
  prepareLogin();
  renderTabs();
  const port = info.port || DEFAULT_PORT;
  const dial = info.auth === 'key'
    ? App.ConnectKey(info.host, port, info.keyPath || '')
    : App.Connect(info.host, port);
  let res;
  try { res = await dial; }
  catch (e) { state.pendingNew = false; msg('reconnect error: ' + e); renderTabs(); showPane(state.currentSid); return; }
  state.pendingNew = false;
  // A failed attempt leaves its reason on the login pane; a successful one is
  // picked up by handleConnectResult, which builds the new session's own tab.
  if (!res || !res.sid) showPane(state.currentSid);
  await handleConnectResult(res, () => runReconnect(info));
}

// afterSessionGone handles a tab disappearing, by logout or by the user
// closing it. With nothing left to show it clears the dead screen and returns
// to where a new connection starts - PuTTY closes its window on logout, and a
// blank terminal with a blinking cursor just reads as hung.
async function afterSessionGone(sid) {
  const wasCurrent = !state.currentSid || state.currentSid === sid;
  resetLine();
  // refreshSessions tears down the vanished session's terminal together with
  // its byte-stream subscription, then shows whichever tab survived.
  await refreshSessions();
  if (!wasCurrent) return;
  // A forward still being typed needs a session to ride: with the last one gone
  // the row is only a form with nowhere to send it, so close it.
  if (!state.currentSid && state.creatingTunnel) endTunnelEdit();
  if (state.currentSid) { await loadFiles(cwd()); return; }
  prepareLogin('[disconnected]');
  switchView('session');
}

function handleAuthKey(d) {
  const term = state.loginEntry ? state.loginEntry.term : null;
  if (!term) return;
  for (const ch of d) {
    const code = ch.charCodeAt(0);
    if (ch === '\r' || ch === '\n') { term.write('\r\n'); const a = authMode.buffer; authMode.active = false; authMode.buffer = ''; App.AuthAnswer(a); return; }
    else if (ch === '\x7f' || code === 8) { if (authMode.buffer.length > 0) { authMode.buffer = authMode.buffer.slice(0, -1); if (authMode.echo) term.write('\b \b'); } }
    else if (code === 3) { authMode.active = false; authMode.buffer = ''; term.write('^C\r\n'); App.AuthAnswer(''); return; }
    else if (code >= 32) { authMode.buffer += ch; if (authMode.echo) term.write(ch); }
  }
}

// ---------- sessions / tabs ----------
async function refreshSessions() {
  try { state.sessions = await App.ListSessions(); }
  catch (e) { msg('sessions: ' + e); return; }
  // Drop the pane state of sessions that no longer exist so the maps cannot
  // grow without bound across reconnects.
  const live = new Set(state.sessions.map((s) => s.id));
  Object.keys(state.cwds).forEach((id) => {
    if (!live.has(id)) { delete state.cwds[id]; delete state.prevCwds[id]; }
  });
  // Release the terminal and the byte-stream subscription of every session that
  // has gone, so a long-lived app does not accumulate a disposed xterm and a dead
  // listener per reconnect.
  Object.keys(state.terms).forEach((id) => { if (!live.has(id)) disposeSessionTerminal(id); });
  // Adopt the backend's browse path for every session the pane has not seen
  // yet. A fresh session starts at the remote user's home directory - which is
  // where the shell itself landed - rather than at "/".
  let fresh = false;
  state.sessions.forEach((s) => {
    if (!(s.id in state.cwds)) { state.cwds[s.id] = s.filesPath || '/'; fresh = true; }
  });
  if (!state.currentSid || !state.sessions.find((s) => s.id === state.currentSid)) {
    state.currentSid = state.sessions.length ? state.sessions[state.sessions.length - 1].id : '';
  }
  renderTabs();
  renderSessionList();
  // Every live session gets its own terminal and its own subscription, whether
  // or not it is on screen: a background tab has to keep collecting output or it
  // would lose exactly the scrollback and program state the per-tab design
  // exists to protect. A session still authenticating has no id here yet, so its
  // prompts land on the login pane instead of being raced by the 5s poll.
  state.sessions.forEach((s) => ensureSessionTerminal(s.id));
  showPane(state.pendingNew ? '' : state.currentSid);
  // Nothing has been rendered for a session that just appeared, so paint it now;
  // otherwise the pane keeps showing the pre-connect listing.
  if (fresh && state.currentSid && state.view === 'terminal') loadFiles(cwd());
}

function renderTabs() {
  const tb = $('#tabs'); if (!tb) return; tb.textContent = '';
  // While a new session is still authenticating, its placeholder tab owns the
  // active highlight so the old tab does not also look selected.
  const activeId = state.pendingNew ? '' : state.currentSid;
  state.sessions.forEach((s) => {
    const t = document.createElement('div'); t.className = 'tab' + (s.id === activeId ? ' active' : '');
    const dot = document.createElement('span'); dot.className = 'dot ' + s.state;
    const lbl = document.createElement('span'); lbl.textContent = s.name || s.id;
    const x = document.createElement('button'); x.className = 'close'; x.textContent = '\u00d7';
    x.addEventListener('click', (ev) => { ev.stopPropagation(); confirmCloseSession(s.id); });
    t.appendChild(dot); t.appendChild(lbl); t.appendChild(x);
    t.addEventListener('click', () => selectSession(s.id));
    t.addEventListener('contextmenu', (ev) => { ev.preventDefault(); showTabMenu(ev.clientX, ev.clientY, s.id); });
    tb.appendChild(t);
  });
  // Placeholder tab shown the instant "Duplicate" is pressed, before the
  // backend has finished dialling and authenticating.
  if (state.pendingNew) {
    const p = document.createElement('div'); p.className = 'tab active pending';
    const dot = document.createElement('span'); dot.className = 'dot connecting';
    const lbl = document.createElement('span'); lbl.textContent = 'New session\u2026';
    p.appendChild(dot); p.appendChild(lbl);
    tb.appendChild(p);
  }
  // No trailing "+": a new connection is started from the Sessions view, and
  // a second terminal to the same server stays under the tab's right-click
  // "Duplicate terminal".
}

// newTerminalLike opens a second session to the server an existing tab points
// at, so the duplicate flow reuses the connection target rather than the form.
async function newTerminalLike(sid) {
  const target = sid || state.currentSid;
  if (!target) { switchView('session'); return; }
  switchView('terminal');
  // The placeholder tab appears at once and the login prompt takes the login
  // pane, so the session being duplicated keeps its own terminal and its own
  // output instead of being overwritten by the new "login as:".
  state.pendingNew = true;
  prepareLogin();
  renderTabs();
  let res;
  try { res = await App.NewSessionLike(target); }
  catch (e) { msg('new terminal: ' + e); state.pendingNew = false; renderTabs(); showPane(state.currentSid); return; }
  state.pendingNew = false;
  // The same hand-back order as doConnect: give the view back to the session
  // that survived first, then report the reason through the shared handler, so a
  // failed duplicate is neither silent nor missing its host-key dialog.
  if (!res || !res.sid) showPane(state.currentSid);
  await handleConnectResult(res, () => App.NewSessionLike(target));
}

// showTabMenu is a lightweight custom context menu (the webview has no native
// one), dismissed by the next click anywhere.
function showTabMenu(x, y, sid) {
  hideTabMenu();
  const menu = document.createElement('div'); menu.id = 'tabMenu'; menu.className = 'ctxMenu';
  const item = (label, fn) => {
    const d = document.createElement('div'); d.className = 'ctxItem'; d.textContent = label;
    d.addEventListener('click', () => { hideTabMenu(); fn(); });
    return d;
  };
  menu.appendChild(item('Duplicate terminal', () => newTerminalLike(sid)));
  menu.appendChild(item('Close terminal', () => confirmCloseSession(sid)));
  menu.style.left = '0px'; menu.style.top = '0px';
  document.body.appendChild(menu);
  // Then slide it back inside the window. A right-click near the right or bottom
  // edge used to hang part of the menu - and its buttons - off screen, with no
  // native menu to shrink it for us.
  const box = menu.getBoundingClientRect();
  const left = Math.max(4, Math.min(x, window.innerWidth - box.width - 4));
  const top = Math.max(4, Math.min(y, window.innerHeight - box.height - 4));
  menu.style.left = left + 'px'; menu.style.top = top + 'px';
  // Defer so the opening right-click does not immediately trigger the close.
  setTimeout(() => document.addEventListener('click', hideTabMenu, { once: true }), 0);
}

function hideTabMenu() { const m = document.getElementById('tabMenu'); if (m) m.remove(); }

function renderSessionList() {
  const ul = $('#sessionList'); if (!ul) return; ul.textContent = '';
  if (!state.sessions.length) { const li = document.createElement('li'); li.textContent = 'No active sessions'; ul.appendChild(li); }
  state.sessions.forEach((s) => {
    const li = document.createElement('li'); if (s.id === state.currentSid) li.classList.add('selected');
    const dot = document.createElement('span'); dot.className = 'dot ' + s.state;
    const nm = document.createElement('span'); nm.className = 'nm'; nm.textContent = s.name;
    const sub = document.createElement('span'); sub.className = 'sub'; sub.textContent = s.host;
    li.appendChild(dot); li.appendChild(nm); li.appendChild(sub);
    li.addEventListener('click', () => { selectSession(s.id); switchView('terminal'); });
    ul.appendChild(li);
  });
}

// selectSession swaps the visible terminal. There is no snapshot to fetch and
// nothing to reset: the tab's own xterm already holds everything it printed
// while it was in the background, including the screen of a running vim, htop
// or tmux, so showing it is the whole repaint.
function selectSession(sid) {
  if (!sid || sid === state.currentSid) return;
  state.currentSid = sid;
  resetLine();
  renderTabs(); renderSessionList();
  ensureSessionTerminal(sid);
  showPane(sid);
  focusActive();
  if (state.view === 'terminal') loadFiles(cwd());
}

async function closeSession(sid) {
  await App.CloseSession(sid);
  await afterSessionGone(sid);
}

// confirmCloseSession guards the x on a tab and the context-menu close: a live
// shell may hold running work, so ask before tearing it down.
function confirmCloseSession(sid) {
  const s = state.sessions.find((x) => x.id === sid);
  const name = s ? (s.name || s.id) : sid;
  if (!confirm('close ' + name + '?')) return;
  closeSession(sid);
}

// ---------- connect ----------
function readForm() {
  return {
    name: $('#svName').value.trim(),
    host: $('#svHost').value.trim(),
    // null means the field is not a usable port: blank still means 22, but
    // "abc" or "70000" is refused at connect/save instead of reaching the
    // backend as NaN (which arrives over IPC as 0).
    port: parsePort($('#svPort').value, DEFAULT_PORT),
    auth: $('#svAuth').value,
    keyPath: $('#svKey').value.trim(),
  };
}

// connectWith starts a session; the backend always asks for the login name
// (and password or key passphrase) in the terminal.
function connectWith(f) {
  return f.auth === 'key' ? App.ConnectKey(f.host, f.port, f.keyPath) : App.Connect(f.host, f.port);
}

async function doConnect() {
  const f = readForm();
  if (!f.host) { msg('host required'); return; }
  if (f.port === null) { msg('port must be 1-65535'); return; }
  // A server that already has a live terminal is opened by switching to it,
  // not by dialling a second session to the same place - that is what the
  // tab's right-click "Duplicate terminal" is for.
  const addr = f.host + ':' + f.port;
  const open = state.sessions.find((s) => s.host === addr);
  if (open) { selectSession(open.id); switchView('terminal'); msg('already connected: ' + (open.name || addr)); return; }
  switchView('terminal');
  // Fresh canvas for every new connection, the way PuTTY opens a new window -
  // even while another session is live. The prompts land on their own login pane
  // now, so a running session keeps its terminal and its output untouched while
  // the new one authenticates, and switching back to its tab shows it as it was.
  state.pendingNew = true;
  prepareLogin();
  renderTabs();
  let res;
  try { res = await connectWith(f); }
  catch (e) { state.pendingNew = false; msg('connect error: ' + e); renderTabs(); showPane(state.currentSid); return; }
  state.pendingNew = false;
  // A failed or cancelled attempt leaves its login text on the login pane. Hand
  // the view back to the session that is still running, then write the reason
  // into it - the order keeps the message from being hidden behind another tab.
  if (!res || !res.sid) showPane(state.currentSid);
  await handleConnectResult(res, () => connectWith(f));
}

async function handleConnectResult(res, retry) {
  if (!res) return;
  if (res.kind === 'unknown_host') { showTOFU(res, retry); return; }
  if (res.kind === 'host_key_mismatch') { showTOFU(res, retry); return; }
  if (res.error) {
    msg(res.error);
    // "cancelled" is this attempt being dropped for a newer one; it is not
    // something to splash across the session the user is working in.
    if (res.kind !== 'cancelled') writeNotice(res.error);
    return;
  }
  if (res.sid) { state.currentSid = res.sid; await refreshSessions(); }
}

// showTOFU asks the user to trust a host key: either one never seen before or
// one that replaced a trusted key. Accepting records exactly the fingerprint on
// screen - a change overwrites the stored key - so retry resumes the flow that
// was stopped, including a duplicate terminal, which has nothing to do with the
// Sessions form.
function showTOFU(info, retry) {
  state.retryConnect = typeof retry === 'function' ? retry : null;
  const changed = info.kind === 'host_key_mismatch';
  $('#tofuTitle').textContent = changed ? 'Host key changed' : 'First-time SSH host';
  $('#tofuWarn').textContent = changed
    ? 'WARNING: this host presented a different key than the one on record. If you did not reimage the server or change its host keys, a man-in-the-middle may be intercepting the connection - verify the new fingerprint out-of-band before accepting.'
    : 'Only trust this host if you can verify the fingerprint out-of-band. A man-in-the-middle on the first connection can present any key.';
  $('#tofu_addr').textContent = info.addr;
  $('#tofu_fp').textContent = info.fingerprint;
  $('#tofu_kt').textContent = 'key type: ' + (info.keyType || '?');
  $('#tofu').showModal();
}

async function acceptTOFU() {
  const info = { addr: $('#tofu_addr').textContent, fingerprint: $('#tofu_fp').textContent };
  try { await App.Trust(info.addr, info.fingerprint); } catch (e) { msg('trust failed: ' + e); return; }
  $('#tofu').close();
  const retry = state.retryConnect;
  state.retryConnect = null;
  if (!retry) { msg('host key trusted'); return; }
  switchView('terminal');
  // Accepting the key starts a second full login, so it takes the same path as
  // doConnect: placeholder tab and a cleared login pane.
  state.pendingNew = true;
  prepareLogin();
  renderTabs();
  let res;
  try { res = await retry(); }
  catch (e) { state.pendingNew = false; msg('retry error: ' + e); renderTabs(); showPane(state.currentSid); return; }
  state.pendingNew = false;
  if (!res || !res.sid) showPane(state.currentSid);
  await handleConnectResult(res, retry);
}

// ---------- saved servers ----------
// dragPID holds the profile id currently under a drag-and-drop reorder; the
// new sequence is persisted through ReorderProfiles so it survives restarts.
let dragPID = '';

async function refreshProfiles() {
  try { state.profiles = await App.ListProfiles(); }
  catch (e) { msg('profiles: ' + e); return; }
  const ul = $('#serverList'); if (!ul) return; ul.textContent = '';
  if (!state.profiles.length) { const li = document.createElement('li'); li.textContent = 'No saved servers'; ul.appendChild(li); return; }
  state.profiles.forEach((p) => {
    const li = document.createElement('li');
    if (state.selectedProfile && state.selectedProfile.id === p.id) li.classList.add('selected');
    const nm = document.createElement('span'); nm.className = 'nm'; nm.textContent = p.name;
    const sub = document.createElement('span'); sub.className = 'sub'; sub.textContent = p.host + ':' + p.port;
    li.appendChild(nm); li.appendChild(sub);
    li.draggable = true;
    li.addEventListener('dragstart', (ev) => {
      dragPID = p.id; li.classList.add('dragging');
      ev.dataTransfer.effectAllowed = 'move';
      try { ev.dataTransfer.setData('text/plain', p.id); } catch (e) {}
    });
    li.addEventListener('dragend', () => {
      // Only clean up here: a completed drop already triggered its own
      // refresh, and a second ListProfiles could land after the reorder was
      // persisted and briefly show the pre-drag order again.
      dragPID = '';
      li.classList.remove('dragging');
    });
    li.addEventListener('dragover', (ev) => {
      if (!dragPID || dragPID === p.id) return;
      ev.preventDefault(); ev.dataTransfer.dropEffect = 'move'; li.classList.add('dropon');
    });
    li.addEventListener('dragleave', () => li.classList.remove('dropon'));
    li.addEventListener('drop', (ev) => {
      ev.preventDefault(); li.classList.remove('dropon');
      if (!dragPID || dragPID === p.id) return;
      // Insert before or after the target depending on which half was hit.
      const ids = state.profiles.map((x) => x.id).filter((id) => id !== dragPID);
      const r = li.getBoundingClientRect();
      let to = ids.indexOf(p.id);
      if (to < 0) to = ids.length;
      if (ev.clientY > r.top + r.height / 2) to++;
      ids.splice(to, 0, dragPID);
      dragPID = '';
      App.ReorderProfiles(ids).then(refreshProfiles).catch((e) => { msg('reorder: ' + e); refreshProfiles(); });
    });
    li.addEventListener('click', () => { state.selectedProfile = p; refreshProfiles(); });
    li.addEventListener('dblclick', () => { state.selectedProfile = p; fillForm(p); doConnect(); });
    ul.appendChild(li);
  });
}

function fillForm(p) {
  $('#svName').value = p.name || '';
  $('#svHost').value = p.host || '';
  $('#svPort').value = p.port || 22;
  $('#svAuth').value = p.auth || 'password';
  $('#svKey').value = p.keyPath || '';
  $('#svKeyWrap').hidden = p.auth !== 'key';
}

function saveServer() {
  const f = readForm();
  if (!f.host) { msg('host required'); return; }
  if (f.port === null) { msg('port must be 1-65535'); return; }
  App.SaveProfile(f.name, f.host, f.port, f.auth, f.keyPath).then(() => { msg('saved'); refreshProfiles(); }).catch((e) => msg('save: ' + e));
}

function deleteServer() {
  if (!state.selectedProfile) { msg('select a saved server first'); return; }
  // No confirm dialog: Delete is an explicit click on a selected row, and the
  // browser-style confirm() popup breaks the native feel of the app.
  const name = state.selectedProfile.name;
  App.DeleteProfile(state.selectedProfile.id).then(() => { state.selectedProfile = null; refreshProfiles(); msg('deleted ' + name); }).catch((e) => msg('delete: ' + e));
}

// importHosts opens the paste-a-list dialog; the backend parses each line and
// PutNamed keeps re-imports from duplicating existing names.
function openImportDialog() {
  const ta = $('#importText'); if (ta) ta.value = '';
  $('#importDlg').showModal();
}

// runImport commits the pasted list. The dialog closes on the click whatever the
// outcome - it is a commit button, not a step in a wizard - and what happened
// (imported, rejected, or nothing typed at all) is reported in the status line.
function runImport() {
  const text = $('#importText').value;
  $('#importDlg').close();
  if (!text.trim()) { msg('nothing to import'); return; }
  App.ImportHosts(text).then((n) => {
    msg(n + ' host(s) imported');
    refreshProfiles();
  }).catch((e) => msg('import: ' + e));
}

// pickImportFile loads a hosts file into the preview box, replacing whatever
// was pasted there; nothing is saved until Import is pressed.
function pickImportFile() {
  App.PickHostFile().then((text) => {
    if (!text) return;
    $('#importText').value = text;
  }).catch((e) => msg('import file: ' + e));
}

// ---------- files (browser pane docked left of the terminal) ----------
// listSeq numbers every listing request. Two of them can overlap for the same
// session (a row click plus a follow-the-terminal move), and the one that
// resolves last would otherwise paint stale rows over fresh ones and leave
// state.cwds pointing at the directory that is no longer on screen.
let listSeq = 0;

async function loadFiles(p) {
  // The session is captured up front: the IPC round trip can outlive a tab
  // switch, and painting session A's directory under session B would both
  // mislabel the pane and aim every row button at the wrong host.
  const sid = state.currentSid;
  const seq = ++listSeq;
  if (!sid) { const tb = $('#tbody'); if (tb) tb.textContent = ''; $('#pathbar').textContent = '/ (no session)'; return; }
  try {
    const entries = await App.ListFiles(sid, p);
    if (sid !== state.currentSid || seq !== listSeq) return;
    state.cwds[sid] = p; $('#pathbar').textContent = p;
    const tb = $('#tbody');
    const frag = document.createDocumentFragment();
    (entries || []).forEach((en) => {
      // Dotfiles stay out of the list until "Show hidden" is ticked.
      if (!showHiddenOn() && en.name.charAt(0) === '.' && en.name !== '.' && en.name !== '..') return;
      const tr = document.createElement('tr');
      const nm = document.createElement('td'); nm.className = 'name'; nm.textContent = (en.isDir ? '[dir] ' : '') + en.name;
      nm.title = en.path; // the narrow pane ellipsises long names
      nm.addEventListener('click', () => { if (en.isDir) loadFiles(en.path); });
      const sz = document.createElement('td'); sz.className = 'sz'; sz.textContent = en.isDir ? '-' : fmtSize(en.size);
      const cell = (cls, text) => { const td = document.createElement('td'); td.className = cls; td.textContent = text; return td; };
      const ac = document.createElement('td'); ac.className = 'ops';
      // "edit" leads the row, so the actions read edit, download, perms, del,
      // rename. A directory has no content to open, but its slot is still laid
      // out and merely hidden: dropping it would slide the four shared buttons
      // left on every folder row and break the vertical alignment down the list.
      const ed = document.createElement('button'); ed.textContent = 'edit'; ed.title = 'open ' + en.name + ' in the editor';
      if (en.isDir) ed.classList.add('ghost');
      else ed.addEventListener('click', () => openEditor(sid, en.path, en.name));
      ac.appendChild(ed);
      const dl = document.createElement('button'); dl.textContent = 'download';
      dl.title = en.isDir ? 'download ' + en.name + ' and its contents to a local folder' : 'download ' + en.name + ' to a local file';
      dl.addEventListener('click', () => {
        // A folder is mirrored recursively; a file goes through the save dialog.
        const job = en.isDir ? App.DownloadDir(sid, en.path, conflictPolicy()) : App.Download(sid, en.path, conflictPolicy());
        job.then(renderQueue).catch((e) => msg('download: ' + e));
      });
      ac.appendChild(dl);
      // "perms" edits the mode (chmod) and owner/group (chown); it applies to
      // directories as well as files.
      const pm = document.createElement('button'); pm.textContent = 'perms'; pm.title = 'change permissions / owner of ' + en.name;
      pm.addEventListener('click', () => openPerm(sid, en));
      ac.appendChild(pm);
      const del = document.createElement('button'); del.className = 'danger'; del.textContent = 'del'; del.title = 'delete ' + en.name;
      del.addEventListener('click', () => { if (confirm('delete ' + en.name + '?')) App.Delete(sid, en.path).then(() => loadFiles(cwd())).catch((e) => msg('delete: ' + e)); });
      const ren = document.createElement('button'); ren.textContent = 'rename';
      ren.title = 'rename ' + en.name;
      ren.addEventListener('click', () => {
        const n = prompt('new name', en.name);
        if (!n || !n.trim()) return;
        App.Rename(sid, en.path, n.trim()).then(() => loadFiles(cwd())).catch((e) => msg('rename: ' + e));
      });
      ac.appendChild(del); ac.appendChild(ren);
      tr.appendChild(nm); tr.appendChild(sz);
      tr.appendChild(cell('dt', en.mtime || '-'));
      tr.appendChild(cell('ow', en.owner || '-'));
      tr.appendChild(cell('gr', en.group || '-'));
      tr.appendChild(cell('pm', en.mode || '-'));
      tr.appendChild(ac);
      frag.appendChild(tr);
    });
    // One swap for the whole directory: /usr and /etc carry hundreds of rows,
    // and appending them to the live table costs a layout pass per row.
    tb.textContent = ''; tb.appendChild(frag);
  } catch (e) { msg('list: ' + e); }
}
function goUp() { loadFiles(parentPath(cwd())); }
function mkdir() {
  const sid = state.currentSid;
  if (!sid) { msg('connect first'); return; }
  const n = prompt('directory name');
  if (!n || !n.trim()) return;
  App.Mkdir(sid, cwd(), n.trim()).then(() => loadFiles(cwd())).catch((e) => msg('mkdir: ' + e));
}
function newFile() {
  if (!state.currentSid) { msg('connect first'); return; }
  const n = prompt('new file name');
  if (!n || !n.trim()) return;
  App.NewFile(state.currentSid, cwd(), n.trim()).then(() => loadFiles(cwd())).catch((e) => msg('new file: ' + e));
}
function upload() { if (!state.currentSid) { msg('connect first'); return; } App.Upload(state.currentSid, cwd(), conflictPolicy()).then(renderQueue).catch((e) => msg('upload: ' + e)); }
function uploadDir() { if (!state.currentSid) { msg('connect first'); return; } App.UploadDir(state.currentSid, cwd(), conflictPolicy()).then(renderQueue).catch((e) => msg('upload folder: ' + e)); }

// conflictPolicy is the transfer-conflict rule the backend applies when a
// destination already exists: overwrite (default), rename ("file (1).ext") or
// skip. Stored as a preference so it survives restarts and resets with the rest.
function conflictPolicy() {
  const v = localStorage.getItem(CONFLICT_KEY);
  return v === 'rename' || v === 'skip' ? v : 'overwrite';
}

// ---------- in-app file editor ----------
// One editor instance is open at a time; `orig` holds the text as loaded so the
// modified dot and the discard-on-close guard compare against the file's real
// state, not against whatever was there when the dialog first appeared.
const editor = { sid: '', path: '', orig: '', binary: false };

function openEditor(sid, path, name) {
  editor.sid = sid; editor.path = path; editor.orig = ''; editor.binary = false;
  $('#edName').textContent = name;
  $('#edPath').textContent = path;
  $('#edPath').title = path;
  $('#edText').value = '';
  $('#edText').readOnly = false;
  $('#edReadonly').hidden = true;
  $('#edSave').disabled = true;
  $('#edDot').hidden = true;
  $('#edStatus').textContent = 'loading\u2026';
  $('#editor').showModal();
  App.ReadRemoteFile(sid, path).then((fc) => {
    // A second open while this one was in flight owns the dialog now; do not
    // paint the older file's contents over the newer one.
    if (editor.path !== path || editor.sid !== sid) return;
    editor.orig = fc.content; editor.binary = !!fc.binary;
    $('#edText').value = fc.content;
    $('#edText').readOnly = editor.binary;
    $('#edReadonly').hidden = !editor.binary;
    $('#edSave').disabled = editor.binary;
    $('#edStatus').textContent = editor.binary ? '' : fmtSize(fc.size);
  }).catch((e) => {
    if (editor.path !== path) return;
    $('#edStatus').textContent = '';
    $('#edText').placeholder = 'cannot open: ' + e;
    msg('edit: ' + e);
  });
}

function editorDirty() { return !editor.binary && $('#edText').value !== editor.orig; }

function saveEditor() {
  if (editor.binary || !$('#editor').open) return;
  const content = $('#edText').value;
  $('#edStatus').textContent = 'saving\u2026';
  App.WriteRemoteFile(editor.sid, editor.path, content).then(() => {
    editor.orig = content;
    $('#edDot').hidden = !editorDirty();
    $('#edStatus').textContent = 'saved';
    msg('saved');
  }).catch((e) => { $('#edStatus').textContent = ''; msg('save: ' + e); });
}

function closeEditor() {
  if (editorDirty() && !confirm('discard unsaved changes?')) return;
  $('#editor').close();
}

// ---------- permissions (chmod / chown) ----------
// The grid is nine checkboxes (owner/group/world x r/w/x) kept in sync with a
// three-digit octal field; owner/group are free text resolved server-side. The
// mode maths itself lives in perm.js, where the tests can reach it.
const perm = { sid: '', path: '', origOctal: '', origOwner: '', origGroup: '' };

function openPerm(sid, en) {
  perm.sid = sid; perm.path = en.path;
  perm.origOctal = (en.perm || '').padStart(3, '0');
  perm.origOwner = en.owner || ''; perm.origGroup = en.group || '';
  $('#permPath').textContent = en.path;
  $('#permPath').title = en.path;
  const mode = parseOctal(perm.origOctal);
  buildPermGrid(mode === null ? 0 : mode);
  $('#permOctal').value = perm.origOctal;
  $('#permOwner').value = '';
  $('#permOwner').placeholder = perm.origOwner || 'user';
  $('#permGroup').value = '';
  $('#permGroup').placeholder = perm.origGroup || 'group';
  $('#permStatus').textContent = '';
  $('#perm').showModal();
}

function buildPermGrid(mode) {
  const g = $('#permGrid'); g.textContent = '';
  PERM_ROWS.forEach(([label, shift]) => {
    const tr = document.createElement('tr');
    const th = document.createElement('td'); th.className = 'permWho'; th.textContent = label; tr.appendChild(th);
    PERM_BITS.forEach(([, bit]) => {
      const td = document.createElement('td');
      const cb = document.createElement('input'); cb.type = 'checkbox';
      cb.dataset.shift = shift; cb.dataset.bit = bit;
      cb.checked = bitOn(mode, bit, shift);
      cb.addEventListener('change', () => { $('#permOctal').value = octalText(modeFromGrid()); $('#permStatus').textContent = ''; });
      td.appendChild(cb); tr.appendChild(td);
    });
    g.appendChild(tr);
  });
}

function modeFromGrid() {
  return modeFromFlags(gridChecks().map((cb) => ({ bit: cb.dataset.bit, shift: cb.dataset.shift, on: cb.checked })));
}

function gridChecks() {
  return Array.from($('#permGrid').querySelectorAll('input[type=checkbox]'));
}

// Typing an octal value drives the checkboxes, but only once it is a valid octal
// string - a half-typed "8" or an empty box leaves the grid alone.
function onPermOctalInput() {
  const m = parseOctal($('#permOctal').value);
  if (m === null) return;
  gridChecks().forEach((cb) => {
    cb.checked = bitOn(m, parseInt(cb.dataset.bit, 10), parseInt(cb.dataset.shift, 10));
  });
  $('#permStatus').textContent = '';
}

function savePerm() {
  const octStr = octalText(modeFromGrid());
  const owner = $('#permOwner').value.trim();
  const group = $('#permGroup').value.trim();
  const jobs = [];
  if (octStr !== perm.origOctal) jobs.push(App.SetPermissions(perm.sid, perm.path, octStr));
  const ownerChanged = owner && owner !== perm.origOwner;
  const groupChanged = group && group !== perm.origGroup;
  if (ownerChanged || groupChanged) jobs.push(App.SetOwner(perm.sid, perm.path, ownerChanged ? owner : '', groupChanged ? group : ''));
  if (!jobs.length) { $('#permStatus').textContent = 'no changes'; return; }
  $('#permStatus').textContent = 'saving\u2026';
  Promise.all(jobs).then(() => {
    perm.origOctal = octStr;
    if (ownerChanged) perm.origOwner = owner;
    if (groupChanged) perm.origGroup = group;
    $('#permStatus').textContent = 'saved';
    msg('permissions updated');
    loadFiles(cwd());
  }).catch((e) => { $('#permStatus').textContent = ''; msg('permissions: ' + e); loadFiles(cwd()); });
}

// ---------- transfer queue (server-side, polled; docked under the browser) ----------
let queueTimer = null;
function setDockVisible(on) {
  const dock = $('#queueDock'); if (dock) dock.classList.toggle('show', !!on);
}
async function renderQueue() {
  const ul = $('#queueList'); if (!ul) return;
  // Item ids are per session, so a late render for another tab must not leave
  // its rows on screen: their cancel buttons would aim at a different queue.
  const sid = state.currentSid;
  let items = [];
  try { items = sid ? await App.QueueList(sid) : []; } catch (e) { items = []; }
  if (sid !== state.currentSid) return;
  ul.textContent = '';
  if (!items || !items.length) { setDockVisible(false); return; }
  setDockVisible(true);
  // One line per folder copy that has finished, newest first so it sits above its
  // own rows in a list that runs newest-first. Each is logged once, when it first
  // appears - the queue polls, and re-announcing the same result every 600ms would
  // bury the log.
  batchSummaries(items).slice().reverse().forEach((g) => {
    const text = batchSummaryText(g);
    // Batch ids restart with every queue, so the key that remembers what has been
    // announced carries the session too - otherwise a second tab's first folder
    // copy would finish in silence.
    const key = sid + ':' + g.batch;
    if (!announcedBatches.has(key)) {
      announcedBatches.add(key);
      msg(text);
    }
    const li = document.createElement('li');
    li.className = 'qbatch';
    li.textContent = text;
    ul.appendChild(li);
  });
  items.slice().reverse().forEach((it) => {
    const li = document.createElement('li');
    const top = document.createElement('div'); top.className = 'qtop';
    const kind = document.createElement('span'); kind.className = 'qkind'; kind.textContent = it.direction;
    const name = document.createElement('span'); name.className = 'qname'; name.textContent = it.name;
    const status = document.createElement('span'); status.className = 'qstatus';
    status.textContent = queueStatusText(it);
    top.appendChild(kind); top.appendChild(name); top.appendChild(status);
    // What the row offers is decided in queueView.js: a paused row is still
    // cancellable, and pause and resume share one slot.
    const actions = queueActions(it);
    if (actions.cancel) {
      const cx = document.createElement('button'); cx.className = 'qcancel'; cx.textContent = 'cancel'; cx.title = 'discard this transfer';
      cx.addEventListener('click', () => App.QueueCancel(sid, it.id).then(renderQueue).catch((e) => msg('cancel: ' + e)));
      top.appendChild(cx);
    }
    if (actions.toggle) {
      const toggle = document.createElement('button'); toggle.className = 'qpause';
      toggle.textContent = actions.toggle;
      toggle.title = actions.toggle === 'resume' ? 'continue from where it stopped' : 'stop here and keep what has already moved';
      const run = actions.toggle === 'resume' ? App.QueueResume : App.QueuePause;
      toggle.addEventListener('click', () => run(sid, it.id).then(renderQueue).catch((e) => msg(actions.toggle + ': ' + e)));
      top.appendChild(toggle);
    }
    const bar = document.createElement('div'); bar.className = 'qbar';
    const fill = document.createElement('div'); fill.style.width = queueBarPct(it) + '%';
    // var() keeps the error bar on the theme palette instead of a fixed red.
    if (queueBarIsError(it)) fill.style.background = 'var(--danger)';
    bar.appendChild(fill);
    li.appendChild(top); li.appendChild(bar);
    ul.appendChild(li);
  });
}
function startQueuePoll() { if (queueTimer) return; renderQueue(); queueTimer = setInterval(renderQueue, 600); }
function stopQueuePoll() { if (queueTimer) { clearInterval(queueTimer); queueTimer = null; } }

// Batches whose summary line has already been logged, keyed by session and batch.
// Kept so a settled folder copy is announced once rather than on every poll until
// the user clears the list.
const announcedBatches = new Set();

// ---------- files dropped from Explorer ----------
// Two places in the window make a drop meaningful, and both are declared to the
// runtime with --wails-drop-target (style.css), so Wails reports nothing elsewhere:
// onto the file pane means "upload these here", onto the terminal means "type
// these paths at the prompt" - which is what someone dragging a file into a shell
// actually wants. The coordinates say which one got it.
function initFileDrop() {
  try {
    OnFileDrop((x, y, paths) => handleFileDrop(x, y, paths || []), true);
  } catch (e) { msg('drag and drop unavailable: ' + e); }
}

function handleFileDrop(x, y, paths) {
  if (!paths.length) return;
  if (!state.currentSid) { msg('connect first'); return; }
  const pane = $('#filePane');
  if (state.view === 'terminal' && pane && inRect(pane, x, y)) {
    App.UploadPaths(state.currentSid, cwd(), conflictPolicy(), paths)
      .then(() => { msg('dropped ' + paths.length + ' item(s)'); renderQueue(); })
      .catch((e) => msg('drop: ' + e));
    return;
  }
  const wrap = $('#termWrap');
  if (state.view === 'terminal' && wrap && inRect(wrap, x, y)) {
    // Typed, not executed: the user still presses Enter, exactly as if they had
    // written the path themselves. Nothing is sent on their behalf.
    App.WriteInput(state.currentSid, paths.map(quoteShellPath).join(' ')).catch(() => msg('write to terminal failed'));
    return;
  }
  msg('drop files on the file pane, or on the terminal to type their paths');
}

function inRect(el, x, y) {
  const r = el.getBoundingClientRect();
  return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
}

// quoteShellPath wraps one path in single quotes - the one form every POSIX shell
// reads literally - and closes, escapes and reopens around an embedded quote so a
// file named "it's" cannot end the string early.
function quoteShellPath(p) {
  return "'" + String(p).split("'").join("'\\''") + "'";
}

// The backend queues ring this while bytes move (throttled to the interval the
// poll used anyway), so live rows update within a frame of a chunk landing
// instead of up to 600ms later. The poll above stays as the safety net for any
// ring lost to a tab switch.
EventsOn('queue:progress', () => { renderQueue(); });

// ---------- tunnels ----------
// One table and one button. A new forward is added as a blank row at the foot of
// the table and an existing one changes inside its own row, so the section is the
// list itself: no second form underneath it to line up, no bulk start/stop bar to
// press by accident, and a row never moves out from under the person editing it.

const TUNNEL_KINDS = [['local', 'Local (-L)'], ['remote', 'Remote (-R)'], ['dynamic', 'Dynamic (SOCKS -D)']];
const LOCAL_BINDS = [['local', 'This device'], ['lan', 'LAN']];
// The same question put to the far end for -R: which address on the SSH server
// opens the port. "All interfaces" is what PuTTY spells as "remote ports do the
// same", and sshd grants it only with GatewayPorts set.
const LOCAL_BIND_HELP = 'who may connect to the forwarded port: this device only (127.0.0.1) or the LAN (0.0.0.0)';
const REMOTE_BINDS = [['local', 'Loopback'], ['lan', 'All interfaces']];
const REMOTE_BIND_HELP = 'which address on the SSH server opens the port; every interface needs GatewayPorts in sshd_config';
// The columns every row fills: Name, Type, Status, Forward port, Destination,
// SSH server, Actions. The row shown instead of an empty table spans all of them.
const TUNNEL_COLS = 7;

const tunnelCell = (cls, text) => { const td = document.createElement('td'); if (cls) td.className = cls; td.textContent = text; return td; };
const tunnelCellWrap = (el) => { const td = document.createElement('td'); td.appendChild(el); return td; };
// tunnelInputCell is the cell holding two controls - a port beside its bind
// picker, a host beside its port. The flex box is a div inside the td on purpose:
// a display:flex on the td itself makes the browser wrap it in an anonymous table
// cell, the row then carries more cells than the table has columns, and every
// column after it slips out of line with the header.
const tunnelInputCell = (els) => {
  const td = document.createElement('td');
  const row = document.createElement('div'); row.className = 'cellRow';
  els.forEach((el) => { if (el) row.appendChild(el); });
  td.appendChild(row);
  return td;
};
const tunnelButton = (label, cls, title, onClick, disabled) => {
  const b = document.createElement('button');
  b.textContent = label; if (cls) b.className = cls; if (title) b.title = title;
  if (disabled) b.disabled = true;
  b.addEventListener('click', onClick);
  return b;
};
// tunnelActions lays a row's buttons out with one consistent gap.
const tunnelActions = (list) => {
  const td = document.createElement('td'); td.className = 'tacts';
  list.forEach((b, i) => { if (i) b.style.marginLeft = '6px'; td.appendChild(b); });
  return td;
};

async function refreshTunnels() {
  try { state.tunnels = await App.ListTunnels(); }
  catch (e) { msg('tunnels: ' + e); return; }
  const tb = $('#tunnelBody'); if (!tb) return;
  tb.textContent = '';
  if (!state.tunnels.length && !state.creatingTunnel) {
    const tr = document.createElement('tr');
    const td = document.createElement('td'); td.colSpan = TUNNEL_COLS; td.className = 'empty'; td.textContent = 'No tunnels yet';
    tr.appendChild(td); tb.appendChild(tr);
  }
  state.tunnels.forEach((t) => {
    tb.appendChild(state.editingTunnel === t.id ? editorRow(t) : displayRow(t));
  });
  if (state.creatingTunnel) tb.appendChild(editorRow(null));
}

// displayRow is one saved forward as text, with the three actions every row
// offers: start or stop it, change it in place, delete it.
function displayRow(t) {
  const tr = document.createElement('tr');
  // A tunnel can outlive nothing but its own session; show the id rather than
  // a blank cell if that session is already gone.
  const sess = state.sessions.find((s) => s.id === t.sessionId);
  tr.appendChild(tunnelCell('nm', t.name));
  tr.appendChild(tunnelCell('muted', t.type));
  // A stopped row is either the user's own pause or an orphan: the session it
  // was built on is gone but the definition is kept, so it is still listed and
  // will be picked up again by the next connection to the same server.
  const statusText = t.running ? 'running' : (t.orphaned ? 'no session' : 'stopped');
  tr.appendChild(tunnelCell(t.running ? 'run' : 'stopped', statusText));
  if (t.kind === 'remote') {
    // A reverse forward opens its port on the server, so the "Forward port"
    // column names that server port - and marks it when the row asked for every
    // interface rather than the server's loopback default - while the destination
    // column shows where each connection lands locally.
    tr.appendChild(tunnelCell('', t.remotePort + ' \u00b7 srv' + (t.bind === 'lan' ? ' \u00b7 all' : '')));
    tr.appendChild(tunnelCell('', 'localhost:' + t.localPort));
  } else {
    tr.appendChild(tunnelCell(t.bind === 'lan' ? 'lanb' : '', t.localPort + (t.bind === 'lan' ? ' \u00b7 LAN' : '')));
    tr.appendChild(tunnelCell('', t.remote));
  }
  // Naming the server an orphan belongs to is what tells the user this row is
  // not a leftover to be cleaned up, but a forward waiting for its host.
  tr.appendChild(tunnelCell('', sess ? sess.name : (t.orphaned ? (t.profileAddr || '') : t.sessionId)));
  // Stop only releases the listener; the definition stays so the row survives
  // and can be started again. "remove" is what deletes it.
  // Two cases can only fail if they are started, so the row says why instead of
  // offering a button that does nothing: an orphan, which has no SSH connection to
  // forward over, and a definition holding a destination that cannot be dialled -
  // saved by an older build or hand-edited into tunnels.json. The second reads the
  // same rule the editor gates its commit button on, and "edit" stays live so the
  // row can be fixed.
  const blocked = !t.running && !t.orphaned ? draftProblem(draftOf(t)) : null;
  const toggle = tunnelButton(t.running ? 'stop' : 'start', t.running ? 'danger' : '', t.running
    ? 'stop this forward, keep the definition'
    : (t.orphaned ? 'connect to ' + (t.profileAddr || 'its server') + ' to start this forward'
      : (blocked ? blocked.msg : 'start this forward again')),
    () => {
      const job = t.running ? App.StopTunnel(t.id) : App.StartTunnel(t.id);
      job.then(refreshTunnels).catch((e) => { msg('tunnel: ' + e); refreshTunnels(); });
    }, (!t.running && t.orphaned) || !!blocked);
  const edit = tunnelButton('edit', '', 'change this forward in place', () => startTunnelEdit(t));
  const rm = tunnelButton('remove', '', 'delete this tunnel definition', () => {
    // Tunnels are worth a confirm: a running forward may carry live traffic
    // and its settings would have to be retyped from memory after a mis-click.
    if (!confirm('remove ' + t.name + '?')) return;
    if (state.editingTunnel === t.id) endTunnelEdit();
    App.CloseTunnel(t.id).then(() => { msg('tunnel removed'); refreshTunnels(); }).catch((e) => msg('remove: ' + e));
  });
  tr.appendChild(tunnelActions([toggle, edit, rm]));
  return tr;
}

// editorRow is one row of the table with its cells turned into inputs: an
// existing definition's own values, or an empty set for the forward being added.
// Both work through state.tunnelDraft, because choosing the forward type of a new
// row rewrites that row and what has already been typed has to come back.
function editorRow(t) {
  const isNew = !t;
  if (!state.tunnelDraft) state.tunnelDraft = draftOf(t);
  const draft = state.tunnelDraft;
  const dynamic = draft.kind === 'dynamic';
  const isRemote = draft.kind === 'remote';
  const tr = document.createElement('tr');
  // The inputs by draft key, so a validation failure can mark the box that caused
  // it instead of only saying something in the log. Only a box the user has typed
  // in gets marked - a fresh row must not open with a red frame on an empty field.
  const fields = {};
  const touched = {};

  const field = (type, value, placeholder, key, cls) => {
    const el = document.createElement('input');
    el.type = type;
    el.value = (value === undefined || value === null) ? '' : String(value);
    if (placeholder) el.placeholder = placeholder;
    el.className = 'cellEdit' + (cls ? ' ' + cls : '');
    el.addEventListener('input', () => { draft[key] = el.value; touched[key] = true; syncCommit(); });
    el.addEventListener('keydown', (ev) => {
      if (ev.repeat) return;
      if (ev.key === 'Enter') commit();
      else if (ev.key === 'Escape') endTunnelEdit();
    });
    fields[key] = el;
    return el;
  };
  const picker = (options, value, onChange, cls, help) => {
    const el = document.createElement('select');
    el.className = 'cellEdit' + (cls ? ' ' + cls : '');
    if (help) el.title = help;
    options.forEach(([v, label]) => {
      const o = document.createElement('option'); o.value = v; o.textContent = label; el.appendChild(o);
    });
    el.value = value;
    el.addEventListener('change', () => onChange(el.value));
    return el;
  };

  tr.appendChild(tunnelCellWrap(field('text', draft.name, 'name (optional)', 'name')));

  // Type is a picker only on the new row: an existing forward's kind says how it
  // is dialled, and changing it would be a different tunnel wearing one name.
  const typeCell = document.createElement('td');
  if (isNew) {
    typeCell.appendChild(picker(TUNNEL_KINDS, draft.kind, (kind) => {
      draft.kind = kind;
      // The destination cells follow the kind, so the row is rebuilt around the
      // draft that already holds what was typed; the rebuilt row takes the caret
      // back to the port.
      refreshTunnels();
    }, 'kindEdit'));
  } else { typeCell.className = 'muted'; typeCell.textContent = t.type; }
  tr.appendChild(typeCell);

  tr.appendChild(tunnelCell(!isNew && t.running ? 'run' : 'stopped', isNew ? 'new' : (t.running ? 'running' : 'stopped')));

  // Bind sits beside the port for -L/-D (loopback by default, 0.0.0.0 to let LAN
  // devices use it). A reverse forward has no local listener at all, so its port
  // box stands for the service on this machine and the bind question moves over to
  // the destination cell, where it is asked of the server.
  // The column header already names the box, so the placeholder stays short: a
  // "local port" spelled out does not fit beside the bind picker and would be
  // clipped to "local p".
  const localCell = tunnelInputCell([
    field('number', draft.localPort, isRemote ? 'local target port' : 'port', 'localPort'),
    isRemote ? null : picker(LOCAL_BINDS, draft.bind, (v) => { draft.bind = v; }, '', LOCAL_BIND_HELP),
  ]);
  tr.appendChild(localCell);

  if (dynamic) {
    // A SOCKS forward dials no fixed destination, so there is nothing to type in
    // the cell where a local one shows host + port inputs.
    tr.appendChild(tunnelCell('muted', 'any (via SOCKS)'));
  } else if (isRemote) {
    // A reverse forward ends on this machine, so the two questions left are which
    // port the server opens and on which of its addresses.
    tr.appendChild(tunnelInputCell([
      field('number', draft.remotePort, 'port', 'remotePort', 'port'),
      picker(REMOTE_BINDS, draft.bind, (v) => { draft.bind = v; }, '', REMOTE_BIND_HELP),
    ]));
  } else {
    tr.appendChild(tunnelInputCell([
      field('text', draft.remoteHost, 'remote host', 'remoteHost'),
      field('number', draft.remotePort, 'port', 'remotePort', 'port'),
    ]));
  }

  // A new forward rides the session on screen; an existing one keeps naming the
  // session it was built on.
  const owner = isNew ? state.currentSid : t.sessionId;
  const sess = state.sessions.find((s) => s.id === owner);
  tr.appendChild(tunnelCell('', sess ? sess.name : owner));

  const commitBtn = tunnelButton(isNew ? 'Add' : 'Save', 'primary', '', commit);
  tr.appendChild(tunnelActions([
    commitBtn,
    tunnelButton('Cancel', '', 'discard the changes', () => endTunnelEdit()),
  ]));
  syncCommit();

  // The caret starts where the typing does: the port of a new forward (its name
  // is optional), the name of one that is already filled in.
  requestAnimationFrame(() => {
    const el = (isNew ? localCell : tr).querySelector('input');
    if (el) { try { el.focus(); } catch (e) {} }
  });
  return tr;

  // syncCommit gates the commit button on the same rules the backend applies, so a
  // forward that cannot work is never clicked into the table. The reason rides on
  // the button's tooltip and marks the box that caused it - saying it in the log
  // alone would leave the row looking as if it simply did nothing.
  function syncCommit() {
    const p = draftProblem(draft);
    Object.keys(fields).forEach((k) => { fields[k].classList.toggle('bad', !!p && p.field === k && !!touched[k]); });
    commitBtn.disabled = !!p;
    commitBtn.title = p ? p.msg : (isNew ? 'open this forward' : 'apply and restart this forward');
  }

  function commit() {
    // Guard against a second Enter (key repeat, or Add clicked twice) while the
    // first is still in flight: an update stops and re-binds the forward, so a
    // repeat would drop live tunneled connections.
    if (state.tunnelDraft !== draft) return;
    // Enter reaches this even while the button is disabled, so the row is checked
    // here too rather than only in the button's state.
    const p = draftProblem(draft);
    if (p) { msg(p.msg); syncCommit(); return; }
    const v = draftValues(draft);
    const name = String(draft.name || '').trim();
    const job = isNew
      ? openDraft(name, v, draft)
      : App.UpdateTunnel(t.id, name, v.localPort, v.remoteHost, v.remotePort, draft.bind);
    // The row closes before the answer arrives: the call already carries the
    // values, and leaving the inputs up would invite a third edit of a forward
    // that is being re-bound.
    state.editingTunnel = '';
    state.creatingTunnel = false;
    state.tunnelDraft = null;
    job.then(() => { msg(isNew ? 'tunnel open' : 'tunnel updated'); refreshTunnels(); }).catch((e) => {
      // Refresh even on failure: a rejected update leaves the definition
      // stopped with the new values, and the row should say so.
      msg('tunnel: ' + e);
      refreshTunnels();
    });
  }
}

// openDraft turns a validated new row into the call that dials it. -R is the odd
// one: the server opens remoteHost:remotePort and ships every connection back to
// this machine's 127.0.0.1:localPort service.
function openDraft(name, v, draft) {
  const sid = state.currentSid;
  if (draft.kind === 'dynamic') return App.OpenDynamicTunnel(sid, name, v.localPort, draft.bind);
  if (draft.kind === 'remote') return App.OpenRemoteTunnel(sid, name, v.remoteHost, v.remotePort, v.localPort, draft.bind);
  return App.OpenTunnel(sid, name, v.localPort, v.remoteHost, v.remotePort, draft.bind);
}

// createTunnelRow adds the blank row, and takes it away again if the button is
// pressed while it is already open.
function createTunnelRow() {
  if (!state.currentSid) { msg('connect first'); return; }
  if (state.creatingTunnel) { endTunnelEdit(); return; }
  state.editingTunnel = '';
  state.creatingTunnel = true;
  state.tunnelDraft = draftOf(null);
  refreshTunnels();
}

// openForwardDialog offers the ssh/PuTTY line form as a second way in. The shapes
// are the ones people already type at a shell, so a batch of forwards is one
// paste rather than six boxes each time.
function openForwardDialog() {
  if (!state.currentSid) { msg('connect first'); return; }
  const ta = $('#forwardText'); if (ta) ta.value = '';
  const dlg = $('#forwardDlg'); if (!dlg) return;
  dlg.showModal();
  if (ta) ta.focus();
}

// runForwardImport parses every line, then opens the forwards one at a time: two
// lines naming the same port must not race each other for the listener, and one
// bad line has to be reported by number instead of stopping the rest.
async function runForwardImport() {
  const ta = $('#forwardText');
  const parsed = parseForwardLines(ta ? ta.value : '');
  if (!parsed.drafts.length) {
    // Nothing usable: the dialog stays open so the line can be corrected in place.
    parsed.errors.slice(0, 3).forEach((e) => msg('line ' + e.line + ': ' + e.error));
    if (!parsed.errors.length) msg('nothing to add');
    return;
  }
  const dlg = $('#forwardDlg'); if (dlg) dlg.close();
  const refused = parsed.errors.slice();
  let added = 0;
  for (const item of parsed.drafts) {
    // The parser reads the shape; the row's own rules decide whether the forward
    // could work, so a pasted line is held to exactly what the boxes insist on.
    const p = draftProblem(item.draft);
    if (p) { refused.push({ line: item.line, error: p.msg }); continue; }
    try {
      await openDraft('', draftValues(item.draft), item.draft);
      added++;
    } catch (e) {
      refused.push({ line: item.line, error: String(e) });
    }
  }
  msg('forwards added: ' + added + (refused.length ? ', refused: ' + refused.length : ''));
  refused.slice(0, 5).forEach((r) => msg('line ' + r.line + ': ' + r.error));
  refreshTunnels();
}

// startTunnelEdit puts one saved forward into its own edit state, replacing
// whichever row was open before it.
function startTunnelEdit(t) {
  if (state.editingTunnel === t.id) return;
  state.creatingTunnel = false;
  state.editingTunnel = t.id;
  state.tunnelDraft = draftOf(t);
  refreshTunnels();
}

// endTunnelEdit leaves the row editor: the open row, whether an edit or the new
// forward, goes back to being a plain line of the table.
function endTunnelEdit() {
  state.editingTunnel = '';
  state.creatingTunnel = false;
  state.tunnelDraft = null;
  refreshTunnels();
}

// ---------- settings ----------
// The sheet holds what has no other home: appearance (theme, terminal font),
// connection behaviour, the transfer conflict policy and the two preferences
// actions - pin the whole set to disk, or start over from the defaults. The
// file-pane Follow and Show-hidden toggles stay on the pane itself.
function refreshSettings() {
  const r = $('#setTermFont');
  if (r) { const e = activeTerm(); r.value = e ? e.options.fontSize : termFontSize(); }
  const o = $('#setTermFontVal');
  if (o && r) o.textContent = r.value + ' px';
  const ar = $('#setAutoReconnect');
  if (ar) ar.checked = autoReconnect();
  const cp = $('#setConflict');
  if (cp) cp.value = conflictPolicy();
  refreshProxy();
}

// setProxyFieldsEnabled disables the proxy detail fields while the type is
// "None". They have no effect then, and four live inputs under a None picker read
// as an invitation to fill in something that will be ignored. The fields keep
// their place, so choosing a type does not move the rest of the sheet.
function setProxyFieldsEnabled(on) {
  ['#setProxyHost', '#setProxyPort', '#setProxyUser', '#setProxyPass'].forEach((sel) => {
    const el = $(sel); if (el) el.disabled = !on;
  });
}

// refreshProxy loads the persisted outbound-proxy settings into the form. The
// password field is never populated (it is not stored); it only shows whether
// one is currently loaded for this run.
async function refreshProxy() {
  let ps;
  try { ps = await App.GetProxy(); } catch (e) { return; }
  const k = $('#setProxyKind'); if (k) k.value = ps.kind || '';
  const h = $('#setProxyHost'); if (h) h.value = ps.host || '';
  const p = $('#setProxyPort'); if (p) p.value = ps.port || '';
  const u = $('#setProxyUser'); if (u) u.value = ps.user || '';
  const pw = $('#setProxyPass'); if (pw) { pw.value = ''; pw.placeholder = ps.hasPassword ? 'password (loaded for this run)' : 'password (not saved)'; }
  setProxyFieldsEnabled(!!(ps.kind || ''));
}

function wireSettings() {
  const r = $('#setTermFont');
  if (r) r.addEventListener('input', () => {
    const o = $('#setTermFontVal'); if (o) o.textContent = r.value + ' px';
    setTermFont(parseInt(r.value, 10));
  });
  const ar = $('#setAutoReconnect');
  if (ar) ar.addEventListener('change', () => {
    // On unless the user explicitly turned it off; stored as a flag word so
    // resetPreferences can clear it back to the default with one removeItem.
    try { localStorage.setItem('gravel.autoReconnect', ar.checked ? 'on' : 'off'); } catch (e) {}
    msg(ar.checked ? 'dropped links will reconnect automatically' : 'dropped links will ask first');
  });
  const cp = $('#setConflict');
  if (cp) cp.addEventListener('change', () => {
    try { localStorage.setItem(CONFLICT_KEY, cp.value); } catch (e) {}
    msg('transfer conflicts: ' + cp.value);
  });
  const ra = $('#setResetAll');
  if (ra) ra.addEventListener('click', resetPreferences);
  const pk = $('#setProxyKind');
  if (pk) pk.addEventListener('change', () => setProxyFieldsEnabled(pk.value !== ''));
  const sp = $('#btnSaveProxy');
  if (sp) sp.addEventListener('click', saveProxy);
  const sv = $('#btnSaveSettings');
  if (sv) sv.addEventListener('click', saveSettings);
}

// saveProxy persists the proxy kind/host/port/user and, if a password was typed
// this session, hands it to the backend for in-memory use only. The password
// field is cleared afterwards so it does not linger in the form.
async function saveProxy() {
  const kind = $('#setProxyKind').value;
  const host = $('#setProxyHost').value.trim();
  const port = parseInt($('#setProxyPort').value, 10) || 0;
  const user = $('#setProxyUser').value.trim();
  const pass = $('#setProxyPass').value;
  try {
    await App.SetProxy(kind, host, port, user);
    if (pass) await App.SetProxyPassword(pass);
    $('#setProxyPass').value = '';
    msg(kind ? 'proxy saved' : 'proxy cleared');
    refreshProxy();
  } catch (e) { msg('proxy: ' + e); }
}

// collectPrefsJSON bundles the frontend preferences (localStorage) so the
// backend can carry them into the pinned copy; they have no other home there.
function collectPrefsJSON() {
  const out = {};
  PREF_KEYS.forEach((k) => { try { const v = localStorage.getItem(k); if (v !== null) out[k] = v; } catch (e) {} });
  return JSON.stringify(out);
}

// saveSettings pins the current preferences into the config folder, beside the
// saved servers. Every change is already stored in the webview as it is made; the
// pinned copy is the one that survives that profile being cleared or moved - the
// way a rename used to silently reset the theme, font size and pane width.
async function saveSettings() {
  try {
    await App.SavePreferences(collectPrefsJSON());
    msg('settings saved');
  } catch (e) { msg('save settings: ' + e); }
}

// restorePinnedPrefs pulls the pinned copy back into the webview, but only into
// the gaps localStorage left: the live copy stays in charge while it holds a
// value, so a setting that was changed and never pinned can never be overruled
// by an older copy on disk.
async function restorePinnedPrefs() {
  let pinned = null;
  // Boot calls this before anything reads a preference, and at first paint the
  // bindings can still be arriving; one short retry costs nothing and a missed
  // read only means the settings come back on the next start instead.
  for (let attempt = 0; attempt < 2 && pinned === null; attempt++) {
    try { pinned = await App.GetPreferences(); }
    catch (e) { await new Promise((done) => setTimeout(done, 250)); }
  }
  if (!pinned) return;
  let restored = 0;
  PREF_KEYS.forEach((k) => {
    const v = pinned[k];
    if (typeof v !== 'string' || v === '') return;
    try { if (localStorage.getItem(k) === null) { localStorage.setItem(k, v); restored++; } } catch (e) {}
  });
  if (restored) msg('settings restored from the saved copy (' + restored + ')');
}

// Keys written by the settings surfaces (font, theme, follow, hidden, pane,
// auto-reconnect). Saved sessions, tunnels and trusted hosts are data, not
// preferences - they are deliberately untouched by a reset.
const PREF_KEYS = ['gravel.termFontSize', 'gravel.theme', 'gravel.followTerminalFolder', 'gravel.showHidden', 'gravel.paneWidth', 'gravel.autoReconnect', 'gravel.conflictPolicy'];

// resetPreferences clears the stored prefs and re-applies every default live:
// font 14px, dark theme, follow-on, hidden-off, pane at 720px, auto-reconnect on.
function resetPreferences() {
  PREF_KEYS.forEach((k) => { try { localStorage.removeItem(k); } catch (e) {} });
  // The pinned copy goes with them, or the next start would read the settings
  // this reset just threw away straight back off the disk.
  App.SavePreferences('{}').catch((e) => msg('clear saved settings: ' + e));
  setTermFont(FONT_DEFAULT);
  applyTheme('dark');
  const ft = $('#followTerm'); if (ft) { ft.checked = true; ft.dispatchEvent(new Event('change')); }
  const sh = $('#showHidden'); if (sh) { sh.checked = false; sh.dispatchEvent(new Event('change')); }
  const ar = $('#setAutoReconnect'); if (ar) ar.checked = true;
  const cp = $('#setConflict'); if (cp) cp.value = 'overwrite';
  setPaneWidth(PANE_DEFAULT);
  refitTerminal();
  refreshSettings();
  msg('settings reset to defaults');
}

// ---------- logs (live view of everything the backend a.log() writes) ----------
// The backend keeps a 500-line ring and mirrors each new line here as a
// "log:line" event, so the tab follows along even while it is not open.
let logLines = [];

EventsOn('log:line', (line) => {
  logLines.push(line);
  if (logLines.length > 500) logLines.splice(0, logLines.length - 500);
  if (state.view === 'logs') renderLogs();
});

async function refreshLogs() {
  try { logLines = await App.ListLogs() || []; } catch (e) {}
  renderLogs();
}

function logFollowOn() { const el = $('#logFollow'); return !!(el && el.checked); }

function renderLogs() {
  const box = $('#logBox'); if (!box) return;
  box.textContent = logLines.join('\n');
  if (logFollowOn()) box.scrollTop = box.scrollHeight;
}

function clearLogView() {
  logLines = [];
  renderLogs();
  msg('log view cleared');
}

// dumpLogs writes only the current session's lines (what the Logs tab shows,
// from app start to now) to a file the user picks. The per-launch file in
// AppData keeps recording regardless.
function dumpLogs() {
  App.DumpLogs().then((p) => { if (p) msg('log dumped to ' + p); }).catch((e) => msg('dump: ' + e));
}

// ---------- resizable file pane ----------
const PANE_KEY = 'gravel.paneWidth';
// Bounds match the min-width/max-width guards on #filePane in style.css.
// The seven columns need 140+54+112+72+72+84+164 = 698px; 720 leaves room for the
// pane border and sub-pixel rounding without a sideways scrollbar.
const PANE_MIN = 320, PANE_MAX = 900, PANE_DEFAULT = 720;

function setPaneWidth(px) {
  const w = clampInt(px, PANE_MIN, PANE_MAX, PANE_DEFAULT);
  document.documentElement.style.setProperty('--pane-w', w + 'px');
  try { localStorage.setItem(PANE_KEY, String(w)); } catch (e) {}
  return w;
}

// refitTerminal measures the pane on screen and pushes its size to its session.
// Hidden panes are deliberately skipped: they measure zero, and pushing that to a
// remote PTY would shrink it - a pane is refitted when it is shown instead. The
// size is pushed even when xterm's own onResize did not fire, because that only
// fires on a cols change, so a stale fit could leave the remote wrapping at a
// width the screen no longer shows - the clipped lines and blank gaps this
// prevents.
function refitTerminal() {
  const sid = state.pendingNew ? '' : state.currentSid;
  refitEntry(sid === '' ? state.loginEntry : state.terms[sid], sid);
}

function initSplitter() {
  const sp = $('#splitter'); if (!sp) return;
  // Only apply a stored width if there is one; a first run keeps the CSS default.
  const saved = localStorage.getItem(PANE_KEY);
  if (saved !== null && saved !== '') setPaneWidth(saved);
  let dragging = false;
  sp.addEventListener('pointerdown', (e) => {
    dragging = true;
    sp.classList.add('dragging');
    document.body.classList.add('resizing');
    try { sp.setPointerCapture(e.pointerId); } catch (err) {}
    e.preventDefault();
  });
  sp.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    setPaneWidth(e.clientX - sp.parentElement.getBoundingClientRect().left);
  });
  const stop = (e) => {
    if (!dragging) return;
    dragging = false;
    sp.classList.remove('dragging');
    document.body.classList.remove('resizing');
    try { sp.releasePointerCapture(e.pointerId); } catch (err) {}
    refitTerminal(); // reflow the terminal once, not on every move
  };
  sp.addEventListener('pointerup', stop);
  sp.addEventListener('pointercancel', stop);
  sp.addEventListener('dblclick', () => { setPaneWidth(PANE_DEFAULT); refitTerminal(); });
}

// ---------- wire events ----------
// initFollowToggle restores the persisted preference; when switching it back on
// the pane is snapped to wherever the terminal session currently is.
function initFollowToggle() {
  const el = $('#followTerm'); if (!el) return;
  const saved = localStorage.getItem(FOLLOW_KEY);
  if (saved !== null) el.checked = saved === '1';
  el.addEventListener('change', () => {
    localStorage.setItem(FOLLOW_KEY, el.checked ? '1' : '0');
    if (el.checked && state.currentSid) loadFiles(cwd());
  });
}

// applyTheme drives both the CSS palette (data-theme on <html>, read by the
// inline script in index.html before first paint so there is no flash) and the
// xterm theme, which is derived from the same custom properties.
function applyTheme(name) {
  document.documentElement.dataset.theme = name;
  try { localStorage.setItem(THEME_KEY, name); } catch (e) {}
  // Every terminal takes the new palette, so no tab is left on the old theme.
  if (state.loginEntry) { try { state.loginEntry.term.options.theme = termTheme(); } catch (e) {} }
  setThemeAll(state.terms, termTheme());
  // The sliding thumb and the highlighted label are pure CSS on data-theme, so
  // the only thing left is telling assistive tech which segment is pressed.
  document.querySelectorAll('#themeToggle .tseg').forEach((b) => {
    b.setAttribute('aria-pressed', b.dataset.theme === name ? 'true' : 'false');
  });
}

function initTheme() {
  // localStorage is the store of the choice; the inline script in index.html
  // only guesses ahead of the first paint so there is no flash, and a theme
  // restored from the pinned copy has to be read back from here.
  applyTheme(localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark');
  document.querySelectorAll('#themeToggle .tseg').forEach((b) => {
    b.addEventListener('click', () => applyTheme(b.dataset.theme));
  });
}

// initShowHidden restores the dotfile preference; changing it only re-renders the
// listing that is already loaded, so no extra round trip is needed on first open.
function initShowHidden() {
  const el = $('#showHidden'); if (!el) return;
  el.checked = localStorage.getItem(HIDDEN_KEY) === '1';
  el.addEventListener('change', () => {
    try { localStorage.setItem(HIDDEN_KEY, el.checked ? '1' : '0'); } catch (e) {}
    if (state.currentSid) loadFiles(cwd());
  });
}

document.querySelectorAll('.navitem').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.view)));
$('#btnConnectServer').addEventListener('click', doConnect);
$('#btnLoadServer').addEventListener('click', () => {
  if (!state.selectedProfile) { msg('select a saved session first'); return; }
  fillForm(state.selectedProfile);
});
$('#btnSaveServer').addEventListener('click', saveServer);
$('#btnDeleteServer').addEventListener('click', deleteServer);
$('#btnImportHosts').addEventListener('click', openImportDialog);
$('#importGo').addEventListener('click', runImport);
$('#importPickFile').addEventListener('click', pickImportFile);
$('#importCancel').addEventListener('click', () => $('#importDlg').close());
$('#svAuth').addEventListener('change', (e) => { $('#svKeyWrap').hidden = e.target.value !== 'key'; });
$('#btnPickKey').addEventListener('click', async () => {
  try { const p = await App.PickSSHKey(); if (p) $('#svKey').value = p; }
  catch (e) { msg('key picker: ' + e); }
});
$('#btnUp').addEventListener('click', goUp);
$('#btnMkdir').addEventListener('click', mkdir);
$('#btnNewFile').addEventListener('click', newFile);
$('#btnUpload').addEventListener('click', upload);
$('#btnUploadDir').addEventListener('click', uploadDir);
$('#btnRefresh').addEventListener('click', () => loadFiles(cwd()));
$('#btnNewTunnel').addEventListener('click', createTunnelRow);
$('#btnPasteForwards').addEventListener('click', openForwardDialog);
$('#forwardGo').addEventListener('click', runForwardImport);
$('#forwardCancel').addEventListener('click', () => $('#forwardDlg').close());
wireSettings();
$('#btnLogRefresh').addEventListener('click', refreshLogs);
$('#btnLogClear').addEventListener('click', clearLogView);
$('#btnLogDump').addEventListener('click', dumpLogs);
$('#btnQueueClear').addEventListener('click', () => App.QueueClear(state.currentSid).then(renderQueue).catch((e) => msg('clear queue: ' + e)));
$('#tofuAccept').addEventListener('click', acceptTOFU);
$('#tofuReject').addEventListener('click', () => { $('#tofu').close(); state.retryConnect = null; msg('connection rejected'); });

// ---------- editor wiring ----------
$('#edText').addEventListener('input', () => {
  $('#edDot').hidden = !editorDirty();
  $('#edStatus').textContent = editorDirty() ? 'unsaved' : '';
});
$('#edSave').addEventListener('click', saveEditor);
$('#edCancel').addEventListener('click', closeEditor);
// ---------- permissions dialog wiring ----------
$('#permOctal').addEventListener('input', onPermOctalInput);
$('#permSave').addEventListener('click', savePerm);
$('#permCancel').addEventListener('click', () => $('#perm').close());
// Ctrl/Cmd+S saves while the editor is the open dialog; the native browser save
// dialog is suppressed. Guard on .open so the shortcut is inert otherwise.
document.addEventListener('keydown', (e) => {
  if (!$('#editor').open) return;
  if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 's') {
    e.preventDefault();
    if (!e.repeat) saveEditor();
  }
}, true);

// Links open in the user's real browser. Letting the webview navigate would
// replace the running app with a web page and lose the terminal session.
document.querySelectorAll('a[data-url]').forEach((a) => a.addEventListener('click', (e) => {
  e.preventDefault();
  try { BrowserOpenURL(a.dataset.url); } catch (err) { msg('could not open ' + a.dataset.url); }
}));

// No zoom gestures at all: Ctrl + wheel and Ctrl + +/- were removed because a
// resize that the remote has not acknowledged garbles its line wrapping; the
// window itself can still be resized, which reflows correctly via fit+resize.

// ---------- boot ----------
// The session list is polled rather than pushed. The handle is kept so a second
// boot() in the same document can never stack a second poller on top of the
// first, the way the transfer queue poll already refuses to double-start.
let sessionPoll = 0;

async function boot() {
  // The pinned copy is read first: every init below takes its value from
  // localStorage, and a restored setting has to be in there before it looks.
  await restorePinnedPrefs();
  initTheme();
  initSplitter();
  initFollowToggle();
  initShowHidden();
  initSearchBar();
  initFileDrop();
  try {
    const v = await App.VersionInfo();
    $('#aboutVer').textContent = v;
    const sv = $('#statusVer'); if (sv) sv.textContent = 'Gravel v' + v;
  } catch (e) { msg('version: ' + e); }
  await refreshProfiles();
  await refreshSessions();
  if (sessionPoll) clearInterval(sessionPoll);
  sessionPoll = setInterval(() => { refreshSessions().catch(() => {}); }, 5000);
}
boot();
