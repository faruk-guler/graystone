// Pure validation for the Tunnels row editor - no DOM, no xterm, no Wails
// bindings, so `node --test` can cover it. The row is the only place a forward is
// described, so what it refuses is what never reaches the table. The backend
// repeats the same rules (app.go validForwardHost and validPort) because a
// tunnels.json that was hand-edited, or written by an older build, never passes
// through this form.

import { parsePort } from './utils.js';

// A destination the SSH server can dial: an address literal (checked apart) or a
// DNS name built from RFC 1123 labels. This is what rejects the residue of
// pasting a URL or a "[host]:port" pair - spaces, slashes, brackets, a trailing
// colon, an empty label.
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

// An address literal, checked apart from the name rule so that "::1" and
// "10.0.0.5" are accepted while the residue of a paste ("[db]:5432",
// "db:5432") is not mistaken for one.
const IPV6_RE = /^[0-9A-Fa-f:]+$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function isAddressLiteral(h) {
  if (h.indexOf(':') >= 0) return IPV6_RE.test(h);
  return IPV4_RE.test(h) && h.split('.').every((part) => Number(part) < 256);
}

// emptyDraft is the blank row: a local forward, listening on this device only,
// with no port and no destination typed yet.
export function emptyDraft() {
  return { kind: 'local', bind: 'local', name: '', localPort: '', remoteHost: '', remotePort: '' };
}

// draftOf seeds the editor from a stored definition, so editing a forward starts
// from what is on record rather than from nothing.
export function draftOf(t) {
  if (!t) return emptyDraft();
  return {
    kind: t.kind || 'local',
    bind: t.bind === 'lan' ? 'lan' : 'local',
    name: t.name || '',
    localPort: t.localPort,
    remoteHost: t.remoteHost || '',
    remotePort: t.remotePort,
  };
}

// hostProblem answers why a destination can never be dialled, or null. The case
// this exists for is a port typed into the host box ("442"): that is a perfectly
// legal DNS label, so a format check alone would accept a forward that reads
// "running" and fails every connection put through it.
function hostProblem(host) {
  const h = String(host === undefined || host === null ? '' : host).trim();
  if (!h) return { msg: 'remote host required', field: 'remoteHost' };
  if (isAddressLiteral(h)) return null;
  if (!HOST_RE.test(h)) return { msg: 'host "' + h + '" is not a valid name or address', field: 'remoteHost' };
  if (h.indexOf('.') < 0 && !/[A-Za-z]/.test(h)) return { msg: 'host "' + h + '" looks like a port, not a host', field: 'remoteHost' };
  return null;
}

// draftProblem is the gate: the first thing wrong with the row, naming the field
// to mark, or null when the row can be committed. The checks run in the order the
// boxes are filled in, so the message always points at the first one left bad.
export function draftProblem(draft) {
  const d = draft || {};
  if (parsePort(d.localPort) === null) return { msg: 'local port must be 1-65535', field: 'localPort' };
  // A SOCKS forward dials no fixed destination, so there is nothing left to check.
  if (d.kind === 'dynamic') return null;
  if (parsePort(d.remotePort) === null) return { msg: 'remote port must be 1-65535', field: 'remotePort' };
  const host = String(d.remoteHost === undefined || d.remoteHost === null ? '' : d.remoteHost).trim();
  // A reverse forward names the port the server opens; its host is the bind
  // address and may stay empty, in which case the server chooses one.
  if (d.kind === 'remote') return host ? hostProblem(host) : null;
  return hostProblem(host);
}

// draftValues returns what to send, or null while the row is invalid. A dynamic
// forward has no destination, but every caller passes the two fields, so they come
// back as empty values rather than undefined.
export function draftValues(draft) {
  if (draftProblem(draft)) return null;
  const d = draft || {};
  const localPort = parsePort(d.localPort);
  if (d.kind === 'dynamic') return { localPort, remoteHost: '', remotePort: 0 };
  return { localPort, remoteHost: String(d.remoteHost || '').trim(), remotePort: parsePort(d.remotePort) };
}
