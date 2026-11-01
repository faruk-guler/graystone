// Pure parser for the "add forwards from a line" dialog: it reads the shapes ssh
// and PuTTY already use, so a forward somebody knows how to type on the command
// line does not have to be found again in six boxes. No DOM, no bindings, so
// `node --test` covers it.
//
//   L 9080 db.internal:5432        -L 9080:db.internal:5432
//   -L 0.0.0.0:9080:db.internal:5432
//   R 2222 localhost:80            -R 2222:localhost:80        -R *:2222:localhost:80
//   D 1080                         -D 1080
//
// Anything it cannot read as one of those is reported, never guessed at: a
// half-parsed forward would open a listener on the wrong place.

const KINDS = { l: 'local', r: 'remote', d: 'dynamic' };
// The leading marker, with the long-option and bare-letter spellings beside it.
const KIND_RE = /^(?:-{1,2}(local|remote|dynamic)(?:[-_]forward)?|-([lrd])|([lrd])(?![a-z]))\s*(.*)$/i;
const LONG_KINDS = { local: 'local', remote: 'remote', dynamic: 'dynamic' };
const IS_PORT = /^\d{1,5}$/;
// A bind prefix is only ever one of these: the wildcard PuTTY writes, and the
// IPv4 address that means the same thing on the wire. An IPv6 bind cannot be
// spelled here at all - the pieces are split on ":" - so it is not offered.
const WILDCARD = ['*', '0.0.0.0'];
// The names a reverse forward's destination host may carry, since it is served
// from this machine: the loopback spellings and nothing else.
const LOCAL_HOSTS = ['localhost', '127.0.0.1', ''];

// parseForwardLine reads one line. It answers { skip } for a blank or commented
// line, { ok, draft } for a forward it understood, and { ok:false, error } when
// the line is not a forward - so the dialog can say which line it refused rather
// than quietly dropping it.
export function parseForwardLine(line) {
  const raw = String(line === undefined || line === null ? '' : line).trim();
  if (!raw || raw.startsWith('#') || raw.startsWith('//')) return { skip: true };
  const body = raw.replace(/^ssh\s+/i, '');
  const m = KIND_RE.exec(body);
  const kind = m ? (m[1] ? LONG_KINDS[m[1].toLowerCase()] : KINDS[(m[2] || m[3]).toLowerCase()]) : 'local';
  const spec = (m ? m[4] : body).trim();
  const parts = spec.split(/[\s:]+/).filter(Boolean);
  if (kind === 'dynamic') return dynamicDraft(parts);
  return endpointDraft(kind, parts);
}

// A SOCKS forward is a port, optionally written with the host it listens on.
function dynamicDraft(parts) {
  if (!parts.length) return refused('no port in a dynamic forward');
  if (parts.length > 2) return refused('a dynamic forward is just a port, like -D 1080');
  const port = parts[parts.length - 1];
  if (!IS_PORT.test(port)) return refused('no port in a dynamic forward');
  return accepted({ kind: 'dynamic', bind: bindFor(parts.length === 2 ? parts[0] : ''), localPort: port });
}

// A local or reverse forward is [bind:]source:host:destination-port, or the same
// three pieces with the destination written as "host:port" after a space.
function endpointDraft(kind, parts) {
  let bind = '';
  let rest = parts;
  // Four pieces, and the first is not a port: that is the optional bind address.
  if (parts.length === 4 && !IS_PORT.test(parts[0])) {
    if (WILDCARD.indexOf(parts[0].toLowerCase()) < 0) {
      return refused('the bind address must be "*" or an address, not "' + parts[0] + '"');
    }
    bind = parts[0];
    rest = parts.slice(1);
  }
  if (rest.length !== 3) return refused('expected source port, host and destination port');
  const [sourcePort, host, destPort] = rest;
  if (!IS_PORT.test(sourcePort)) return refused('the ' + (kind === 'remote' ? 'server' : 'local') + ' port is not a number');
  if (!IS_PORT.test(destPort)) return refused('the destination port is not a number');
  if (kind === 'remote') {
    // For -R the bind is the address the server opens, and the destination is a
    // service on this machine. Our reverse forward always hands the connection to
    // loopback here, so a line pointing it at another host is refused rather than
    // quietly delivered somewhere else.
    if (!LOCAL_HOSTS.includes(host.toLowerCase())) {
      return refused('a reverse forward ends on this machine, so the destination host must be localhost (not "' + host + '")');
    }
    return accepted({ kind: 'remote', bind: bindFor(bind), localPort: destPort, remoteHost: '', remotePort: sourcePort });
  }
  return accepted({ kind: 'local', bind: bindFor(bind), localPort: sourcePort, remoteHost: host, remotePort: destPort });
}

function bindFor(prefix) {
  return WILDCARD.indexOf(String(prefix || '').toLowerCase()) >= 0 ? 'lan' : 'local';
}

function accepted(fields) {
  return {
    ok: true,
    draft: {
      name: '',
      bind: 'local',
      localPort: '',
      remoteHost: '',
      remotePort: '',
      ...fields,
    },
  };
}

function refused(why) {
  return { ok: false, error: why };
}

// parseForwardLines reads the whole paste. It keeps the line numbers (1-based, as
// the user counts them in the box) so a refusal can be pointed at.
export function parseForwardLines(text) {
  const drafts = [];
  const errors = [];
  const lines = String(text === undefined || text === null ? '' : text).split(/\r?\n/);
  lines.forEach((line, i) => {
    const r = parseForwardLine(line);
    if (r.skip) return;
    if (r.ok) { drafts.push({ line: i + 1, draft: r.draft }); return; }
    errors.push({ line: i + 1, error: r.error + ' ("' + line.trim() + '")' });
  });
  return { drafts, errors };
}
