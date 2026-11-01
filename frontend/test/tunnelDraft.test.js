// Frontend regression tests - run with `npm test` in the frontend folder
// (or `node --test`). These cover src/tunnelDraft.js: the rules the Tunnels row
// editor gates a forward on, which need no browser, no xterm and no bindings.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { draftOf, draftProblem, draftValues } from '../src/tunnelDraft.js';

const local = (over) => Object.assign({ kind: 'local', bind: 'local', name: '', localPort: '8080', remoteHost: 'db.internal', remotePort: '5432' }, over);

test('draftOf starts a new row as an empty local forward and maps a stored one', () => {
  assert.deepEqual(draftOf(null), { kind: 'local', bind: 'local', name: '', localPort: '', remoteHost: '', remotePort: '' });
  assert.deepEqual(draftOf(undefined), { kind: 'local', bind: 'local', name: '', localPort: '', remoteHost: '', remotePort: '' });
  const stored = { kind: 'remote', bind: 'lan', name: 'web', localPort: 9000, remoteHost: '0.0.0.0', remotePort: 80 };
  assert.deepEqual(draftOf(stored), { kind: 'remote', bind: 'lan', name: 'web', localPort: 9000, remoteHost: '0.0.0.0', remotePort: 80 });
  // A definition whose kind was never recorded stays a local forward, and a bind
  // that is not the LAN marker reads as loopback rather than as something unknown.
  assert.equal(draftOf({ localPort: 1, remoteHost: 'h', remotePort: 2 }).kind, 'local');
  assert.equal(draftOf({ kind: 'local', bind: 'anything-else' }).bind, 'local');
});

test('a complete local forward is accepted and returns its values', () => {
  const d = local();
  assert.equal(draftProblem(d), null);
  assert.deepEqual(draftValues(d), { localPort: 8080, remoteHost: 'db.internal', remotePort: 5432 });
});

test('the ports are the first thing the row checks', () => {
  for (const bad of ['', '  ', '0', '70000', 'abc', '80.5']) {
    const p = draftProblem(local({ localPort: bad }));
    assert.ok(p, `localPort ${JSON.stringify(bad)} must be refused`);
    assert.equal(p.field, 'localPort');
    assert.equal(p.msg, 'local port must be 1-65535');
  }
  const p = draftProblem(local({ remotePort: '' }));
  assert.equal(p.field, 'remotePort');
  assert.equal(p.msg, 'remote port must be 1-65535');
});

// The case the whole rule exists for: a port typed into the host box is a legal
// DNS label, so only an explicit check keeps a dead forward out of the table.
test('a destination that can never be dialled is refused, and says which box', () => {
  const cases = [
    ['', 'remote host required'],
    ['   ', 'remote host required'],
    ['442', 'host "442" looks like a port, not a host'],
    ['8080', 'host "8080" looks like a port, not a host'],
    ['http://db.internal', 'host "http://db.internal" is not a valid name or address'],
    ['db internal', 'host "db internal" is not a valid name or address'],
    ['[db.internal]:5432', 'host "[db.internal]:5432" is not a valid name or address'],
    ['db.internal:', 'host "db.internal:" is not a valid name or address'],
    ['db..internal', 'host "db..internal" is not a valid name or address'],
  ];
  for (const [host, msg] of cases) {
    const p = draftProblem(local({ remoteHost: host }));
    assert.ok(p, `remoteHost ${JSON.stringify(host)} must be refused`);
    assert.equal(p.field, 'remoteHost');
    assert.equal(p.msg, msg);
    assert.equal(draftValues(local({ remoteHost: host })), null);
  }
});

test('every destination a server can actually dial is accepted', () => {
  for (const host of ['10.0.0.5', '127.0.0.1', '::1', 'fe80::1', 'db.internal', 'localhost', 'web-1.example.com', 'a']) {
    assert.equal(draftProblem(local({ remoteHost: host })), null, `host ${host}`);
  }
  // Typed with spaces around it, because that is how a paste arrives.
  assert.deepEqual(draftValues(local({ remoteHost: '  10.0.0.5  ' })).remoteHost, '10.0.0.5');
});

test('a SOCKS forward needs a port and nothing else', () => {
  const d = local({ kind: 'dynamic', remoteHost: '', remotePort: '' });
  assert.equal(draftProblem(d), null);
  assert.deepEqual(draftValues(d), { localPort: 8080, remoteHost: '', remotePort: 0 });
  assert.equal(draftProblem(local({ kind: 'dynamic', localPort: 'x' })).field, 'localPort');
});

test('a reverse forward may name no bind host, but not a false one', () => {
  assert.equal(draftProblem(local({ kind: 'remote', remoteHost: '' })), null);
  assert.equal(draftProblem(local({ kind: 'remote', remoteHost: '0.0.0.0' })), null);
  assert.equal(draftProblem(local({ kind: 'remote', remoteHost: '442' })).field, 'remoteHost');
});

test('the checks run in the order the boxes are filled in', () => {
  // Both ports blank and no host: the message has to be about the local port,
  // because that is the first box the user is standing at.
  const p = draftProblem(local({ localPort: '', remoteHost: '', remotePort: '' }));
  assert.equal(p.field, 'localPort');
});
