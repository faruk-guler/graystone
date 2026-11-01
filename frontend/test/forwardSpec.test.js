// Frontend regression tests - run with `npm test` in the frontend folder
// (or `node --test`). These cover src/forwardSpec.js, the ssh / PuTTY line form
// the "Paste lines" dialog reads.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseForwardLine, parseForwardLines } from '../src/forwardSpec.js';
import { draftProblem } from '../src/tunnelDraft.js';

const LOCAL = { kind: 'local', bind: 'local', name: '', localPort: '9080', remoteHost: 'db.internal', remotePort: '5432' };

test('a local forward is read in every spelling people actually type', () => {
  for (const line of [
    'L 9080 db.internal:5432',
    'l 9080 db.internal:5432',
    '-L 9080 db.internal:5432',
    '-L 9080:db.internal:5432',
    '-L9080:db.internal:5432',
    '-L 9080 db.internal 5432',
    'ssh -L 9080:db.internal:5432',
    'ssh -L 9080 db.internal:5432',
    '--local-forward 9080:db.internal:5432',
    '9080:db.internal:5432',
  ]) {
    const r = parseForwardLine(line);
    assert.ok(r.ok, `parseForwardLine(${JSON.stringify(line)}) refused: ${r.error}`);
    assert.deepEqual(r.draft, LOCAL, line);
  }
});

test('a bind prefix is the LAN choice, not part of the port', () => {
  for (const line of ['L 0.0.0.0:9080:db.internal:5432', '-L *:9080:db.internal:5432', '-L 0.0.0.0 9080 db.internal:5432']) {
    const r = parseForwardLine(line);
    assert.ok(r.ok, `${line}: ${r.error}`);
    assert.equal(r.draft.bind, 'lan', line);
    assert.equal(r.draft.localPort, '9080', line);
    assert.equal(r.draft.remoteHost, 'db.internal', line);
  }
});

test('a dynamic forward is a port, with or without the host it listens on', () => {
  for (const line of ['D 1080', '-D 1080', 'ssh -D 1080', '--dynamic-forward 1080', '-D localhost:1080']) {
    const r = parseForwardLine(line);
    assert.ok(r.ok, `${line}: ${r.error}`);
    assert.equal(r.draft.kind, 'dynamic', line);
    assert.equal(r.draft.localPort, '1080', line);
    assert.equal(r.draft.remoteHost, '', line);
  }
});

test('a reverse forward names the server port and the local service', () => {
  const want = { kind: 'remote', bind: 'local', name: '', localPort: '80', remoteHost: '', remotePort: '2222' };
  for (const line of ['R 2222 localhost:80', '-R 2222:localhost:80', 'ssh -R 2222 127.0.0.1:80', '-R 2222:localhost:80']) {
    const r = parseForwardLine(line);
    assert.ok(r.ok, `${line}: ${r.error}`);
    assert.deepEqual(r.draft, want, line);
  }
  // The wildcard prefix is PuTTY's "remote ports do the same".
  const all = parseForwardLine('-R *:2222:localhost:80');
  assert.ok(all.ok, all.error);
  assert.equal(all.draft.bind, 'lan');
});

test('a reverse forward that ends on another machine is refused, not rerouted', () => {
  const r = parseForwardLine('-R 2222:10.0.0.9:80');
  assert.equal(r.ok, false);
  assert.match(r.error, /ends on this machine/);
});

test('a line that is not a forward says what is wrong instead of being guessed', () => {
  const cases = [
    ['L 9080 db.internal', /expected source port/],
    ['L abc db.internal:5432', /local port is not a number/],
    ['L 9080 db.internal:port', /destination port is not a number/],
    ['D', /no port/],
    ['D 1080 extra', /no port/],
    ['D 1080 extra more', /dynamic forward is just a port/],
    ['L 1.2.3.4:9080:db:5432', /bind address must be/],
  ];
  for (const [line, re] of cases) {
    const r = parseForwardLine(line);
    assert.equal(r.ok, false, `parseForwardLine(${JSON.stringify(line)}) should refuse`);
    assert.match(r.error, re, line);
  }
});

test('blank lines and notes are skipped, not refused', () => {
  for (const line of ['', '   ', '# the database', '// note']) {
    assert.deepEqual(parseForwardLine(line), { skip: true }, JSON.stringify(line));
  }
});

test('parseForwardLines keeps the line numbers of what it took and what it did not', () => {
  const text = '# db box\nL 9080 db.internal:5432\n\nD 1080\nnonsense here';
  const { drafts, errors } = parseForwardLines(text);
  assert.deepEqual(drafts.map((d) => d.line), [2, 4]);
  assert.deepEqual(drafts.map((d) => d.draft.kind), ['local', 'dynamic']);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 5);
  assert.match(errors[0].error, /nonsense here/);
});

// The parser reads the shape; the row rules decide whether the forward could
// work. A pasted line with a port in the host box must fail that second gate.
test('a well-shaped line still has to pass the row rules', () => {
  const r = parseForwardLine('L 9080 442:80');
  assert.ok(r.ok, r.error);
  const p = draftProblem(r.draft);
  assert.equal(p.field, 'remoteHost');
  assert.match(p.msg, /looks like a port/);
});
