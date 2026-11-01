// Frontend regression tests - run with `npm test` in the frontend folder
// (or `node --test test/`). These cover src/utils.js, the part of the UI logic
// that needs no browser, no xterm and no Wails bindings.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_PORT, MAX_PORT, MIN_PORT, fmtSize, joinWrappedRows, logicalLine, osc7Path, parentPath, parsePort, stripPrompt } from '../src/utils.js';

test('fmtSize reaches GB instead of piling up megabytes', () => {
  assert.equal(fmtSize(0), '0B');
  assert.equal(fmtSize(512), '512B');
  assert.equal(fmtSize(1024), '1.0KB');
  assert.equal(fmtSize(1536), '1.5KB');
  assert.equal(fmtSize(1048576), '1.0MB');
  // The bug this file was extracted for: 1 GB used to read "1024.0MB".
  assert.equal(fmtSize(1073741824), '1.00GB');
  assert.equal(fmtSize(4 * 1073741824), '4.00GB');
});

test('fmtSize renders an unusable size as a dash, never NaN', () => {
  for (const bad of [NaN, undefined, null, Infinity, -Infinity, 'x']) {
    assert.equal(fmtSize(bad), '-', `fmtSize(${String(bad)})`);
  }
});

test('parsePort accepts a whole port and keeps the blank default', () => {
  assert.equal(parsePort('', DEFAULT_PORT), 22);
  assert.equal(parsePort('   ', DEFAULT_PORT), 22);
  assert.equal(parsePort(undefined, DEFAULT_PORT), 22);
  assert.equal(parsePort(null, DEFAULT_PORT), 22);
  assert.equal(parsePort('22'), 22);
  assert.equal(parsePort(' 8080 '), 8080);
  assert.equal(parsePort(8080), 8080);
  assert.equal(parsePort(String(MIN_PORT)), MIN_PORT);
  assert.equal(parsePort(String(MAX_PORT)), MAX_PORT);
});

test('parsePort refuses what the backend cannot bind', () => {
  // Blank with no fallback is a required field left empty.
  assert.equal(parsePort(''), null);
  assert.equal(parsePort('', 0), null);
  for (const bad of ['0', '-1', '65536', '22.5', '2e3', 'abc', '80 80', '+22', '0x10']) {
    assert.equal(parsePort(bad, DEFAULT_PORT), null, `parsePort(${bad})`);
  }
});

test('osc7Path turns a report into a path', () => {
  assert.equal(osc7Path('file://host/var/log'), '/var/log');
  assert.equal(osc7Path('file:///etc'), '/etc');
  assert.equal(osc7Path('file://host/'), '/');
  assert.equal(osc7Path('file://host/home/user/my%20dir'), '/home/user/my dir');
});

test('osc7Path leaves the pane alone on anything else', () => {
  for (const bad of ['', undefined, null, 'nonsense', 'file://', 'http://host/x']) {
    assert.equal(osc7Path(bad), '', `osc7Path(${String(bad)})`);
  }
  // A broken escape must not throw; the raw text is the honest answer.
  assert.equal(osc7Path('file://host/a%zz'), '/a%zz');
});

test('stripPrompt cuts the shell terminator and everything before it', () => {
  assert.equal(stripPrompt('user@host:~$ ls -l'), 'ls -l');
  assert.equal(stripPrompt('root@host:/tmp# cd /var'), 'cd /var');
  assert.equal(stripPrompt('12345 % fg'), 'fg');
  assert.equal(stripPrompt('x# one $ two'), 'two');
});

test('stripPrompt keeps a line with no prompt intact', () => {
  assert.equal(stripPrompt('cd /tmp'), 'cd /tmp');
  assert.equal(stripPrompt(''), '');
  assert.equal(stripPrompt(undefined), '');
});

test('parentPath walks up without escaping the root', () => {
  assert.equal(parentPath('/var/log'), '/var');
  assert.equal(parentPath('/a/b/c//'), '/a/b');
  assert.equal(parentPath('/var'), '/');
  assert.equal(parentPath('/'), '/');
  assert.equal(parentPath(''), '/');
  assert.equal(parentPath(undefined), '/');
});

// The follow bug these cover: a cd whose path is longer than the terminal width
// is echoed over several rows, the prompt sits on the first one only and the
// cursor ends on the last, so the command can only be recovered by stitching.
test('joinWrappedRows stitches a deep path back from the rows it wrapped over', () => {
  const deep = '$ cd /etc/esd/sdsdsd/sdsdsd/s/sds/ds/ds/ds/ds/ds/dsds/d/sd/sd/sd/sd/sd/sd/sd/sd';
  const rows = [
    { text: deep.slice(0, 40), isWrapped: false },
    { text: deep.slice(40, 80), isWrapped: true },
    { text: deep.slice(80), isWrapped: true },
  ];
  assert.equal(joinWrappedRows(rows), deep);
  assert.equal(stripPrompt(joinWrappedRows(rows)), 'cd /etc/esd/sdsdsd/sdsdsd/s/sds/ds/ds/ds/ds/ds/dsds/d/sd/sd/sd/sd/sd/sd/sd/sd');
});

test('joinWrappedRows keeps the space a line broke on', () => {
  // A wrap that landed on a space must not weld the two halves together.
  const rows = [
    { text: '$ cd /very/long/path ', isWrapped: false },
    { text: '/deeper/dir', isWrapped: true },
  ];
  assert.equal(joinWrappedRows(rows), '$ cd /very/long/path /deeper/dir');
});

test('joinWrappedRows drops the rows of an earlier line', () => {
  const rows = [
    { text: 'output of the previous command', isWrapped: false },
    { text: '$ cd /a', isWrapped: false },
    { text: '/b', isWrapped: true },
  ];
  assert.equal(joinWrappedRows(rows), '$ cd /a/b');
});

test('joinWrappedRows handles a plain single row and an empty buffer', () => {
  assert.equal(joinWrappedRows([{ text: '$ ls -l   ', isWrapped: false }]), '$ ls -l');
  assert.equal(joinWrappedRows([]), '');
  assert.equal(joinWrappedRows(undefined), '');
  assert.equal(joinWrappedRows([null, { text: '$ cd /tmp', isWrapped: true }]), '$ cd /tmp');
});

// logicalLine is the walk over the buffer that the follow feature depends on:
// it decides which rows belong to the command the cursor sits on.
test('logicalLine walks up from the cursor across the rows one command spans', () => {
  const line = 'user@host:/tmp$ cd /etc/esd/sdsdsd/sdsdsd/s/sds/ds/ds/ds/ds/ds/dsds/d/sd/sd/sd/sd/sd/sd/sd/sd';
  const rows = [
    { text: line.slice(0, 44), isWrapped: false },
    { text: line.slice(44), isWrapped: true },
  ];
  const read = (r) => rows[r] || null;
  assert.equal(logicalLine(read, 1), line);
  // The same command while it still fits on one row is just that row.
  assert.equal(logicalLine(read, 0), line.slice(0, 44));
});

test('logicalLine stops at the row that starts a line of its own', () => {
  const rows = [
    { text: 'output of the command before', isWrapped: false },
    { text: 'user@host:~$ cd ', isWrapped: false },
    { text: '/var/log', isWrapped: true },
  ];
  assert.equal(logicalLine((r) => rows[r] || null, 2), 'user@host:~$ cd /var/log');
});

test('logicalLine bounds the walk and takes a missing row as the top', () => {
  // Every row claims to continue another: only the limit stops the scan.
  assert.equal(logicalLine(() => ({ text: 'x', isWrapped: true }), 500, 4).length, 5);
  // A buffer that has nothing above the cursor row yields the cursor row alone.
  assert.equal(logicalLine((r) => (r === 7 ? { text: '$ cd /tmp', isWrapped: false } : null), 7), '$ cd /tmp');
  assert.equal(logicalLine(null, 3), '');
  assert.equal(logicalLine(() => ({ text: 'x', isWrapped: false }), 'nope'), '');
});
