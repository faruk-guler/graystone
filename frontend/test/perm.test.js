// Permission-mode rules - run with `npm test` in the frontend folder.
// These are the rules the chmod dialog runs on; the backend has its own copy
// (parsePermOctal in app.go), and keeping both honest is the point of this file.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { bitOn, modeFromFlags, octalText, parseOctal } from '../src/perm.js';

test('parseOctal reads the modes people type', () => {
  assert.equal(parseOctal('644'), 0o644);
  assert.equal(parseOctal('777'), 0o777);
  assert.equal(parseOctal('0'), 0);
  assert.equal(parseOctal(' 600 '), 0o600);
  // A leading zero is a prefix, not a digit that changes the value.
  assert.equal(parseOctal('0644'), 0o644);
  // The backend accepts four digits, so the dialog must not reject "0755" and
  // then silently do nothing with it.
  assert.equal(parseOctal('0755'), 0o755);
});

test('parseOctal refuses what is not a mode yet', () => {
  for (const bad of ['', '   ', '8', '99', '64x', '12345', null, undefined, NaN, '6 4 4']) {
    assert.equal(parseOctal(bad), null, `parseOctal(${String(bad)})`);
  }
});

test('parseOctal keeps only the bits a mode can carry', () => {
  // 7777 is four octal digits, and the backend masks it to 0777: the grid must
  // show the same result the server will store.
  assert.equal(parseOctal('7777'), 0o777);
  assert.equal(parseOctal('1700'), 0o700);
});

test('octalText always renders three digits so an unchanged mode compares equal', () => {
  assert.equal(octalText(0o644), '644');
  assert.equal(octalText(0), '000');
  assert.equal(octalText(0o777), '777');
  assert.equal(octalText(parseOctal('0755')), '755');
  // The dialog compares this string against the mode it loaded, so a value the
  // user did not change must not look edited.
  assert.equal(octalText(0o644), '644');
});

test('parseOctal and octalText round-trip every mode', () => {
  for (let m = 0; m <= 0o777; m++) {
    assert.equal(parseOctal(octalText(m)), m, octalText(m));
  }
});

test('bitOn reads one owner class out of a mode', () => {
  // 0644 = owner rw-, group r--, world r--.
  assert.equal(bitOn(0o644, 4, 6), true);   // owner r
  assert.equal(bitOn(0o644, 2, 6), true);   // owner w
  assert.equal(bitOn(0o644, 1, 6), false);  // owner x
  assert.equal(bitOn(0o644, 4, 3), true);   // group r
  assert.equal(bitOn(0o644, 2, 3), false);  // group w
  assert.equal(bitOn(0o644, 1, 3), false);  // group x
  assert.equal(bitOn(0o644, 4, 0), true);   // world r
  assert.equal(bitOn(0o644, 2, 0), false);  // world w
  assert.equal(bitOn(0o644, 1, 0), false);  // world x
});

test('modeFromFlags rebuilds the mode the grid shows', () => {
  const flags = [];
  for (const [, shift] of [[0, 6], [0, 3], [0, 0]]) {
    for (const [, bit] of [['r', 4], ['w', 2], ['x', 1]]) {
      flags.push({ bit, shift, on: bitOn(0o750, bit, shift) });
    }
  }
  assert.equal(modeFromFlags(flags), 0o750);
  assert.equal(modeFromFlags([]), 0);
});

test('modeFromFlags ignores malformed entries instead of throwing', () => {
  // A checkbox whose dataset is missing arrives as NaN; it must not poison the
  // whole mode.
  assert.equal(modeFromFlags([{ bit: 4, shift: 6, on: true }, { bit: undefined, shift: undefined, on: true }]), 0o400);
});
