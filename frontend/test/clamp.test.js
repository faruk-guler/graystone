// Size bounds - run with `npm test` in the frontend folder. The terminal font and
// the file pane width both go through clampInt, and both used to be able to
// store "NaN" in localStorage from a bad input.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { clampInt } from '../src/clamp.js';

const FONT = { min: 10, max: 30, dflt: 14 };
const PANE = { min: 320, max: 900, dflt: 720 };

test('clampInt keeps an in-range value', () => {
  assert.equal(clampInt(14, FONT.min, FONT.max, FONT.dflt), 14);
  assert.equal(clampInt('14', FONT.min, FONT.max, FONT.dflt), 14);
  assert.equal(clampInt(14.4, FONT.min, FONT.max, FONT.dflt), 14);
  assert.equal(clampInt(14.6, FONT.min, FONT.max, FONT.dflt), 15);
});

test('clampInt pulls an out-of-range size to the nearest bound', () => {
  assert.equal(clampInt(2, FONT.min, FONT.max, FONT.dflt), 10);
  assert.equal(clampInt(999, FONT.min, FONT.max, FONT.dflt), 30);
  assert.equal(clampInt(2000, PANE.min, PANE.max, PANE.dflt), 900);
  assert.equal(clampInt(100, PANE.min, PANE.max, PANE.dflt), 320);
  assert.equal(clampInt(0, PANE.min, PANE.max, PANE.dflt), 320);
});

test('clampInt falls back instead of storing nonsense', () => {
  for (const bad of [NaN, undefined, null, '', 'abc', Infinity, -Infinity, {}]) {
    assert.equal(clampInt(bad, FONT.min, FONT.max, FONT.dflt), FONT.dflt, `clampInt(${String(bad)})`);
  }
});

test('the bounds the UI advertises are the bounds the code uses', () => {
  // Settings shows "10-30 px" for the font; a stored 8 (from an older build)
  // must land on the legal floor rather than the default, and a stored 40 on the
  // ceiling, so the slider position matches what the terminal renders.
  assert.equal(clampInt(8, FONT.min, FONT.max, FONT.dflt), 10);
  assert.equal(clampInt(40, FONT.min, FONT.max, FONT.dflt), 30);
});
