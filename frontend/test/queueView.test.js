// Transfer row text and buttons - run with `npm test` in the frontend folder.
// The backend names these statuses in internal/transfer (TransferStatus.String),
// so this is where a renamed or newly added status shows up as a wrong row
// instead of a mystery in the running app.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { batchSummaries, batchSummaryText, queueActions, queueBarIsError, queueBarPct, queueStatusText } from '../src/queueView.js';

const item = (over) => ({
  status: 'Transferring', progress: 42, speed: '1.2MB/s', eta: '0:08',
  transferred: 42 * 1024, total: '100KB', error: '', ...over,
});

test('a moving row shows percent, speed and remaining time', () => {
  assert.equal(queueStatusText(item({})), '42% · 1.2MB/s · ETA 0:08');
});

test('a finished row shows the size that arrived', () => {
  assert.equal(queueStatusText(item({ status: 'Completed' })), 'done · 100KB');
});

test('a failed row shows the reason, never a bare word', () => {
  assert.equal(queueStatusText(item({ status: 'Failed', error: 'connection reset' })), 'error: connection reset');
  assert.equal(queueStatusText(item({ status: 'Failed', error: '' })), 'error: ');
});

test('pending and paused rows show how far they got', () => {
  assert.equal(queueStatusText(item({ status: 'Pending' })), 'Pending · 43008/100KB');
  assert.equal(queueStatusText(item({ status: 'Paused' })), 'Paused · 43008/100KB');
});

test('a completed bar is full even if the last tick said 99', () => {
  assert.equal(queueBarPct(item({ status: 'Completed', progress: 99 })), 100);
  assert.equal(queueBarPct(item({ progress: 42 })), 42);
});

test('only a failed or cancelled row paints the danger bar', () => {
  assert.equal(queueBarIsError(item({ status: 'Failed' })), true);
  assert.equal(queueBarIsError(item({ status: 'Cancelled' })), true);
  assert.equal(queueBarIsError(item({ status: 'Paused' })), false);
  assert.equal(queueBarIsError(item({ status: 'Completed' })), false);
});

test('pause and resume share one slot, and a paused row is still cancellable', () => {
  assert.deepEqual(queueActions(item({ status: 'Transferring' })), { cancel: true, toggle: 'pause' });
  assert.deepEqual(queueActions(item({ status: 'Pending' })), { cancel: true, toggle: 'pause' });
  assert.deepEqual(queueActions(item({ status: 'Paused' })), { cancel: true, toggle: 'resume' });
});

test('a settled row offers no buttons', () => {
  for (const status of ['Completed', 'Failed', 'Cancelled', 'Skipped']) {
    assert.deepEqual(queueActions(item({ status })), { cancel: false, toggle: '' }, status);
  }
});

test('a skipped row names the reason it was left out', () => {
  assert.equal(queueStatusText(item({ status: 'Skipped', error: 'symbolic link' })), 'skipped · symbolic link');
  assert.equal(queueBarPct(item({ status: 'Skipped', progress: 0 })), 100);
  assert.equal(queueBarIsError(item({ status: 'Skipped' })), false);
});

const row = (batch, status, over) => item({ batch, status, ...over });

test('a finished batch is summed once, with its label', () => {
  const items = [
    row(3, 'Completed', { batchLabel: 'Upload folder site' }),
    row(3, 'Completed', { batchLabel: 'Upload folder site' }),
    row(3, 'Completed', { batchLabel: 'Upload folder site' }),
    row(3, 'Skipped', { batchLabel: 'Upload folder site' }),
    row(3, 'Failed', { batchLabel: 'Upload folder site' }),
  ];
  const sums = batchSummaries(items);
  assert.equal(sums.length, 1);
  assert.deepEqual(
    { ...sums[0] },
    { batch: 3, label: 'Upload folder site', done: 3, skipped: 1, failed: 1, cancelled: 0, moving: 0, total: 5 },
  );
  assert.equal(batchSummaryText(sums[0]), 'Upload folder site: 3 copied, 1 skipped, 1 failed');
});

test('a batch is not summarised while any row is still moving', () => {
  for (const status of ['Pending', 'Transferring', 'Paused']) {
    assert.deepEqual(batchSummaries([row(1, 'Completed'), row(1, status)]), [], status);
  }
  // Once the last one settles, the group is reported - including a cancel, which
  // is a result the user should see counted rather than missing.
  const sums = batchSummaries([row(1, 'Completed'), row(1, 'Cancelled')]);
  assert.equal(sums.length, 1);
  assert.equal(batchSummaryText(sums[0]), 'batch 1: 1 copied, 1 cancelled');
});

test('one-row batches and unbatched rows are left alone', () => {
  // A lone upload already says "done" on its own row; a headline would be noise.
  assert.deepEqual(batchSummaries([row(2, 'Completed')]), []);
  assert.deepEqual(batchSummaries([{ status: 'Completed' }, { status: 'Failed' }]), []);
  assert.deepEqual(batchSummaries(null), []);
  assert.equal(batchSummaryText(null), '');
});

test('batches come back oldest first so the newest sits on top of its rows', () => {
  const items = [
    row(1, 'Completed'), row(1, 'Completed'),
    row(2, 'Completed'), row(2, 'Completed'),
    row(3, 'Completed'), row(3, 'Completed'),
  ];
  assert.deepEqual(batchSummaries(items).map((g) => g.batch), [1, 2, 3]);
});
