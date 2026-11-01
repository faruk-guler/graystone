// What a transfer row says and which buttons it offers, decided from the item
// alone. renderQueue keeps the DOM half; this half is what can be tested without
// a browser, and it is the half that goes wrong when a new status appears in the
// backend (an unknown status used to fall through to a row with no buttons at
// all).

export function queueStatusText(it) {
  switch (it.status) {
    case 'Completed': return 'done \u00b7 ' + it.total;
    case 'Transferring': return it.progress + '% \u00b7 ' + it.speed + ' \u00b7 ETA ' + it.eta;
    case 'Failed': return 'error: ' + (it.error || '');
    // A skipped row carries its reason where a failure would carry an error: the
    // file is fine, the queue was told to leave it alone (a link, or the policy).
    case 'Skipped': return 'skipped \u00b7 ' + (it.error || '');
    default: return it.status + ' \u00b7 ' + it.transferred + '/' + it.total;
  }
}

// A finished row is full regardless of the last progress tick it was sent with,
// so the bar does not stop at 99% on a file that arrived. A skipped row is
// finished too - it just never started moving.
export function queueBarPct(it) {
  return (it.status === 'Completed' || it.status === 'Skipped') ? 100 : it.progress;
}

export function queueBarIsError(it) {
  return it.status === 'Failed' || it.status === 'Cancelled';
}

// queueActions: a paused row is still cancellable, and pause and resume share
// one slot - the row is either moving, or waiting for the user to let it move
// again. Anything finished offers neither.
export function queueActions(it) {
  const moving = it.status === 'Transferring' || it.status === 'Pending';
  return {
    cancel: moving || it.status === 'Paused',
    toggle: it.status === 'Paused' ? 'resume' : (moving ? 'pause' : ''),
  };
}

// batchSummaries groups the rows by the batch that queued them and answers with
// one entry per batch whose every row has settled. That is what lets a folder copy
// end with "12 copied, 2 skipped, 1 failed" instead of leaving the user to count
// rows in a list that scrolls.
//
// A batch of a single row is not summarised: the row already says it, and one
// dropped file does not need a headline. Rows with no batch (a lone upload) are
// left out entirely.
export function batchSummaries(items) {
  const groups = new Map();
  (Array.isArray(items) ? items : []).forEach((it) => {
    const id = it && it.batch ? it.batch : 0;
    if (!id) return;
    let g = groups.get(id);
    if (!g) {
      g = { batch: id, label: it.batchLabel || ('batch ' + id), done: 0, skipped: 0, failed: 0, cancelled: 0, moving: 0, total: 0 };
      groups.set(id, g);
    }
    g.total++;
    switch (it.status) {
      case 'Completed': g.done++; break;
      case 'Skipped': g.skipped++; break;
      case 'Failed': g.failed++; break;
      case 'Cancelled': g.cancelled++; break;
      // Pending, Transferring, Paused - the group has not finished yet.
      default: g.moving++;
    }
  });
  const out = [];
  groups.forEach((g) => { if (!g.moving && g.total > 1) out.push(g); });
  // Oldest first, so the list - which shows newest rows on top - can reverse it
  // and keep each summary next to the rows it describes.
  return out.sort((a, b) => a.batch - b.batch);
}

// batchSummaryText is the one line the queue and the log both show.
export function batchSummaryText(g) {
  if (!g) return '';
  const parts = [g.done + ' copied'];
  if (g.skipped) parts.push(g.skipped + ' skipped');
  if (g.failed) parts.push(g.failed + ' failed');
  if (g.cancelled) parts.push(g.cancelled + ' cancelled');
  return g.label + ': ' + parts.join(', ');
}
