// clampInt is the one rule behind every size bound in the UI (terminal font,
// file pane width). A value that is not a number - a blank or hand-edited
// localStorage entry, a NaN from a half-finished calculation - becomes the
// fallback; a number outside the allowed range is pulled to the nearest bound,
// because the user was aiming past the edge rather than typing nonsense.
//
// Blank comes out as the fallback and not as the minimum on purpose: Number('')
// and Number(null) are both 0, which would otherwise read as "the user asked for
// the smallest size this control allows".
export function clampInt(value, min, max, fallback) {
  const text = typeof value === 'string' ? value.trim() : value;
  const n = Math.round(Number(text === '' || text === null || text === undefined ? NaN : text));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
