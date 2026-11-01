// Permission-mode maths, kept out of the DOM so it can be tested and so the
// octal rule lives in exactly one place.

// The same grid the permissions dialog builds: three owners, three bits each.
export const PERM_ROWS = [['Owner', 6], ['Group', 3], ['World', 0]];
export const PERM_BITS = [['r', 4], ['w', 2], ['x', 1]];

// parseOctal reads what the octal box holds: 1-4 digits, anything else is not a
// mode yet. The 4-digit allowance and the 0777 mask match the backend's
// parsePermOctal - a half-typed or out-of-range value returns null so the caller
// can leave the grid alone instead of jumping to a different mode.
export function parseOctal(s) {
  const t = String(s == null ? '' : s).trim().replace(/^0+(?=.)/, '');
  if (!/^[0-7]{1,4}$/.test(t)) return null;
  return parseInt(t, 8) & 0o777;
}

// octalText is how a mode is shown and compared: always three digits, so "644"
// and "0644" are the same string and an unchanged mode never looks edited.
export function octalText(mode) {
  return (mode & 0o777).toString(8).padStart(3, '0');
}

export function bitOn(mode, bit, shift) {
  return (mode & (bit << shift)) !== 0;
}

// modeFromFlags folds the checkbox state back into a mode. Each entry is
// { bit, shift, on } in whatever order the DOM reported them.
export function modeFromFlags(flags) {
  let m = 0;
  for (const f of flags) {
    if (f.on) m |= (Number(f.bit) << Number(f.shift));
  }
  return m & 0o777;
}
