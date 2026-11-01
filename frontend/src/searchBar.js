// searchBar.js – DOM-free search state machine.
// Extracted so `node --test` can cover the logic without xterm or the Wails
// bindings. main.js owns the SearchAddon and the bar element; this module
// tracks only what is open, what the user typed, and how many hits resulted.

export const searchState = {
  isOpen: false,
  term: '',
  count: 0,
};

export function openSearchBar() {
  searchState.isOpen = true;
  return true;
}

export function closeSearchBar() {
  searchState.isOpen = false;
  searchState.term = '';
  searchState.count = 0;
  return true;
}

export function updateSearchTerm(t) {
  searchState.term = t || '';
  return searchState.term;
}

export function updateSearchCount(count) {
  searchState.count = typeof count === 'number' && count >= 0 ? count : 0;
  return searchState.count;
}

// searchResultText formats the status string shown beside the search input.
export function searchResultText(count) {
  if (count === 0) return 'no matches';
  if (count === 1) return '1 match';
  return count + ' matches';
}
