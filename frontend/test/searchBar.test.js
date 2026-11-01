import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  searchState, openSearchBar, closeSearchBar,
  updateSearchTerm, updateSearchCount,
  searchResultText,
} from '../src/searchBar.js';

describe('searchBar', () => {
  beforeEach(() => { closeSearchBar(); });

  it('starts closed', () => {
    assert.equal(searchState.isOpen, false);
    assert.equal(searchState.term, '');
    assert.equal(searchState.count, 0);
  });

  it('openSearchBar sets isOpen', () => {
    openSearchBar();
    assert.equal(searchState.isOpen, true);
  });

  it('closeSearchBar resets all fields', () => {
    openSearchBar();
    updateSearchTerm('grep');
    updateSearchCount(7);
    closeSearchBar();
    assert.equal(searchState.isOpen, false);
    assert.equal(searchState.term, '');
    assert.equal(searchState.count, 0);
  });

  it('updateSearchTerm stores the value and returns it', () => {
    assert.equal(updateSearchTerm('foo'), 'foo');
    assert.equal(searchState.term, 'foo');
  });

  it('updateSearchTerm treats null/undefined as empty string', () => {
    assert.equal(updateSearchTerm(null), '');
    assert.equal(updateSearchTerm(undefined), '');
  });

  it('updateSearchCount stores a non-negative number', () => {
    assert.equal(updateSearchCount(5), 5);
    assert.equal(searchState.count, 5);
  });

  it('updateSearchCount clamps negatives and non-numbers to 0', () => {
    assert.equal(updateSearchCount(-1), 0);
    assert.equal(updateSearchCount('bad'), 0);
    assert.equal(searchState.count, 0);
  });

  it('searchResultText: 0 → no matches', () => {
    assert.equal(searchResultText(0), 'no matches');
  });

  it('searchResultText: 1 → 1 match (singular)', () => {
    assert.equal(searchResultText(1), '1 match');
  });

  it('searchResultText: N → N matches (plural)', () => {
    assert.equal(searchResultText(2), '2 matches');
    assert.equal(searchResultText(42), '42 matches');
  });
});
