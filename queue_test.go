package main

import (
	"fmt"
	"strings"
	"testing"

	"graystone/internal/transfer"
)

// The queue's skip rows are what makes "N skipped" mean something: a folder that
// left files out has to say so, and say so without burying the list.

func TestAddSkipRowsRecordsEveryReason(t *testing.T) {
	q := transfer.NewTransferQueue(nil, 1)
	q.BeginBatch("Upload folder site")
	addSkipRows(q, transfer.Upload, []skipEntry{
		{path: `C:\site\link.txt`, reason: "symbolic link"},
		{path: `C:\site\secret`, reason: "unreadable"},
	})
	q.EndBatch()

	items := q.GetItems()
	if len(items) != 2 {
		t.Fatalf("got %d rows, want one per skipped path", len(items))
	}
	for i, want := range []struct{ name, reason string }{{"link.txt", "symbolic link"}, {"secret", "unreadable"}} {
		got := items[i]
		if got.Status != transfer.StatusSkipped {
			t.Fatalf("row %d is %s, want Skipped", i, got.Status)
		}
		if got.FileName != want.name {
			t.Fatalf("row %d named %q, want %q", i, got.FileName, want.name)
		}
		if got.ErrorMsg != want.reason {
			t.Fatalf("row %d reason %q, want %q", i, got.ErrorMsg, want.reason)
		}
	}
}

// TestAddSkipRowsCollapsesPastTheLimit keeps a tree of nothing but links honest -
// the count is the whole number - without pushing thousands of rows into a list
// the UI polls every 600ms.
func TestAddSkipRowsCollapsesPastTheLimit(t *testing.T) {
	q := transfer.NewTransferQueue(nil, 1)
	many := make([]skipEntry, skipRowLimit+7)
	for i := range many {
		many[i] = skipEntry{path: fmt.Sprintf(`C:\site\f%04d`, i), reason: "symbolic link"}
	}
	addSkipRows(q, transfer.Download, many)

	items := q.GetItems()
	if len(items) != skipRowLimit+1 {
		t.Fatalf("got %d rows, want the limit (%d) plus one for the rest", len(items), skipRowLimit)
	}
	last := items[len(items)-1]
	if !strings.Contains(last.ErrorMsg, "and 7 more") {
		t.Fatalf("the overflow row must give the remaining count, got %q", last.ErrorMsg)
	}
	// A folder with nothing left out adds nothing: no row, no noise.
	before := len(q.GetItems())
	addSkipRows(q, transfer.Upload, nil)
	if len(q.GetItems()) != before {
		t.Fatal("an empty skip list must not add rows")
	}
}
