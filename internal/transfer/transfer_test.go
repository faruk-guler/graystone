package transfer

import (
	"errors"
	"fmt"
	"graystone/internal/sftptest"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// TestQueueLongerThanTheWorkerPoolDrains guards the invariant the worker count
// exists to keep: with two slots and five rows, every row still finishes. A
// single pump would have stalled the queue after the first two, and waitStatus
// fails on timeout, so a stall cannot pass quietly.
func TestQueueLongerThanTheWorkerPoolDrains(t *testing.T) {
	cli, root := sftptest.NewClient(t)
	q := NewTransferQueue(cli, 2)

	local := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(local, pattern(64*1024), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var ids []int
	for i := 0; i < 5; i++ {
		ids = append(ids, q.AddUpload(local, fmt.Sprintf("%s/up-%d.bin", root, i)).ID)
	}
	for _, id := range ids {
		waitStatus(t, q, id, StatusCompleted)
	}
	for i := range ids {
		if got := snapshotOf(t, q, ids[i]); got.Status != StatusCompleted {
			t.Fatalf("row %d ended as %s", ids[i], got.Status)
		}
	}
}

func TestQueueState(t *testing.T) {
	// Initialize with nil client to test queue logic only
	q := NewTransferQueue(nil, 2)

	if len(q.GetItems()) != 0 {
		t.Error("Queue should be empty")
	}

	// Add an item
	item := q.AddUpload("local", "remote")

	// Since client is nil, processNext should return early or fail gracefully without processing
	// In the current implementation, processNext checks `q.client == nil` and returns.
	// So the item should remain in StatusPending.
	if item.Status != StatusPending {
		t.Errorf("Expected pending, got %s", item.Status)
	}

	if len(q.GetItems()) != 1 {
		t.Errorf("Expected 1 item, got %d", len(q.GetItems()))
	}

	// Test cancellation
	q.CancelItem(item.ID)
	// CancelItem finds the item and sets status to Cancelled
	if item.Status != StatusCancelled {
		t.Errorf("Expected cancelled, got %s", item.Status)
	}
}

// These regression tests guard the queue's cancel path and its progress
// bookkeeping, both of which the UI touches concurrently: the Logs/queue poll
// reads every item while a transfer goroutine is still writing its counters.

// TestCancelRunningItemIsIdempotent guards the double close. A running item's
// cancel channel is closed to signal the pump, so a second click - or the poll
// re-rendering the row and the user clicking again - must not close it twice.
func TestCancelRunningItemIsIdempotent(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddUpload("local", "remote")

	q.mu.Lock()
	item.Status = StatusInProgress
	q.mu.Unlock()

	q.CancelItem(item.ID)
	q.CancelItem(item.ID) // must not panic

	select {
	case <-item.cancel:
	default:
		t.Error("running item was not signalled to stop")
	}
}

// TestCancellingAFinishedItemKeepsItsStatus: a row that already completed must
// not be rewritten to "Cancelled" by a late click on a stale listing.
func TestCancellingAFinishedItemKeepsItsStatus(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddUpload("local", "remote")

	q.mu.Lock()
	item.Status = StatusCompleted
	q.mu.Unlock()

	q.CancelItem(item.ID)

	if item.Status != StatusCompleted {
		t.Errorf("completed item was overwritten with %s", item.Status)
	}
}

// TestCancelledTransferIsNotReportedFailed: the pump returns a "cancelled"
// error as soon as it sees the signal. That is the user's own action, so the
// row has to keep reading Cancelled instead of an alarming error line.
func TestCancelledTransferIsNotReportedFailed(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	q.mu.Lock()
	item.Status = StatusInProgress
	q.mu.Unlock()

	q.CancelItem(item.ID)
	q.finish(item, errors.New("cancelled"))

	if item.Status != StatusCancelled {
		t.Fatalf("status = %s, want Cancelled", item.Status)
	}
	if item.ErrorMsg != "" {
		t.Errorf("a cancel is not a failure, but ErrorMsg = %q", item.ErrorMsg)
	}
	if item.EndTime == "" {
		t.Error("finish should still stamp the end time")
	}
}

// TestFailedTransferStillReportsTheError keeps the other side of that switch.
func TestFailedTransferStillReportsTheError(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddUpload("local", "remote")

	q.mu.Lock()
	item.Status = StatusInProgress
	q.mu.Unlock()

	q.finish(item, errors.New("read: connection reset"))

	if item.Status != StatusFailed {
		t.Fatalf("status = %s, want Failed", item.Status)
	}
	if item.ErrorMsg == "" {
		t.Error("a real failure must carry its message to the queue row")
	}
}

// TestGetItemsReturnsSnapshots: handing out the live pointers meant a poll
// could read an item while its transfer goroutine was mid-update. Callers get
// copies, so later mutations cannot rewrite an already rendered row.
func TestGetItemsReturnsSnapshots(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddUpload("local", "remote")

	snap := q.GetItems()[0]
	if snap == item {
		t.Fatal("GetItems must not hand out the live item")
	}
	q.setTotal(item, 1000)
	q.addProgress(item, 250)

	if snap.TotalBytes != 0 || snap.TransferBytes != 0 {
		t.Errorf("snapshot changed after it was taken: %+v", snap)
	}
	latest := q.GetItems()[0]
	if latest.Progress() != 25 {
		t.Errorf("progress = %d, want 25", latest.Progress())
	}
}

// TestConcurrentProgressAndPolling is the shape of the real workload: the UI
// polls every item while a transfer advances its counters. Run under -race it
// fails if either side ever touches an item outside the queue lock.
func TestConcurrentProgressAndPolling(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddUpload("local", "remote")
	q.setTotal(item, 32*1024*1024)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			q.addProgress(item, 4096)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			for _, it := range q.GetItems() {
				_ = it.Progress()
				_ = it.Speed(time.Time{})
				_ = it.ETA(time.Time{})
			}
		}
	}()
	wg.Wait()

	if got := q.GetItems()[0].TransferBytes; got != 2000*4096 {
		t.Errorf("transferred %d bytes, want %d", got, 2000*4096)
	}
}

// ---------- transient-failure retry ----------

// withFastRetry shortens the retry budgets for one test and puts them back.
func withFastRetry(t *testing.T) {
	t.Helper()
	origRetries, origBackoff := maxTransferRetries, transferRetryBackoff
	maxTransferRetries, transferRetryBackoff = 3, time.Millisecond
	t.Cleanup(func() { maxTransferRetries, transferRetryBackoff = origRetries, origBackoff })
}

// TestRetryAfterTransientError is the whole point of the retry layer: a link
// blip mid-file used to mark the transfer Failed even though the resume
// machinery can continue from the exact stopped byte. The blip must cost a
// retry, not the file.
func TestRetryAfterTransientError(t *testing.T) {
	withFastRetry(t)
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	var calls atomic.Int32
	fake := func(_ *sftp.Client, it *TransferItem) error {
		n := calls.Add(1)
		if n == 1 {
			return fmt.Errorf("read: connection reset by peer")
		}
		q.addProgress(it, 10)
		return nil
	}
	// retryTransfer is what processNext calls per attempt; the queue client
	// stays nil, so no pump competes with the fake copy.
	if err := q.retryTransfer(item, nil, fake); err != nil {
		t.Fatalf("retryTransfer: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", calls.Load())
	}
}

// TestPermanentErrorIsNotRetried keeps a wrong password from becoming a
// three-try puzzle: permission and missing-file failures are stated once.
func TestPermanentErrorIsNotRetried(t *testing.T) {
	withFastRetry(t)
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	var calls atomic.Int32
	fake := func(*sftp.Client, *TransferItem) error {
		calls.Add(1)
		return fmt.Errorf("permission denied")
	}
	err := q.retryTransfer(item, nil, fake)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want the original failure", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("attempts = %d, want 1 (permanent errors are not retried)", calls.Load())
	}
}

// TestCancelledItemIsNotRetried: a user cancel observed inside the copy loop
// must end the row immediately; sitting through backoff and another attempt
// would fight the click that stopped it.
func TestCancelledItemIsNotRetried(t *testing.T) {
	withFastRetry(t)
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	var calls atomic.Int32
	fake := func(*sftp.Client, *TransferItem) error {
		calls.Add(1)
		q.CancelItem(item.ID) // cancel observed during the attempt
		return fmt.Errorf("read: connection reset by peer")
	}
	if err := q.retryTransfer(item, nil, fake); err == nil {
		t.Fatal("expected the transient error to be returned")
	}
	if calls.Load() != 1 {
		t.Fatalf("attempts = %d, want 1 after a cancel", calls.Load())
	}
}

// TestPausedDuringRetryBecomesPaused: a pause that lands while the retry is
// sleeping converts the whole row to Paused at its saved offset, reusing the
// pause/resume semantics instead of failing and deleting the partial.
func TestPausedDuringRetryBecomesPaused(t *testing.T) {
	withFastRetry(t)
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	fake := func(*sftp.Client, *TransferItem) error {
		if q.bytesDone(item) == 0 {
			q.PauseItem(item.ID)
		}
		return fmt.Errorf("read: connection reset by peer")
	}
	if err := q.retryTransfer(item, nil, fake); !errors.Is(err, errPaused) {
		t.Fatalf("err = %v, want errPaused", err)
	}
}

// TestExhaustedRetriesReportAttempts bounds the loop's footprint: the failure
// that finally sticks carries the original message plus how often it tried, so
// the queue row tells the user the retry really happened.
func TestExhaustedRetriesReportAttempts(t *testing.T) {
	withFastRetry(t)
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	var calls atomic.Int32
	fake := func(*sftp.Client, *TransferItem) error {
		calls.Add(1)
		return fmt.Errorf("read: connection reset by peer")
	}
	err := q.retryTransfer(item, nil, fake)
	if err == nil || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("err = %v, want the attempt count reported", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", calls.Load())
	}
}

// TestIsTransientClassification pins the classifier both halves depend on.
func TestIsTransientClassification(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	item := q.AddDownload("/remote/file", "local")

	transient := []error{
		errors.New("read: connection reset by peer"),
		errors.New("write: ssh: channel closed"),
		fmt.Errorf("read: %w", errTimeoutLike{}),
		fmt.Errorf("read: %w", io.ErrUnexpectedEOF),
	}
	for _, err := range transient {
		if !isTransient(item, err) {
			t.Errorf("%v should be transient", err)
		}
	}

	permanent := []error{
		errors.New("permission denied"),
		errors.New("file does not exist"),
		errors.New("no space left on device"),
		fmt.Errorf("cancelled"),
		errPaused,
		nil,
	}
	for _, err := range permanent {
		if isTransient(item, err) {
			t.Errorf("%v must not be transient", err)
		}
	}

	// A cancelled row is never retried, whatever the error text says.
	q.CancelItem(item.ID)
	if isTransient(item, errors.New("read: connection reset by peer")) {
		t.Error("a cancelled item must not be classified transient")
	}
}

type errTimeoutLike struct{}

func (errTimeoutLike) Error() string   { return "i/o timeout" }
func (errTimeoutLike) Timeout() bool   { return true }
func (errTimeoutLike) Temporary() bool { return true }

// ---------- progress callback ----------

// TestProgressRingsThrottled: two state changes inside one cadence window are
// one ring, not two - the point of the callback is to replace the UI poll, not
// to out-shout it.
func TestProgressRingsThrottled(t *testing.T) {
	origCadence, origRetries, origBackoff := progressCadence, maxTransferRetries, transferRetryBackoff
	progressCadence, maxTransferRetries, transferRetryBackoff = 50*time.Millisecond, 1, time.Millisecond
	t.Cleanup(func() {
		progressCadence, maxTransferRetries, transferRetryBackoff = origCadence, origRetries, origBackoff
	})

	q := NewTransferQueue(nil, 1)
	var rings atomic.Int32
	q.SetOnProgress(func() { rings.Add(1) })

	item := q.AddDownload("/remote/file", "local")
	// One ring for the transition into InProgress; the copy then holds the
	// attempt open well past the window so a second ring can only be the
	// forced one from finish.
	if err := q.retryTransfer(item, nil, func(*sftp.Client, *TransferItem) error {
		q.notifyProgress()
		time.Sleep(60 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatalf("retryTransfer: %v", err)
	}
	q.finish(item, nil)
	if got := rings.Load(); got != 2 {
		t.Fatalf("rings = %d, want 2 (start + forced finish)", got)
	}
}

// TestFinalStateRingsEvenInsideWindow is the forced-finish rule: a file that
// completes 1 ms after its start ring must still reach the UI, or the row sits
// on "Transferring" until an unrelated event repaints it.
func TestFinalStateRingsEvenInsideWindow(t *testing.T) {
	origCadence := progressCadence
	progressCadence = time.Hour
	t.Cleanup(func() { progressCadence = origCadence })

	q := NewTransferQueue(nil, 1)
	var rings atomic.Int32
	q.SetOnProgress(func() { rings.Add(1) })

	item := q.AddDownload("/remote/file", "local")
	q.notifyProgress() // pretend a start ring just happened
	q.finish(item, nil)

	if rings.Load() != 2 {
		t.Fatalf("rings = %d, want the finish to bypass a wide-open cadence window", rings.Load())
	}
	if q.GetItems()[0].Status != StatusCompleted {
		t.Fatal("item should have completed")
	}
}

// TestProgressCallbackRunsOutsideLock keeps the ring honest: a callback that
// reads the queue (the app's does, through GetItems) must not deadlock the
// pump that fired it.
func TestProgressCallbackRunsOutsideLock(t *testing.T) {
	origCadence := progressCadence
	progressCadence = 0
	t.Cleanup(func() { progressCadence = origCadence })

	q := NewTransferQueue(nil, 1)
	done := make(chan struct{})
	q.SetOnProgress(func() {
		defer close(done)
		for _, it := range q.GetItems() { // re-enters the very lock the ring holds
			_ = it.Status
		}
	})
	item := q.AddDownload("/remote/file", "local")
	q.notifyProgress()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("progress callback deadlocked (item %+v)", q.GetItems()[0])
	}
	_ = item
}

// ---------- transfer conflict policy ----------

func TestParsePolicy(t *testing.T) {
	cases := map[string]ConflictPolicy{
		"overwrite": Overwrite, "": Overwrite, "garbage": Overwrite,
		"rename": Rename, "RENAME": Rename, " skip ": Skip,
	}
	for in, want := range cases {
		if got := ParsePolicy(in); got != want {
			t.Errorf("ParsePolicy(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSplitExt(t *testing.T) {
	cases := []struct{ name, stem, ext string }{
		{"report.txt", "report", ".txt"},
		{"archive.tar.gz", "archive.tar", ".gz"},
		{"Makefile", "Makefile", ""},
		{".hidden", ".hidden", ""}, // leading dot is not an extension boundary
	}
	for _, c := range cases {
		stem, ext := SplitExt(c.name)
		if stem != c.stem || ext != c.ext {
			t.Errorf("SplitExt(%q) = (%q,%q), want (%q,%q)", c.name, stem, ext, c.stem, c.ext)
		}
	}
}

// TestUniqueLocalPathWalksTheCounter proves the rename chain skips taken names
// and keeps the extension: file.txt -> file (1).txt -> file (2).txt. Paths are
// built with filepath so the expectation matches the OS separator the function
// itself uses.
func TestUniqueLocalPathWalksTheCounter(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator), "d")
	taken := map[string]bool{
		filepath.Join(dir, "report.txt"):     true,
		filepath.Join(dir, "report (1).txt"): true,
	}
	exists := func(p string) bool { return taken[p] }
	if got, want := UniqueLocalPath(filepath.Join(dir, "report.txt"), exists), filepath.Join(dir, "report (2).txt"); got != want {
		t.Fatalf("UniqueLocalPath = %q, want %q", got, want)
	}
	// A free path is returned untouched.
	if got, want := UniqueLocalPath(filepath.Join(dir, "free.txt"), exists), filepath.Join(dir, "free.txt"); got != want {
		t.Fatalf("unused path changed: %q", got)
	}
}

func TestLocalDestDecision(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "here.txt")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	absent := filepath.Join(dir, "gone.txt")

	// Skip drops only an existing destination.
	if _, ok := LocalDestDecision(existing, Skip); ok {
		t.Fatal("Skip must not queue over an existing file")
	}
	if p, ok := LocalDestDecision(absent, Skip); !ok || p != absent {
		t.Fatalf("Skip of an absent path changed it: %q ok=%v", p, ok)
	}
	// Rename moves off the taken name to a fresh sibling.
	p, ok := LocalDestDecision(existing, Rename)
	if !ok || p == existing {
		t.Fatalf("Rename kept the taken path: %q ok=%v", p, ok)
	}
	if filepath.Base(p) != "here (1).txt" {
		t.Fatalf("Rename produced %q, want 'here (1).txt'", filepath.Base(p))
	}
	// Overwrite is a no-op on the path.
	if p, ok := LocalDestDecision(existing, Overwrite); !ok || p != existing {
		t.Fatalf("Overwrite altered the destination: %q ok=%v", p, ok)
	}
}

func TestUniqueRemotePathUsesSlashes(t *testing.T) {
	taken := map[string]bool{"/remote/a.txt": true}
	exists := func(p string) bool { return taken[p] }
	if got, want := UniqueRemotePath("/remote/a.txt", exists), "/remote/a (1).txt"; got != want {
		t.Fatalf("UniqueRemotePath = %q, want %q", got, want)
	}
}
