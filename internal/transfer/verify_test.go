package transfer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gravel/internal/sftptest"
)

// The copy is not finished when the last Write returns; it is finished when the
// far side measures what was sent. These cover that last check - the message it
// produces, and the real transfers it must let through.

func TestVerifySize(t *testing.T) {
	if err := verifySize("remote", 4096, 4096); err != nil {
		t.Fatalf("equal lengths reported an error: %v", err)
	}
	if err := verifySize("remote", 0, 0); err != nil {
		t.Fatalf("an empty file is a match: %v", err)
	}
	err := verifySize("remote", 4000, 4096)
	if err == nil {
		t.Fatal("a short copy must be an error")
	}
	if !strings.Contains(err.Error(), "remote is 4000 bytes, expected 4096") {
		t.Fatalf("message names the side and both lengths, got %q", err.Error())
	}
	// Longer than asked for is just as wrong - a resumed row that appended
	// instead of continuing would otherwise look like a success.
	if err := verifySize("local file", 11, 10); err == nil {
		t.Fatal("a long file must be an error too")
	}
}

// TestUploadCompletesWithMatchingRemoteLength is the regression the check could
// otherwise cause: a good copy must still be reported as Completed, and the file
// on the far side must really be the length the row says it is.
func TestUploadCompletesWithMatchingRemoteLength(t *testing.T) {
	cli, root := sftptest.NewClient(t)
	q := NewTransferQueue(cli, 1)

	local := filepath.Join(t.TempDir(), "payload.bin")
	const size = 300 * 1024 // over several chunks, so a lost tail would show
	if err := os.WriteFile(local, pattern(size), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	remote := fmt.Sprintf("%s/payload.bin", root)
	id := q.AddUpload(local, remote).ID
	waitStatus(t, q, id, StatusCompleted)

	fi, err := cli.Stat(remote)
	if err != nil {
		t.Fatalf("stat remote: %v", err)
	}
	if fi.Size() != size {
		t.Fatalf("remote is %d bytes, want %d", fi.Size(), size)
	}
	if got := snapshotOf(t, q, id); got.TotalBytes != size {
		t.Fatalf("row reports %d total bytes, want %d", got.TotalBytes, size)
	}
}

// TestDownloadCompletesWithMatchingLocalLength is the same guard on the other
// side of the copy, where the expected length comes from the remote Stat.
func TestDownloadCompletesWithMatchingLocalLength(t *testing.T) {
	cli, root := sftptest.NewClient(t)
	remote := fmt.Sprintf("%s/source.bin", root)
	const size = 200 * 1024
	if err := os.WriteFile(remote, pattern(size), 0o600); err != nil {
		t.Fatalf("seed remote: %v", err)
	}
	q := NewTransferQueue(cli, 1)
	dest := filepath.Join(t.TempDir(), "source.bin")
	id := q.AddDownload(remote, dest).ID
	waitStatus(t, q, id, StatusCompleted)

	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat local: %v", err)
	}
	if fi.Size() != size {
		t.Fatalf("local file is %d bytes, want %d", fi.Size(), size)
	}
}

// TestBatchStampsTheRowsItQueues is how the summary finds its rows: everything
// added between BeginBatch and EndBatch carries the group id and answers to its
// label, and anything queued outside a group stays unbatched.
func TestBatchStampsTheRowsItQueues(t *testing.T) {
	q := NewTransferQueue(nil, 1)

	loose := q.AddUpload("a.txt", "/remote/a.txt")
	if loose.Batch != 0 {
		t.Fatalf("a row queued outside a batch must carry no group, got %d", loose.Batch)
	}

	batch := q.BeginBatch("Upload folder docs")
	first := q.AddUpload("b.txt", "/remote/b.txt")
	second := q.AddDownload("/remote/c.txt", "c.txt")
	q.EndBatch()
	after := q.AddUpload("d.txt", "/remote/d.txt")

	if first.Batch != batch || second.Batch != batch {
		t.Fatalf("batch rows lost their group: %d, %d, want %d", first.Batch, second.Batch, batch)
	}
	if after.Batch != 0 {
		t.Fatalf("EndBatch did not close the group: row %d is still in %d", after.ID, after.Batch)
	}
	if got := q.BatchLabel(batch); got != "Upload folder docs" {
		t.Fatalf("BatchLabel = %q, want the label BeginBatch was given", got)
	}
	if got := q.BatchLabel(0); got != "" {
		t.Fatalf("the unbatched group must have no label, got %q", got)
	}
	// Two groups are two groups: a second folder must not join the first.
	other := q.BeginBatch("Upload folder other")
	if other == batch {
		t.Fatalf("BeginBatch reused the id %d", other)
	}
	q.EndBatch()
	if q.BatchLabel(other) != "Upload folder other" {
		t.Fatal("the second batch lost its own label")
	}
}

// TestAddSkippedRowIsSettled keeps a skip row out of the pump's way and out of the
// user's reach: it is finished on arrival, so pause and cancel must not move it -
// and it carries the reason the batch summary reports.
func TestAddSkippedRowIsSettled(t *testing.T) {
	q := NewTransferQueue(nil, 1)
	q.BeginBatch("Upload folder site")
	up := q.AddSkipped(Upload, filepath.Join("site", "link.txt"), "", "symbolic link")
	down := q.AddSkipped(Download, "", "/var/log/app.log", "already there (skip policy)")
	q.EndBatch()

	if up.Status != StatusSkipped || up.ErrorMsg != "symbolic link" {
		t.Fatalf("upload skip row wrong: %s / %q", up.Status, up.ErrorMsg)
	}
	if up.FileName != "link.txt" {
		t.Fatalf("an upload row is named by its local path, got %q", up.FileName)
	}
	if down.FileName != "app.log" {
		t.Fatalf("a download row is named by its remote path, got %q", down.FileName)
	}
	if down.Status.String() != "Skipped" {
		t.Fatalf("status text = %q, want Skipped", down.Status.String())
	}
	if up.Batch == 0 || down.Batch == 0 {
		t.Fatal("skips belong to the batch that left them out")
	}
	if up.EndTime == "" {
		t.Fatal("a settled row needs an end time, or the UI shows it as still running")
	}

	q.PauseItem(up.ID)
	q.CancelItem(down.ID)
	if got := snapshotOf(t, q, up.ID); got.Status != StatusSkipped {
		t.Fatalf("pause moved a settled row to %s", got.Status)
	}
	if got := snapshotOf(t, q, down.ID); got.Status != StatusSkipped {
		t.Fatalf("cancel moved a settled row to %s", got.Status)
	}

	// A skip row is finished, so "Clear finished" removes it with the rest.
	q.ClearCompleted()
	for _, it := range q.GetItems() {
		if it.ID == up.ID || it.ID == down.ID {
			t.Fatal("skipped rows must clear with the other finished rows")
		}
	}
}
