package transfer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

// TransferDirection indicates upload or download
type TransferDirection int

const (
	Download TransferDirection = iota
	Upload
)

// TransferStatus represents the state of a transfer item
type TransferStatus int

const (
	StatusPending TransferStatus = iota
	StatusInProgress
	StatusPaused
	StatusCompleted
	StatusFailed
	StatusCancelled
	// StatusSkipped is a row that will never be copied: a symbolic link inside a
	// folder upload, or a file the conflict policy left alone. It is settled the
	// moment it is created, so the pump never picks it up, and it exists so the
	// batch summary can count what was left out instead of those files quietly
	// vanishing from the list.
	StatusSkipped
)

func (s TransferStatus) String() string {
	switch s {
	case StatusPending:
		return "Pending"
	case StatusInProgress:
		return "Transferring"
	case StatusPaused:
		return "Paused"
	case StatusCompleted:
		return "Completed"
	case StatusFailed:
		return "Failed"
	case StatusCancelled:
		return "Cancelled"
	case StatusSkipped:
		return "Skipped"
	}
	return "Unknown"
}

// errPaused stops a pump goroutine at the next chunk boundary when the user
// pauses a running transfer. It is deliberately not a failure: the byte counter
// stays where the copy stopped, and ResumeItem continues from that offset.
var errPaused = errors.New("paused")

// copyChunkSize is the per-read buffer in doDownload and doUpload. A var so
// tests can lower it to exercise chunk-boundary pause/resume without moving a
// whole megabyte first.
//
// The default (256 KB) is the WAN throughput lever. pkg/sftp services a request
// of at most maxPacket (32 KB, its default) in one round trip, but it splits any
// larger Read or Write into len(b)/maxPacket + 1 concurrent sub-requests - up to
// its 64-request cap - precisely so that "writes with a suitably large buffer
// transfer data at a much faster rate by overlapping round trip times". With the
// old 32 KB buffer every chunk was exactly one serial request, so throughput was
// bounded by RTT alone: on a 100 ms link that caps a single stream near 320 KB/s
// no matter how much bandwidth exists. A 256 KB buffer puts 9 requests in flight.
//
// The trade-off is pause latency: a pause is observed between chunks, so stopping
// a running transfer now waits for at most one 256 KB chunk to finish.
var copyChunkSize = 256 * 1024

// Retry tuning, var-style so tests do not wait out the real budgets. A brief
// link blip (NAT reset, server restart of sshd's child, an EOF on a stalled
// channel) used to mark the whole file Failed even though the pause/resume
// machinery could carry on from the exact byte where it stopped.
var (
	maxTransferRetries   = 3               // total attempts per transfer
	transferRetryBackoff = 1 * time.Second // doubled per attempt
)

// verifySize is the last check a copy gets: the length now on the far side against
// the length the copy set out to write. A mismatch is reported as a failure so the
// row cannot read "Completed" over a short file - the worst way for a transfer to
// fail, because nothing on screen says the bytes are missing.
func verifySize(what string, got, want int64) error {
	if got != want {
		return fmt.Errorf("%s is %d bytes, expected %d", what, got, want)
	}
	return nil
}

// isTransient classifies a copy failure as worth another attempt. A reset, a
// timeout, an EOF mid-stream or an SSH channel that died underneath a live SFTP
// write all leave both files intact at the shared offset, so the next attempt
// simply continues. A permission problem, a missing file or an out-of-disk
// write is stated once and stays failed - repeating those only re-rolls the
// same error while the queue sits idle. Cancel and pause are checked first and
// are never transient.
func isTransient(item *TransferItem, err error) bool {
	if err == nil || errors.Is(err, errPaused) {
		return false
	}
	if item != nil {
		select {
		case <-item.cancel:
			return false
		default:
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	switch strings.ToLower(err.Error()) {
	case "cancelled", "canceled":
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, m := range []string{
		"connection reset",
		"connection aborted",
		"connection refused",
		"broken pipe",
		"EOF",
		"use of closed",
		"ssh: channel",
		"ssh: connect",
	} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// sleepInterruptible waits out the backoff unless the item is cancelled (or
// paused - the pump that resumes the row owns the next attempt) in between.
func (q *TransferQueue) sleepInterruptible(item *TransferItem, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		if itemCancelled(item) || q.isPaused(item) {
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		select {
		case <-item.cancel:
			return
		case <-time.After(remaining):
		}
	}
}

// retryTransfer runs one copy and retries it when the failure looks transient.
// Every attempt re-reads both sides' real lengths before deciding where to
// continue - exactly the check a resume already makes - so the counter can
// never outrun the bytes actually on disk or on the server. The partial file
// deliberately survives a failed attempt; only the last one decides, and the
// copy's own cleanup still removes it when the transfer truly fails.
func (q *TransferQueue) retryTransfer(item *TransferItem, client *sftp.Client, do func(*sftp.Client, *TransferItem) error) error {
	backoff := transferRetryBackoff
	var err error
	for attempt := 1; attempt <= maxTransferRetries; attempt++ {
		err = do(client, item)
		if err == nil || errors.Is(err, errPaused) || itemCancelled(item) || !isTransient(item, err) {
			return err
		}
		if attempt < maxTransferRetries {
			q.sleepInterruptible(item, backoff)
			backoff *= 2
			select {
			case <-item.cancel:
				return err
			default:
			}
			if q.isPaused(item) {
				return errPaused
			}
		}
	}
	return fmt.Errorf("%w (after %d attempts)", err, maxTransferRetries)
}

func itemCancelled(item *TransferItem) bool {
	select {
	case <-item.cancel:
		return true
	default:
		return false
	}
}

// ConflictPolicy decides what a queued transfer does when something already
// sits at its destination. It arrives as a string from the UI and is
// normalised by ParsePolicy; an unrecognised value falls back to Overwrite,
// which is the behaviour Graystone always had.
type ConflictPolicy int

const (
	Overwrite ConflictPolicy = iota
	Rename
	Skip
)

// ParsePolicy maps the frontend's "overwrite"/"rename"/"skip" strings.
func ParsePolicy(s string) ConflictPolicy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "rename":
		return Rename
	case "skip":
		return Skip
	default:
		return Overwrite
	}
}

// SplitExt separates a file name into stem and extension for renaming:
// "archive.tar.gz" splits as "archive.tar" + ".gz" (only the last dot),
// ".hidden" has no stem-dot to cut on and stays whole.
func SplitExt(name string) (stem, ext string) {
	i := strings.LastIndex(name, ".")
	if i <= 0 {
		return name, ""
	}
	return name[:i], name[i:]
}

// UniqueLocalPath is the Rename answer for a local destination: the path
// itself when nothing is there, else "name (1).ext", "name (2).ext" ... up to
// a sane cap. exists is injected so the remote side can share this logic with
// an SFTP Stat instead of os.Stat.
func UniqueLocalPath(dest string, exists func(string) bool) string {
	if !exists(dest) {
		return dest
	}
	dir, base := filepath.Dir(dest), filepath.Base(dest)
	stem, ext := SplitExt(base)
	for i := 1; i <= 1000; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if !exists(cand) {
			return cand
		}
	}
	return dest
}

// UniqueRemotePath is the rename chain for a remote (slash-separated)
// destination, sharing SplitExt and the " (n)" shape with the local side.
func UniqueRemotePath(dest string, exists func(string) bool) string {
	if !exists(dest) {
		return dest
	}
	dir, base := path.Dir(dest), path.Base(dest)
	stem, ext := SplitExt(base)
	for i := 1; i <= 1000; i++ {
		cand := path.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if !exists(cand) {
			return cand
		}
	}
	return dest
}

// LocalDestDecision applies a policy to a local destination: it returns the
// path to transfer to and whether the row should be queued at all (false is
// the Skip outcome). Overwrite keeps the path exactly as chosen.
func LocalDestDecision(dest string, policy ConflictPolicy) (string, bool) {
	switch policy {
	case Skip:
		if _, err := os.Stat(dest); err == nil {
			return dest, false
		}
	case Rename:
		return UniqueLocalPath(dest, func(p string) bool { _, err := os.Stat(p); return err == nil }), true
	}
	return dest, true
}

// RemoteExists is the stat half the conflict decisions need, narrowed to a
// function so app.go injects the session's client and tests can stub it.
func RemoteExists(c *sftp.Client, p string) bool {
	_, err := c.Stat(p)
	return err == nil
}

// TransferItem represents a single file transfer
type TransferItem struct {
	ID            int               `json:"id"`
	FileName      string            `json:"name"`
	RemotePath    string            `json:"remote_path"`
	LocalPath     string            `json:"local_path"`
	Direction     TransferDirection `json:"direction"`
	TotalBytes    int64             `json:"total_bytes"`
	TransferBytes int64             `json:"transfer_bytes"`
	Status        TransferStatus    `json:"status"`
	Error         error             `json:"-"`
	ErrorMsg      string            `json:"error"`
	StartTime     string            `json:"start_time"`
	EndTime       string            `json:"end_time"`
	// Batch groups the rows one action queued - a folder copy, a drop of several
	// files - so the UI can report "12 copied, 2 skipped, 1 failed" when the group
	// settles instead of leaving the user to count rows. 0 means "not batched".
	Batch  int           `json:"batch"`
	cancel chan struct{} `json:"-"`
	// cancelled records that the cancel channel was already closed, so a second
	// CancelItem on the same running item cannot panic on a double close.
	cancelled bool
	// running records that a pump goroutine is inside this item's copy loop. A
	// paused item must not be picked up again until that goroutine has left,
	// otherwise two writers would race on the same file offsets.
	running bool
	// srcSize and srcMod record the source file as the attempt that started this
	// row saw it, so a resumed copy can tell whether the bytes it already carried
	// still belong to that file. Bookkeeping, not UI data.
	srcSize int64     `json:"-"`
	srcMod  time.Time `json:"-"`
}

// Progress returns the transfer progress as a percentage (0-100)
func (t *TransferItem) Progress() int {
	if t.TotalBytes == 0 {
		return 0
	}
	return int(t.TransferBytes * 100 / t.TotalBytes)
}

// Speed returns current transfer speed in bytes per second
func (t *TransferItem) Speed(startTimeObj time.Time) int64 {
	if startTimeObj.IsZero() || t.TransferBytes == 0 {
		return 0
	}
	elapsed := time.Since(startTimeObj).Seconds()
	if elapsed == 0 {
		return 0
	}
	return int64(float64(t.TransferBytes) / elapsed)
}

// ETA returns estimated time remaining
func (t *TransferItem) ETA(startTimeObj time.Time) string {
	speed := t.Speed(startTimeObj)
	if speed == 0 {
		return "∞"
	}
	remaining := t.TotalBytes - t.TransferBytes
	seconds := remaining / speed
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 3600 {
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh %dm", seconds/3600, (seconds%3600)/60)
}

// FormatSize formats bytes into human-readable string
func FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatSpeed formats speed in bytes/sec to human readable
func FormatSpeed(bytesPerSec int64) string {
	return FormatSize(bytesPerSec) + "/s"
}

// TransferQueue manages a queue of file transfers.
//
// A progress callback, when the UI layer registers one through SetOnProgress,
// is rung at most once per progressCadence while bytes are moving - never from
// inside the per-chunk lock round trip, which would only slow the copy down.
type TransferQueue struct {
	mu      sync.Mutex
	items   []*TransferItem
	nextID  int
	maxConc int // max concurrent transfers
	active  int
	client  *sftp.Client
	// workers counts the drain goroutines alive right now. Each one runs at most
	// one transfer at a time, so this is also what makes maxConc real. Queueing
	// used to spawn a goroutine per row: a 2000-file folder meant 2000 goroutines
	// each scanning the whole list under one mutex, for the same two transfers.
	workers int
	// onProgress, lastProgress and the cadence gate are all guarded by mu.
	onProgress   func()
	lastProgress time.Time
	// nextBatch/curBatch serve BeginBatch and EndBatch: every row added between
	// the two calls carries the batch id, which is how a folder's rows are later
	// recognised as one group. batchLabels names each group for the summary line.
	// All three are guarded by mu like the rest of the queue.
	nextBatch   int
	curBatch    int
	batchLabels map[int]string
}

// startWorker ensures a drain loop exists to run the item the caller just made
// runnable. The caller must hold q.mu, so claiming the slot cannot race with a
// worker that is on its way out.
func (q *TransferQueue) startWorker() {
	if q.workers >= q.maxConc {
		return
	}
	q.workers++
	go q.processNext()
}

// progressCadence bounds how often the registered callback may fire while a
// transfer is running. Var-style so tests can lower it; the value matches the
// interval the old frontend poll used, so the UI gains freshness without any
// new event storms.
var progressCadence = 600 * time.Millisecond

// SetOnProgress installs the callback that reports "the queue moved". Passing
// nil disables the rings again.
func (q *TransferQueue) SetOnProgress(fn func()) {
	q.mu.Lock()
	q.onProgress = fn
	q.mu.Unlock()
}

// notifyProgress rings the callback if the cadence window has passed. Like
// isPaused it asks the lock rather than the pointer, and it fires the callback
// outside the lock so a slow listener can never block the copy loop's next
// chunk.
func (q *TransferQueue) notifyProgress() {
	q.ring(false)
}

// notifyProgressForced is for state changes the UI must see even 40 ms after
// the last ring: a five-second file whose finish waited out the window would
// otherwise sit on screen as "Transferring" until some later event rendered it.
func (q *TransferQueue) notifyProgressForced() {
	q.ring(true)
}

func (q *TransferQueue) ring(force bool) {
	q.mu.Lock()
	if q.onProgress == nil || (!force && time.Since(q.lastProgress) < progressCadence) {
		q.mu.Unlock()
		return
	}
	q.lastProgress = time.Now()
	fn := q.onProgress
	q.mu.Unlock()
	fn()
}

// NewTransferQueue creates a new transfer queue
func NewTransferQueue(client *sftp.Client, maxConcurrent int) *TransferQueue {
	return &TransferQueue{
		items:       make([]*TransferItem, 0),
		maxConc:     maxConcurrent,
		client:      client,
		batchLabels: map[int]string{},
	}
}

// SetClient swaps the SFTP session the queue copies through. Production builds
// the queue with its client and never replaces it; this exists so a test can
// create the queue first and decide the exact moment transfers are allowed to
// start.
func (q *TransferQueue) SetClient(client *sftp.Client) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.client = client
}

// AddDownload adds a download to the queue
func (q *TransferQueue) AddDownload(remotePath, localPath string) *TransferItem {
	q.mu.Lock()

	q.nextID++
	item := &TransferItem{
		ID:         q.nextID,
		FileName:   filepath.Base(remotePath),
		RemotePath: remotePath,
		LocalPath:  localPath,
		Direction:  Download,
		Status:     StatusPending,
		Batch:      q.curBatch,
		cancel:     make(chan struct{}),
	}

	q.items = append(q.items, item)
	q.startWorker()
	q.mu.Unlock()

	return item
}

// AddUpload adds an upload to the queue
func (q *TransferQueue) AddUpload(localPath, remotePath string) *TransferItem {
	q.mu.Lock()

	q.nextID++
	item := &TransferItem{
		ID:         q.nextID,
		FileName:   filepath.Base(localPath),
		RemotePath: remotePath,
		LocalPath:  localPath,
		Direction:  Upload,
		Status:     StatusPending,
		Batch:      q.curBatch,
		cancel:     make(chan struct{}),
	}

	q.items = append(q.items, item)
	q.startWorker()
	q.mu.Unlock()

	return item
}

// BeginBatch opens a group of rows and returns its id. The label is what the
// summary will name the group by ("Upload /var/log"). Everything added until
// EndBatch belongs to it; a folder copy is the reason it exists.
func (q *TransferQueue) BeginBatch(label string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nextBatch++
	if q.batchLabels == nil {
		q.batchLabels = map[int]string{}
	}
	q.batchLabels[q.nextBatch] = label
	q.curBatch = q.nextBatch
	return q.nextBatch
}

// EndBatch closes the group BeginBatch opened. Rows already queued keep their
// stamp; later ones belong to no group until the next BeginBatch.
func (q *TransferQueue) EndBatch() {
	q.mu.Lock()
	q.curBatch = 0
	q.mu.Unlock()
}

// BatchLabel is the name BeginBatch gave a group; "" for the unbatched 0.
func (q *TransferQueue) BatchLabel(batch int) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.batchLabels[batch]
}

// AddSkipped records a file the queue deliberately will not copy: a link inside a
// folder, or a file the conflict policy left alone. Without a row there is nothing
// to count, and "nothing happened" is a poor report for a folder the user can see
// on disk. The row is settled on arrival, so cancel and pause - which only act on
// pending, running or paused rows - never reach it, and it needs no cancel channel.
func (q *TransferQueue) AddSkipped(d TransferDirection, localPath, remotePath, reason string) *TransferItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nextID++
	name := filepath.Base(localPath)
	if d == Download {
		name = filepath.Base(remotePath)
	}
	item := &TransferItem{
		ID:         q.nextID,
		FileName:   name,
		RemotePath: remotePath,
		LocalPath:  localPath,
		Direction:  d,
		Status:     StatusSkipped,
		ErrorMsg:   reason,
		Batch:      q.curBatch,
		EndTime:    time.Now().Format(time.RFC3339),
	}
	q.items = append(q.items, item)
	return item
}

// PauseItem stops a queued or running transfer. A pending row simply waits; a
// running one keeps the bytes it already moved, so ResumeItem does not restart
// the file. A row that already finished keeps its real status.
func (q *TransferQueue) PauseItem(id int) {
	q.mu.Lock()
	for _, item := range q.items {
		if item.ID != id {
			continue
		}
		switch item.Status {
		case StatusPending, StatusInProgress:
			item.Status = StatusPaused
		}
		break
	}
	q.mu.Unlock()
}

// ResumeItem puts a paused transfer back in line. If its pump goroutine has not
// noticed the pause yet, that goroutine carries on with the handles it already
// has open; otherwise a fresh pump reopens both sides at the saved offset.
func (q *TransferQueue) ResumeItem(id int) {
	q.mu.Lock()
	for _, item := range q.items {
		if item.ID != id {
			continue
		}
		if item.Status == StatusPaused {
			item.Status = StatusPending
			// If the old pump is still alive it owns this row and will pick it up
			// on its own next pass; starting a second one would race two writers
			// over the same file handles.
			if !item.running {
				q.startWorker()
			}
		}
		break
	}
	q.mu.Unlock()
}

// isPaused asks the lock rather than the pointer: the pump and the UI poll both
// touch the same row.
func (q *TransferQueue) isPaused(item *TransferItem) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return item.Status == StatusPaused
}

// bytesDone reads how much has really been moved, under the lock.
func (q *TransferQueue) bytesDone(item *TransferItem) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return item.TransferBytes
}

// setDone realigns the counter with the file that is actually on disk before a
// resumed copy decides where to continue.
func (q *TransferQueue) setDone(item *TransferItem, n int64) {
	q.mu.Lock()
	item.TransferBytes = n
	q.mu.Unlock()
}

// CancelItem cancels a queued or running transfer. It is idempotent, and an
// item that already finished keeps its real status - only pending and running
// transfers can be cancelled.
func (q *TransferQueue) CancelItem(id int) {
	q.mu.Lock()

	for _, item := range q.items {
		if item.ID != id {
			continue
		}
		switch item.Status {
		case StatusPending, StatusInProgress, StatusPaused:
			// Close the cancel channel for both Pending and InProgress items so
			// that a transfer goroutine which picks up a just-cancelled Pending
			// item still receives the cancellation signal immediately.
			if !item.cancelled {
				item.cancelled = true
				close(item.cancel)
			}
			item.Status = StatusCancelled
		}
		break
	}
	q.mu.Unlock()
}

// ClearCompleted removes completed/failed/cancelled items
func (q *TransferQueue) ClearCompleted() {
	q.mu.Lock()

	var remaining []*TransferItem
	for _, item := range q.items {
		if item.Status == StatusPending || item.Status == StatusInProgress || item.Status == StatusPaused {
			remaining = append(remaining, item)
		}
	}
	q.items = remaining
	q.mu.Unlock()
}

// GetItems returns a snapshot of all queue items. Each entry is a copy: the
// transfer goroutine advances the byte counters under the queue lock, so
// handing out the live pointers would let a reader catch them mid-write.
func (q *TransferQueue) GetItems() []*TransferItem {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]*TransferItem, 0, len(q.items))
	for _, item := range q.items {
		snapshot := *item
		result = append(result, &snapshot)
	}
	return result
}

// setTotal and addProgress publish the byte counters under the queue lock so
// the progress the UI polls can never be read as a torn value.
func (q *TransferQueue) setTotal(item *TransferItem, total int64) {
	q.mu.Lock()
	item.TotalBytes = total
	q.mu.Unlock()
}

// sourceReplaced compares the file about to be copied against what the row's
// first attempt recorded, and stores the fingerprint on that first pass.
//
// A resumed transfer continues at an offset measured in the source's earlier
// bytes. If the source was swapped in the meantime the result is a hybrid of two
// files - and because the closing check only compares lengths, a swap that kept
// the size passes as a clean completion, which is the worst way for a transfer to
// fail. Restarting is always safe, so any mismatch starts from zero.
//
// Size plus mtime is the same heuristic rsync uses: a replacement that preserved
// both exactly cannot be told apart from no change, and it also carries the same
// bytes, so continuing is correct there anyway.
func (q *TransferQueue) sourceReplaced(item *TransferItem, size int64, mod time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	seen := item.srcSize != 0 || !item.srcMod.IsZero()
	unchanged := item.srcSize == size && item.srcMod.Equal(mod)
	item.srcSize, item.srcMod = size, mod
	return seen && !unchanged
}

func (q *TransferQueue) addProgress(item *TransferItem, n int64) {
	q.mu.Lock()
	item.TransferBytes += n
	q.mu.Unlock()
}

// GetStats returns queue statistics. Paused rows are counted separately: they
// are neither waiting to start nor occupying a concurrency slot.
func (q *TransferQueue) GetStats() (pending, paused, active, completed, failed int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, item := range q.items {
		switch item.Status {
		case StatusPending:
			pending++
		case StatusPaused:
			paused++
		case StatusInProgress:
			active++
		case StatusCompleted:
			completed++
		case StatusFailed, StatusCancelled:
			failed++
		}
	}
	return
}

func (q *TransferQueue) processNext() {
	for {
		q.mu.Lock()
		if q.client == nil || q.active >= q.maxConc {
			// Hand the worker slot back while still holding the lock, so an item
			// added after this point can always start a fresh worker.
			q.workers--
			q.mu.Unlock()
			return
		}

		// Find next pending item. A paused row is skipped, and so is one whose
		// pump has not exited yet - its file handles belong to that goroutine.
		var nextItem *TransferItem
		for _, item := range q.items {
			if item.Status == StatusPending && !item.running {
				nextItem = item
				break
			}
		}

		if nextItem == nil {
			q.workers--
			q.mu.Unlock()
			return
		}

		startTimeObj := time.Now()
		nextItem.Status = StatusInProgress
		nextItem.running = true
		nextItem.StartTime = startTimeObj.Format(time.RFC3339)
		q.active++
		client := q.client
		q.mu.Unlock()
		// The row just changed state; let a listener render it even if the
		// cadence window has not expired since the last ring.
		q.notifyProgress()

		// Execute transfer, retrying transient link failures from wherever
		// the bytes actually stopped.
		var err error
		if nextItem.Direction == Download {
			err = q.retryTransfer(nextItem, client, q.doDownload)
		} else {
			err = q.retryTransfer(nextItem, client, q.doUpload)
		}

		q.finish(nextItem, err)
		// Loop back to pick up the next pending item rather than calling
		// processNext recursively. Recursive calls accumulate a goroutine per
		// completed transfer when the queue drains slowly, and can exhaust the
		// stack if many items complete back-to-back.
	}
}

// finish records a transfer's outcome and frees its concurrency slot. A
// cancelled row keeps the Cancelled status the user set: the pump returns a
// "cancelled" error precisely because it noticed that signal, and turning it
// into "Failed - error: cancelled" would report a mis-click as a broken link.
// A paused row keeps its counters and gets no end time, because it is not over.
func (q *TransferQueue) finish(item *TransferItem, err error) {
	q.mu.Lock()
	q.active--
	item.running = false
	paused := item.Status == StatusPaused || errors.Is(err, errPaused)
	switch {
	case paused:
		item.Status = StatusPaused
	case item.Status == StatusCancelled:
	case err != nil:
		item.Status = StatusFailed
		item.Error = err
		item.ErrorMsg = err.Error()
	default:
		item.Status = StatusCompleted
	}
	if !paused {
		item.EndTime = time.Now().Format(time.RFC3339)
	}
	// Freeing a slot is the event that lets a waiting row run. This worker will
	// usually loop and take it itself, but if every worker has already exited
	// (a queue that drained while the client was still nil, say) this is the hand
	// -off that keeps pending rows from sleeping forever. It needs the lock, and
	// the count makes it a no-op while this worker still holds its own slot.
	q.startWorker()
	q.mu.Unlock()
	// The final state must reach the UI whatever the cadence window says.
	q.notifyProgressForced()
}

func (q *TransferQueue) doDownload(client *sftp.Client, item *TransferItem) (err error) {
	// Bytes already on disk: 0 for a fresh row, and where a pause stopped for a
	// resumed one. Both sides are opened around this offset.
	done := q.bytesDone(item)

	// Get remote file info for size
	info, err := client.Stat(item.RemotePath)
	if err != nil {
		return fmt.Errorf("stat remote: %w", err)
	}
	// The remote file is the source here. If it is not the one this row started
	// copying, nothing already on disk belongs to it and the copy must start over.
	if q.sourceReplaced(item, info.Size(), info.ModTime()) {
		done = 0
		q.setDone(item, 0)
	}
	q.setTotal(item, info.Size())

	// The counter is only as good as the file it describes. If the partial was
	// deleted or shortened behind our back, continuing from its real length beats
	// stitching unrelated bytes onto the end of it.
	if fi, serr := os.Stat(item.LocalPath); serr != nil {
		done = 0
	} else if fi.Size() < done {
		done = fi.Size()
	}
	if q.bytesDone(item) != done {
		q.setDone(item, done)
	}

	// Open remote file
	src, err := client.Open(item.RemotePath)
	if err != nil {
		return fmt.Errorf("open remote: %w", err)
	}
	defer src.Close()
	if done > 0 {
		if _, err := src.Seek(done, io.SeekStart); err != nil {
			return fmt.Errorf("seek remote: %w", err)
		}
	}

	// Create local file - or continue the one a pause left behind. The offset is
	// set on the handle instead of opening with O_APPEND: the copy issues plain
	// Writes, and on a remote handle the protocol carries an explicit offset that
	// an append flag would not move.
	flags := os.O_WRONLY | os.O_CREATE
	if done == 0 {
		flags |= os.O_TRUNC
	}
	dst, err := os.OpenFile(item.LocalPath, flags, 0o666)
	if err != nil {
		return fmt.Errorf("create local: %w", err)
	}
	defer dst.Close()
	if done > 0 {
		if _, err := dst.Seek(done, io.SeekStart); err != nil {
			return fmt.Errorf("seek local: %w", err)
		}
		// Anything the partial holds beyond the counter is somebody else's bytes;
		// dropping it keeps a resumed file exactly the length of the remote one.
		if err := dst.Truncate(done); err != nil {
			return fmt.Errorf("truncate local: %w", err)
		}
	}

	// Cleanup on error. A pause is not an error and its partial file is exactly
	// what the resume needs, so only a real failure removes it.
	defer func() {
		if err != nil && !errors.Is(err, errPaused) {
			// Close file before removing
			dst.Close()
			os.Remove(item.LocalPath)
		}
	}()

	// Transfer with progress tracking
	buf := make([]byte, copyChunkSize)
	for {
		select {
		case <-item.cancel:
			return fmt.Errorf("cancelled")
		default:
		}
		if q.isPaused(item) {
			return errPaused
		}
		// Cadence-gated: with no listener registered this is one mutex pair,
		// and inside a copyChunkSize byte write that costs far less than the I/O.
		q.notifyProgress()

		n, readErr := src.Read(buf)
		if n > 0 {
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("write: %w", writeErr)
			}
			q.addProgress(item, int64(n))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}

	// The local length is the proof the copy arrived whole. A write the OS
	// accepted into its cache and then lost - a full disk, a teardown mid-flush -
	// used to leave the row reading "Completed" over a short file, which is the
	// worst way for a transfer to fail. Close first: that is what flushes the
	// handle, and a Stat before it can report a length the last writes have not
	// reached yet.
	if cerr := dst.Close(); cerr != nil {
		return fmt.Errorf("close local: %w", cerr)
	}
	fi, serr := os.Stat(item.LocalPath)
	if serr != nil {
		return fmt.Errorf("verify local: %w", serr)
	}
	return verifySize("local file", fi.Size(), item.TotalBytes)
}

func (q *TransferQueue) doUpload(client *sftp.Client, item *TransferItem) (err error) {
	// Bytes already delivered to the remote side: 0 for a fresh row, and where a
	// pause stopped for a resumed one.
	done := q.bytesDone(item)

	// Get local file info
	info, err := os.Stat(item.LocalPath)
	if err != nil {
		return fmt.Errorf("stat local: %w", err)
	}
	// Same rule as the download side, with the roles swapped: the local file is the
	// source, so a replacement since the pause means the bytes already delivered
	// remotely came from a different file.
	if q.sourceReplaced(item, info.Size(), info.ModTime()) {
		done = 0
		q.setDone(item, 0)
	}
	q.setTotal(item, info.Size())

	// The remote length is the only trustworthy offset: if that file was removed
	// or truncated meanwhile, appending at the remembered position would produce
	// content that is neither the old nor the new file.
	if done > 0 {
		if fi, serr := client.Stat(item.RemotePath); serr != nil {
			done = 0
		} else if fi.Size() < done {
			done = fi.Size()
		}
		if q.bytesDone(item) != done {
			q.setDone(item, done)
		}
	}

	// Open local file
	src, err := os.Open(item.LocalPath)
	if err != nil {
		return fmt.Errorf("open local: %w", err)
	}
	defer src.Close()
	if done > 0 {
		if _, err := src.Seek(done, io.SeekStart); err != nil {
			return fmt.Errorf("seek local: %w", err)
		}
	}

	// Create remote file - or continue the one a pause left behind, at the offset
	// the protocol writes will carry.
	flags := os.O_WRONLY | os.O_CREATE
	if done == 0 {
		flags |= os.O_TRUNC
	}
	dst, err := client.OpenFile(item.RemotePath, flags)
	if err != nil {
		return fmt.Errorf("create remote: %w", err)
	}
	defer dst.Close()
	if done > 0 {
		if _, err := dst.Seek(done, io.SeekStart); err != nil {
			return fmt.Errorf("seek remote: %w", err)
		}
		// Same rule as the download side: the counter decides where the resumed
		// copy ends, so a remote file left longer by an earlier attempt is cut back.
		if err := dst.Truncate(done); err != nil {
			return fmt.Errorf("truncate remote: %w", err)
		}
	}

	// Cleanup on error; a pause keeps its partial remote file as the resume point
	defer func() {
		if err != nil && !errors.Is(err, errPaused) {
			dst.Close()
			client.Remove(item.RemotePath)
		}
	}()

	// Transfer with progress tracking
	buf := make([]byte, copyChunkSize)
	for {
		select {
		case <-item.cancel:
			return fmt.Errorf("cancelled")
		default:
		}
		if q.isPaused(item) {
			return errPaused
		}
		q.notifyProgress()

		n, readErr := src.Read(buf)
		if n > 0 {
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("write: %w", writeErr)
			}
			q.addProgress(item, int64(n))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}

	// The remote length is the only proof the file arrived whole. pkg/sftp sends
	// each Write synchronously, so this is not about buffering - it is about a
	// server that accepted a write and then lost it (a full disk reported late, an
	// SFTP subsystem torn down mid-flush): the row used to read "Completed" over a
	// short file. Close before measuring, and let a mismatch fall through the same
	// cleanup as any other failure so the partial remote file is removed instead of
	// being left behind looking finished.
	if cerr := dst.Close(); cerr != nil {
		return fmt.Errorf("close remote: %w", cerr)
	}
	fi, serr := client.Stat(item.RemotePath)
	if serr != nil {
		return fmt.Errorf("verify remote: %w", serr)
	}
	return verifySize("remote", fi.Size(), info.Size())
}
