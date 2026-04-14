package gun

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type testWriteCloser struct {
	mu     sync.Mutex
	closed bool
}

func (w *testWriteCloser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (w *testWriteCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *testWriteCloser) IsClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

type testReadCloser struct {
	closeOnce sync.Once
	closeCh   chan struct{}
}

func (r *testReadCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (r *testReadCloser) Close() error {
	r.closeOnce.Do(func() {
		close(r.closeCh)
	})
	return nil
}

type fakeConnTimer struct {
	mu         sync.Mutex
	stopResult bool
	callback   func()
	stopped    bool
}

func (t *fakeConnTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	return t.stopResult
}

func (t *fakeConnTimer) Fire() {
	t.mu.Lock()
	callback := t.callback
	t.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func withFakeConnTimers(t *testing.T, stopResult bool) *[]*fakeConnTimer {
	t.Helper()
	oldFactory := newConnTimer
	timers := make([]*fakeConnTimer, 0, 4)
	newConnTimer = func(d time.Duration, f func()) connTimer {
		timer := &fakeConnTimer{
			stopResult: stopResult,
			callback:   f,
		}
		timers = append(timers, timer)
		return timer
	}
	t.Cleanup(func() {
		newConnTimer = oldFactory
	})
	return &timers
}

func TestConnDeadlineClearIgnoresStaleTimer(t *testing.T) {
	timers := withFakeConnTimers(t, false)
	writer := &testWriteCloser{}
	conn := &Conn{
		writer: writer,
	}

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(*timers) != 1 {
		t.Fatalf("expected one timer, got %d", len(*timers))
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	(*timers)[0].Fire()

	if conn.closed {
		t.Fatal("stale deadline callback closed the connection after deadline was cleared")
	}
	if writer.IsClosed() {
		t.Fatal("stale deadline callback closed the writer after deadline was cleared")
	}
}

func TestConnCloseWhileInitInProgressDoesNotDeadlock(t *testing.T) {
	writer := &testWriteCloser{}
	reader := &testReadCloser{closeCh: make(chan struct{})}
	initEntered := make(chan struct{})
	releaseInit := make(chan struct{})

	conn := &Conn{
		writer: writer,
		initFn: func(*httputils.NetAddr) (io.ReadCloser, error) {
			close(initEntered)
			<-releaseInit
			return reader, nil
		},
	}

	initDone := make(chan error, 1)
	go func() {
		initDone <- conn.Init()
	}()

	<-initEntered

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- conn.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked while initReader was in progress")
	}

	close(releaseInit)

	select {
	case err := <-initDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Init did not return after Close")
	}

	select {
	case <-reader.closeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("reader was not closed after init completed on a closed conn")
	}
}

func TestConnInitAfterCloseDoesNotCallInitFn(t *testing.T) {
	writer := &testWriteCloser{}
	initCalled := make(chan struct{}, 1)
	conn := &Conn{
		writer: writer,
		initFn: func(*httputils.NetAddr) (io.ReadCloser, error) {
			initCalled <- struct{}{}
			return &testReadCloser{closeCh: make(chan struct{})}, nil
		},
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	err := conn.Init()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}

	select {
	case <-initCalled:
		t.Fatal("initFn should not run after Close")
	default:
	}
}
