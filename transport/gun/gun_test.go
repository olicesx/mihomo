package gun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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

func TestRequestBodyPipeBuffersInitialWrite(t *testing.T) {
	pipe := newRequestBodyPipe(32)
	writeDone := make(chan error, 1)
	payload := []byte("hello")

	go func() {
		_, err := pipe.Write(payload)
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Write blocked before the reader consumed any data")
	}

	buf := make([]byte, len(payload))
	n, err := io.ReadFull(pipe, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != len(payload) || string(buf) != string(payload) {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
}

func TestRequestBodyPipeRespectsBufferLimit(t *testing.T) {
	pipe := newRequestBodyPipe(4)
	writeDone := make(chan error, 1)

	go func() {
		_, err := pipe.Write([]byte("hello"))
		writeDone <- err
	}()

	select {
	case <-writeDone:
		t.Fatal("Write completed before the reader made room in the buffer")
	case <-time.After(100 * time.Millisecond):
	}

	buf := make([]byte, 4)
	n, err := io.ReadFull(pipe, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if n != 4 || string(buf) != "hell" {
		t.Fatalf("unexpected prefix: %q", buf[:n])
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write stayed blocked after the reader made room in the buffer")
	}

	one := make([]byte, 1)
	n, err = io.ReadFull(pipe, one)
	if err != nil {
		t.Fatalf("unexpected tail read error: %v", err)
	}
	if n != 1 || string(one) != "o" {
		t.Fatalf("unexpected tail byte: %q", one[:n])
	}
}

func TestTransportDialBuffersInitialWrite(t *testing.T) {
	started := make(chan struct{})
	allowRead := make(chan struct{})
	bodyRead := make(chan []byte, 1)

	transport := &Transport{
		transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			close(started)
			<-allowRead
			expectedLen := 5 + 1 + UVarintLen(uint64(len("hello"))) + len("hello")
			buf := make([]byte, expectedLen)
			if _, err := io.ReadFull(req.Body, buf); err != nil {
				return nil, err
			}
			bodyRead <- buf
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       &testReadCloser{closeCh: make(chan struct{})},
				Request:    req,
			}, nil
		}),
		cfg:    &Config{Host: "example.com:443"},
		ctx:    context.Background(),
		cancel: func() {},
	}

	conn, err := transport.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	<-started

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("hello"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("initial Write blocked until RoundTrip started reading")
	}

	close(allowRead)

	select {
	case got := <-bodyRead:
		if len(got) == 0 {
			t.Fatal("RoundTrip did not receive the buffered payload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RoundTrip did not receive the buffered payload")
	}
}
