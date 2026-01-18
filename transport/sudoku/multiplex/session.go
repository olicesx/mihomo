package multiplex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	frameOpen  byte = 0x01
	frameData  byte = 0x02
	frameClose byte = 0x03
	frameReset byte = 0x04
)

const (
	headerSize     = 1 + 4 + 4  // frameType(1) + streamID(4) + length(4)
	maxFrameSize   = 256 * 1024 // max frame payload size
	maxDataPayload = 32 * 1024  // max data payload per frame
	streamChanSize = 64         // buffered channel size for read queue
)

type acceptEvent struct {
	stream  *stream
	payload []byte
}

// Session manages a multiplex session over a single connection
type Session struct {
	conn net.Conn

	writeMu sync.Mutex

	// RWMutex optimizes for read-heavy scenarios
	streamsMu sync.RWMutex
	streams   map[uint32]*stream
	nextID    uint32

	acceptCh chan acceptEvent

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewClientSession creates a client-side multiplex session
func NewClientSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s := &Session{
		conn:    conn,
		streams: make(map[uint32]*stream),
		closed:  make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

// NewServerSession creates a server-side multiplex session
func NewServerSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s := &Session{
		conn:     conn,
		streams:  make(map[uint32]*stream),
		acceptCh: make(chan acceptEvent, 256),
		closed:   make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

// IsClosed returns true if the session has been closed
func (s *Session) IsClosed() bool {
	if s == nil {
		return true
	}
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// closeWithError closes the session with the specified error
func (s *Session) closeWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closeOnce.Do(func() {
		s.streamsMu.Lock()
		s.closeErr = err
		// close all streams but keep the map for error reporting
		for _, st := range s.streams {
			st.close(err)
		}
		s.streamsMu.Unlock()

		close(s.closed)
		_ = s.conn.Close()
	})
}

// Close closes the session
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeWithError(io.ErrClosedPipe)
	return nil
}

// getCloseErr returns the error that caused the session to close
func (s *Session) getCloseErr() error {
	s.streamsMu.RLock()
	err := s.closeErr
	s.streamsMu.RUnlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (s *Session) registerStream(st *stream) {
	s.streamsMu.Lock()
	s.streams[st.id] = st
	s.streamsMu.Unlock()
}

func (s *Session) getStream(id uint32) *stream {
	s.streamsMu.RLock()
	st := s.streams[id]
	s.streamsMu.RUnlock()
	return st
}

func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *Session) nextStreamID() uint32 {
	s.streamsMu.Lock()
	s.nextID++
	id := s.nextID
	if id == 0 { // skip 0
		s.nextID++
		id = s.nextID
	}
	s.streamsMu.Unlock()
	return id
}

func (s *Session) sendFrame(frameType byte, streamID uint32, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("mux payload too large: %d", len(payload))
	}

	var header [headerSize]byte
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := writeFull(s.conn, header[:]); err != nil {
		s.closeWithError(err)
		return err
	}
	if len(payload) > 0 {
		if err := writeFull(s.conn, payload); err != nil {
			s.closeWithError(err)
			return err
		}
	}
	return nil
}

func (s *Session) sendReset(streamID uint32, msg string) {
	if msg == "" {
		msg = "reset"
	}
	_ = s.sendFrame(frameReset, streamID, []byte(msg))
	_ = s.sendFrame(frameClose, streamID, nil)
}

// OpenStream opens a new stream with optional initial payload
func (s *Session) OpenStream(openPayload []byte) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("nil session")
	}
	if s.IsClosed() {
		return nil, s.getCloseErr()
	}

	streamID := s.nextStreamID()
	st := newStream(s, streamID)
	s.registerStream(st)

	if err := s.sendFrame(frameOpen, streamID, openPayload); err != nil {
		st.close(err)
		s.removeStream(streamID)
		return nil, fmt.Errorf("mux open failed: %w", err)
	}
	return st, nil
}

// AcceptStream accepts a new stream (server-side only)
func (s *Session) AcceptStream() (net.Conn, []byte, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil session")
	}
	if s.acceptCh == nil {
		return nil, nil, fmt.Errorf("accept is not supported on client sessions")
	}
	select {
	case ev := <-s.acceptCh:
		return ev.stream, ev.payload, nil
	case <-s.closed:
		return nil, nil, s.getCloseErr()
	}
}

// readLoop reads and processes multiplex frames from the connection
func (s *Session) readLoop() {
	var header [headerSize]byte
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.closeWithError(err)
			return
		}
		frameType := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		n := int(binary.BigEndian.Uint32(header[5:9]))
		if n < 0 || n > maxFrameSize {
			s.closeWithError(fmt.Errorf("invalid mux frame length: %d", n))
			return
		}

		var payload []byte
		if n > 0 {
			payload = make([]byte, n)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWithError(err)
				return
			}
		}

		switch frameType {
		case frameOpen:
			if s.acceptCh == nil {
				s.sendReset(streamID, "unexpected open")
				continue
			}
			if streamID == 0 {
				s.sendReset(streamID, "invalid stream id")
				continue
			}
			if s.getStream(streamID) != nil {
				s.sendReset(streamID, "stream already exists")
				continue
			}
			st := newStream(s, streamID)
			s.registerStream(st)
			// send directly to acceptCh, no goroutine needed
			select {
			case s.acceptCh <- acceptEvent{stream: st, payload: payload}:
			case <-s.closed:
				st.close(io.ErrClosedPipe)
				s.removeStream(streamID)
			}

		case frameData:
			st := s.getStream(streamID)
			if st == nil || len(payload) == 0 {
				continue
			}
			st.enqueue(payload)

		case frameClose:
			st := s.getStream(streamID)
			if st != nil {
				st.close(io.EOF)
				s.removeStream(streamID)
			}

		case frameReset:
			st := s.getStream(streamID)
			if st != nil {
				msg := trimASCII(payload)
				if msg == "" {
					msg = "reset"
				}
				st.close(errors.New(msg))
				s.removeStream(streamID)
			}

		default:
			s.closeWithError(fmt.Errorf("unknown mux frame type: %d", frameType))
			return
		}
	}
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func trimASCII(b []byte) string {
	i := 0
	j := len(b)
	for i < j {
		c := b[i]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		i++
	}
	for j > i {
		c := b[j-1]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		j--
	}
	if i >= j {
		return ""
	}
	out := make([]byte, j-i)
	copy(out, b[i:j])
	return string(out)
}

// stream represents a single stream in the multiplex session
type stream struct {
	session *Session
	id      uint32

	mu       sync.Mutex
	closed   bool
	closeErr error
	readCh   chan []byte // buffered channel for incoming data
	readBuf  []byte      // partial read buffer for unconsumed data

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newStream(session *Session, id uint32) *stream {
	return &stream{
		session:    session,
		id:         id,
		readCh:     make(chan []byte, streamChanSize),
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}
}

func (c *stream) enqueue(payload []byte) {
	// defensive: recover from sending to closed channel
	defer func() {
		if recover() != nil {
			// channel was closed, do nothing
		}
	}()

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return
	}

	// copy payload to avoid data race with caller
	data := make([]byte, len(payload))
	copy(data, payload)

	// try non-blocking send first (fast path)
	select {
	case c.readCh <- data:
		return
	default:
	}

	// slow path: channel full, wait with session close check
	// this prevents head-of-line blocking from affecting entire session
	select {
	case c.readCh <- data:
	case <-c.session.closed:
	}
}

func (c *stream) close(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true
	c.closeErr = err
	c.readBuf = nil // clear any buffered data
	close(c.readCh) // notify all waiting readers
}

func (c *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.mu.Lock()
	// consume any leftover data from previous partial read
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		if n < len(c.readBuf) {
			c.readBuf = c.readBuf[n:]
		} else {
			c.readBuf = nil
		}
		c.mu.Unlock()
		return n, nil
	}
	closed := c.closed
	closeErr := c.closeErr
	c.mu.Unlock()

	if closed {
		return 0, closeErr
	}

	// block until data arrives or channel is closed
	data, ok := <-c.readCh
	if !ok {
		// channel closed, return the close error
		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		// store remaining data for next read
		c.mu.Lock()
		c.readBuf = data[n:]
		c.mu.Unlock()
	}
	return n, nil
}

func (c *stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// check if stream is closed
	c.mu.Lock()
	closed := c.closed
	closeErr := c.closeErr
	c.mu.Unlock()

	if closed {
		return 0, closeErr
	}

	// check if session is closed
	if c.session.IsClosed() {
		return 0, c.session.getCloseErr()
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxDataPayload {
			chunk = p[:maxDataPayload]
		}
		if err := c.session.sendFrame(frameData, c.id, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *stream) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	c.closeErr = io.ErrClosedPipe
	close(c.readCh)

	_ = c.session.sendFrame(frameClose, c.id, nil)
	c.session.removeStream(c.id)
	return nil
}

func (c *stream) LocalAddr() net.Addr  { return c.localAddr }
func (c *stream) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *stream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}
func (c *stream) SetReadDeadline(time.Time) error  { return nil }
func (c *stream) SetWriteDeadline(time.Time) error { return nil }
