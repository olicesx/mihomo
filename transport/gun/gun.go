// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/httputils"
	"github.com/metacubex/mihomo/common/pool"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrSmallBuffer   = errors.New("buffer too small")
)

var defaultHeader = http.Header{
	"Content-Type": []string{"application/grpc"},
	"User-Agent":   []string{"grpc-go/1.36.0"},
}

// Keep a bounded steady-state backlog once the HTTP/2 transport starts reading
// request bodies. Startup writes are buffered independently so they never have
// to wait for RoundTrip to begin consuming the request body.
const requestBodyBufferSize = 256 * 1024

const (
	defaultMaxConnections = 8
	defaultMinStreams     = 5
)

type DialFn = func(ctx context.Context, network, addr string) (net.Conn, error)

type Conn struct {
	initFn func(addr *httputils.NetAddr) (io.ReadCloser, error)
	writer io.Writer // writer must not nil
	closer io.Closer
	httputils.NetAddr

	initOnce sync.Once
	initErr  error
	reader   io.ReadCloser
	remain   int

	closeMutex sync.Mutex
	closed     bool
	onClose    func()

	deadlineMutex sync.Mutex
	deadlineTimer connTimer
	deadlineSeq   uint64
}

type connTimer interface {
	Stop() bool
}

var newConnTimer = func(d time.Duration, f func()) connTimer {
	return time.AfterFunc(d, f)
}

type requestBodyPipe struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	started bool
	closed  bool
	readErr error
	maxSize int
}

func newRequestBodyPipe(maxSize int) *requestBodyPipe {
	p := &requestBodyPipe{maxSize: maxSize}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *requestBodyPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.started = true
	p.cond.Broadcast()

	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}

	if len(p.buf) == 0 {
		if p.readErr != nil {
			return 0, p.readErr
		}
		return 0, io.EOF
	}

	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	p.cond.Broadcast()
	return n, nil
}

func (p *requestBodyPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	written := 0
	for written < len(b) {
		if p.closed {
			return written, io.ErrClosedPipe
		}

		space := len(b) - written
		if p.started {
			for len(p.buf) >= p.maxSize && !p.closed {
				p.cond.Wait()
			}
			if p.closed {
				return written, io.ErrClosedPipe
			}
			space = p.maxSize - len(p.buf)
			if space > len(b)-written {
				space = len(b) - written
			}
		}
		p.buf = append(p.buf, b[written:written+space]...)
		written += space
		p.cond.Broadcast()
	}

	return len(b), nil
}

func (p *requestBodyPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	p.readErr = io.EOF
	p.cond.Broadcast()
	return nil
}

type Config struct {
	ServiceName  string
	UserAgent    string
	Host         string
	PingInterval int
}

func (g *Conn) initReader() {
	reader, err := g.initFn(&g.NetAddr)
	if err != nil {
		g.initErr = err
		if closer, ok := g.writer.(io.Closer); ok {
			closer.Close()
		}
		return
	}

	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed { // if g.Close() be called between g.initFn(), direct close the initFn returned reader
		_ = reader.Close()
		g.initErr = net.ErrClosed
		return
	}

	g.reader = reader
}

func (g *Conn) Init() error {
	g.closeMutex.Lock()
	closed := g.closed
	if closed && g.initErr == nil {
		g.initErr = net.ErrClosed
	}
	g.closeMutex.Unlock()
	if closed {
		return g.initErr
	}
	g.initOnce.Do(g.initReader)
	return g.initErr
}

func (g *Conn) Read(b []byte) (n int, err error) {
	if err = g.Init(); err != nil {
		return
	}
	return g.read(b)
}

func (g *Conn) read(b []byte) (n int, err error) {
	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = g.reader.Read(b[:size])
		g.remain -= n
		return
	}

	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	var discard [6]byte
	_, err = io.ReadFull(g.reader, discard[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return 0, err
	}

	protobufPayloadLen, err := ReadUVariant(g.reader)
	if err != nil {
		return 0, ErrInvalidLength
	}
	g.remain = int(protobufPayloadLen)
	return g.read(b)
}

func (g *Conn) Write(b []byte) (n int, err error) {
	dataLen := len(b)
	varLen := UVarintLen(uint64(dataLen))
	buf := pool.Get(5 + 1 + varLen + dataLen)
	defer pool.Put(buf)
	_ = buf[6] // bounds check hint to compiler
	buf[0] = 0x00
	binary.BigEndian.PutUint32(buf[1:5], uint32(1+varLen+dataLen))
	buf[5] = 0x0A
	binary.PutUvarint(buf[6:], uint64(dataLen))
	copy(buf[6+varLen:], b)

	_, err = g.writer.Write(buf)
	if err == io.ErrClosedPipe {
		if initErr := g.Init(); initErr != nil {
			err = initErr
		}
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return len(b), err
}

func (g *Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	varLen := UVarintLen(uint64(dataLen))
	header := buffer.ExtendHeader(6 + varLen)
	_ = header[6] // bounds check hint to compiler
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], uint32(1+varLen+dataLen))
	header[5] = 0x0A
	binary.PutUvarint(header[6:], uint64(dataLen))
	_, err := g.writer.Write(buffer.Bytes())

	if err == io.ErrClosedPipe {
		if initErr := g.Init(); initErr != nil {
			err = initErr
		}
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return err
}

func (g *Conn) FrontHeadroom() int {
	return 6 + binary.MaxVarintLen64
}

func (g *Conn) Close() error {
	g.deadlineMutex.Lock()
	g.deadlineSeq++
	if timer := g.deadlineTimer; timer != nil {
		_ = timer.Stop()
		g.deadlineTimer = nil
	}
	g.deadlineMutex.Unlock()

	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true

	var errorArr []error

	if closer, ok := g.writer.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if reader := g.reader; reader != nil {
		if err := reader.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if closer := g.closer; closer != nil {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if g.onClose != nil {
		g.onClose()
	}

	return errors.Join(errorArr...)
}

func (g *Conn) SetReadDeadline(t time.Time) error  { return g.SetDeadline(t) }
func (g *Conn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

func (g *Conn) SetDeadline(t time.Time) error {
	g.deadlineMutex.Lock()
	defer g.deadlineMutex.Unlock()

	g.deadlineSeq++
	if timer := g.deadlineTimer; timer != nil {
		_ = timer.Stop()
		g.deadlineTimer = nil
	}

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		go g.Close()
		return nil
	}

	seq := g.deadlineSeq
	var timer connTimer
	timer = newConnTimer(d, func() {
		g.deadlineMutex.Lock()
		if g.deadlineSeq != seq || g.deadlineTimer != timer {
			g.deadlineMutex.Unlock()
			return
		}
		g.deadlineTimer = nil
		g.deadlineMutex.Unlock()
		_ = g.Close()
	})
	g.deadlineTimer = timer
	return nil
}

type Transport struct {
	transport http.RoundTripper
	cfg       *Config
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	count     atomic.Int64
}

func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		httputils.CloseTransport(t.transport)
	})
	return nil
}

func NewTransport(dialFn DialFn, tlsConfig *vmess.TLSConfig, gunCfg *Config) *Transport {
	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
		defer cancel()
		pconn, err := dialFn(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		if tlsConfig == nil {
			return pconn, nil
		}

		conn, err := vmess.StreamTLSConn(ctx, pconn, tlsConfig)
		if err != nil {
			_ = pconn.Close()
			return nil, err
		}

		if tlsConfig.Reality == nil { // reality doesn't return the negotiated ALPN
			state := tlsC.GetTLSConnectionState(conn)
			if p := state.NegotiatedProtocol; p != http.Http2NextProtoTLS {
				_ = conn.Close()
				return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http.Http2NextProtoTLS)
			}
		}
		return conn, nil
	}

	transport := &http.Http2Transport{
		DialTLSContext:     dialFunc,
		AllowHTTP:          false,
		DisableCompression: true,
		ReadIdleTimeout:    time.Duration(gunCfg.PingInterval) * time.Second, // If zero, no health check is performed
		PingTimeout:        0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	wrap := &Transport{
		transport: transport,
		cfg:       gunCfg,
		ctx:       ctx,
		cancel:    cancel,
	}
	return wrap
}

func ServiceNameToPath(serviceName string) string {
	if strings.HasPrefix(serviceName, "/") { // custom paths
		return serviceName
	}
	return "/" + serviceName + "/Tun"
}

func (t *Transport) Dial() (net.Conn, error) {
	serviceName := "GunService"
	if t.cfg.ServiceName != "" {
		serviceName = t.cfg.ServiceName
	}
	path := ServiceNameToPath(serviceName)

	body := newRequestBodyPipe(requestBodyBufferSize)

	header := defaultHeader.Clone()
	if t.cfg.UserAgent != "" {
		header.Set("User-Agent", t.cfg.UserAgent)
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body:   body,
		URL: &url.URL{
			Scheme: "https",
			Host:   t.cfg.Host,
			Path:   path,
			// for unescape path
			Opaque: "//" + t.cfg.Host + path,
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     header,
	}
	request = request.WithContext(t.ctx)

	conn := &Conn{
		initFn: func(addr *httputils.NetAddr) (io.ReadCloser, error) {
			request = request.WithContext(httputils.NewAddrContext(addr, request.Context()))
			response, err := t.transport.RoundTrip(request)
			if err != nil {
				return nil, err
			}
			return response.Body, nil
		},
		writer: body,
	}

	t.count.Add(1)
	conn.onClose = func() { t.count.Add(-1) }

	go conn.Init()

	return conn, nil
}

type Client struct {
	mutex          sync.Mutex
	maxConnections int
	minStreams     int
	maxStreams     int
	transports     []*Transport
	maker          func() *Transport
}

func NewClient(maker func() *Transport, maxConnections, minStreams, maxStreams int) *Client {
	if maxConnections == 0 && minStreams == 0 && maxStreams == 0 {
		maxConnections = defaultMaxConnections
		minStreams = defaultMinStreams
	}
	return &Client{
		maxConnections: maxConnections,
		minStreams:     minStreams,
		maxStreams:     maxStreams,
		maker:          maker,
	}
}

func (c *Client) Dial() (net.Conn, error) {
	return c.getTransport().Dial()
}

func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var errs []error
	for _, t := range c.transports {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.transports = nil
	return errors.Join(errs...)
}

func (c *Client) getTransport() *Transport {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var transport *Transport
	for _, t := range c.transports {
		if transport == nil || t.count.Load() < transport.count.Load() {
			transport = t
		}
	}
	if transport == nil {
		return c.newTransportLocked()
	}
	numStreams := int(transport.count.Load())
	if numStreams == 0 {
		return transport
	}
	if c.maxConnections > 0 {
		if len(c.transports) >= c.maxConnections || numStreams < c.minStreams {
			return transport
		}
	} else {
		if c.maxStreams > 0 && numStreams < c.maxStreams {
			return transport
		}
	}
	return c.newTransportLocked()
}

func (c *Client) newTransportLocked() *Transport {
	transport := c.maker()
	c.transports = append(c.transports, transport)
	return transport
}

func StreamGunWithConn(conn net.Conn, tlsConfig *vmess.TLSConfig, gunCfg *Config) (net.Conn, error) {
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewTransport(dialFn, tlsConfig, gunCfg)
	c, err := transport.Dial()
	if err != nil {
		return nil, err
	}
	if c, ok := c.(*Conn); ok { // The incoming net.Conn should be closed synchronously with the generated gun.Conn
		c.closer = conn
	}
	return c, nil
}
