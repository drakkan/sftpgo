package util

import (
	"net"
	"sync/atomic"
	"time"
)

type listener struct {
	net.Listener
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &Conn{
		Conn:                     c,
		ReadTimeout:              l.ReadTimeout,
		WriteTimeout:             l.WriteTimeout,
		ReadThreshold:            int32((l.ReadTimeout * 1024) / time.Second),
		WriteThreshold:           int32((l.WriteTimeout * 1024) / time.Second),
		BytesReadFromDeadline:    0,
		BytesWrittenFromDeadline: 0,
	}
	return tc, nil
}

// Conn wraps a net.Conn, and sets a deadline for every read
// and write operation.
type Conn struct {
	net.Conn
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
	ReadThreshold            int32
	WriteThreshold           int32
	BytesReadFromDeadline    int32
	BytesWrittenFromDeadline int32
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.BytesReadFromDeadline) > c.ReadThreshold {
		atomic.StoreInt32(&c.BytesReadFromDeadline, 0)
		// we set both read and write deadlines here otherwise after the request
		// is read writing the response fails with an i/o timeout error
		err = c.Conn.SetDeadline(time.Now().Add(c.ReadTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = c.Conn.Read(b)
	atomic.AddInt32(&c.BytesReadFromDeadline, int32(n))
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.BytesWrittenFromDeadline) > c.WriteThreshold {
		atomic.StoreInt32(&c.BytesWrittenFromDeadline, 0)
		// we extend the read deadline too, not sure it's necessary,
		// but it doesn't hurt
		err = c.Conn.SetDeadline(time.Now().Add(c.WriteTimeout))
		if err != nil {
			return
		}
	}
	n, err = c.Conn.Write(b)
	atomic.AddInt32(&c.BytesWrittenFromDeadline, int32(n))
	return
}

func newListener(network, addr string, readTimeout, writeTimeout time.Duration) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	tl := &listener{
		Listener:     l,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}
	return tl, nil
}
