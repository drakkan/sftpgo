// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
		Conn:           c,
		ReadTimeout:    l.ReadTimeout,
		WriteTimeout:   l.WriteTimeout,
		ReadThreshold:  int32((l.ReadTimeout * 1024) / time.Second),
		WriteThreshold: int32((l.WriteTimeout * 1024) / time.Second),
	}
	tc.BytesReadFromDeadline.Store(0)
	tc.BytesWrittenFromDeadline.Store(0)
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
	BytesReadFromDeadline    atomic.Int32
	BytesWrittenFromDeadline atomic.Int32
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.BytesReadFromDeadline.Load() > c.ReadThreshold {
		c.BytesReadFromDeadline.Store(0)
		// we set both read and write deadlines here otherwise after the request
		// is read writing the response fails with an i/o timeout error
		err = c.Conn.SetDeadline(time.Now().Add(c.ReadTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = c.Conn.Read(b)
	c.BytesReadFromDeadline.Add(int32(n))
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.BytesWrittenFromDeadline.Load() > c.WriteThreshold {
		c.BytesWrittenFromDeadline.Store(0)
		// we extend the read deadline too, not sure it's necessary,
		// but it doesn't hurt
		err = c.Conn.SetDeadline(time.Now().Add(c.WriteTimeout))
		if err != nil {
			return
		}
	}
	n, err = c.Conn.Write(b)
	c.BytesWrittenFromDeadline.Add(int32(n))
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
