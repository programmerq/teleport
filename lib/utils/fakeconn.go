/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/trace"
	"github.com/pborman/uuid"

	"github.com/sirupsen/logrus"
)

// PipeNetConn implemetns net.Conn from io.Reader,io.Writer and io.Closer
type PipeNetConn struct {
	reader     io.Reader
	writer     io.Writer
	closer     io.Closer
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewPipeNetConn returns a net.Conn like object
// using Pipe as an underlying implementation over reader, writer and closer
func NewPipeNetConn(reader io.Reader,
	writer io.Writer,
	closer io.Closer,
	fakelocalAddr net.Addr,
	fakeRemoteAddr net.Addr) *PipeNetConn {

	return &PipeNetConn{
		reader:     reader,
		writer:     writer,
		closer:     closer,
		localAddr:  fakelocalAddr,
		remoteAddr: fakeRemoteAddr,
	}
}

func (nc *PipeNetConn) Read(buf []byte) (n int, e error) {
	return nc.reader.Read(buf)
}

func (nc *PipeNetConn) Write(buf []byte) (n int, e error) {
	return nc.writer.Write(buf)
}

func (nc *PipeNetConn) Close() error {
	if nc.closer != nil {
		return nc.closer.Close()
	}
	return nil
}

func (nc *PipeNetConn) LocalAddr() net.Addr {
	return nc.localAddr
}

func (nc *PipeNetConn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

func (nc *PipeNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (nc *PipeNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (nc *PipeNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// DualPipeAddrConn creates a net.Pipe to connect a client and a server. The
// two net.Conn instances are wrapped in an addrConn which holds the source and
// destination addresses.
func DualPipeNetConn(srcAddr net.Addr, dstAddr net.Addr) (*PipeNetConn, *PipeNetConn) {
	server, client := net.Pipe()

	serverConn := NewPipeNetConn(server, server, server, dstAddr, srcAddr)
	clientConn := NewPipeNetConn(client, client, client, srcAddr, dstAddr)

	return serverConn, clientConn
}

// NewChConn returns a new net.Conn implemented over
// SSH channel
func NewChConn(conn ssh.Conn, ch ssh.Channel) *ChConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &ChConn{
		data:   make(chan []byte),
		read:   make(chan readRequest),
		ctx:    ctx,
		cancel: cancel,
		id:     uuid.New(),
	}
	c.Channel = ch
	c.conn = conn
	go c.begin()
	return c
}

// NewExclusiveChConn returns a new net.Conn implemented over
// SSH channel, whenever this connection closes
func NewExclusiveChConn(conn ssh.Conn, ch ssh.Channel) *ChConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &ChConn{
		exclusive: true,
		data:      make(chan []byte),
		read:      make(chan readRequest),
		ctx:       ctx,
		cancel:    cancel,
	}
	c.Channel = ch
	c.conn = conn
	go c.begin()
	return c
}

// ChConn is a net.Conn like object
// that uses SSH channel
type ChConn struct {
	mu sync.Mutex

	ssh.Channel
	conn ssh.Conn
	// exclusive indicates that whenever this channel connection
	// is getting closed, the underlying connection is closed as well
	exclusive bool

	readDeadline time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	data         chan []byte
	read         chan readRequest
	err          error
	id           string
	buf          []byte
}

// UseTunnel makes a channel request asking for the type of connection. If
// the other side does not respond (older cluster) or takes to long to
// respond, be on the safe side and assume it's not a tunnel connection.
func (c *ChConn) UseTunnel() bool {
	responseCh := make(chan bool, 1)

	go func() {
		ok, err := c.SendRequest(ConnectionTypeRequest, true, nil)
		if err != nil {
			responseCh <- false
			return
		}
		responseCh <- ok
	}()

	select {
	case response := <-responseCh:
		return response
	case <-time.After(1 * time.Second):
		logrus.Debugf("Timed out waiting for response: returning false.")
		return false
	}
}

// Close closes channel and if the ChConn is exclusive, connection as well
func (c *ChConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.Channel.Close()
	if !c.exclusive {
		return trace.Wrap(err)
	}
	err2 := c.conn.Close()
	return trace.NewAggregate(err, err2)
}

// LocalAddr returns a local address of a connection
// Uses underlying net.Conn implementation
func (c *ChConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns a remote address of a connection
// Uses underlying net.Conn implementation
func (c *ChConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets a connection deadline
// ignored for the channel connection
func (c *ChConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return trace.Wrap(err)
	}
	if err := c.SetWriteDeadline(t); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// SetReadDeadline sets a connection read deadline
// ignored for the channel connection
func (c *ChConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Printf("======= SETTING READ DEADLINE TO %v %v\n", t, c.id)
	if !t.IsZero() && t.Before(time.Now()) {
		fmt.Println("===== CANCELING READS IN PROGRESS", c.id)
		c.cancel()
	} else if !t.IsZero() {
		//c.ctx, c.cancel = context.WithDeadline(context.Background(), t)
	} else {
		fmt.Println("===== RESETTING DEADLINE", c.id)
		c.ctx, c.cancel = context.WithCancel(context.Background())
	}
	//c.readDeadline = t
	return nil
}

type readResult struct {
	n   int
	err error
}

type readRequest struct {
	len   int
	dataC chan []byte
	ctx   context.Context
	id    string
	t     time.Time
}

func (c *ChConn) Read(data []byte) (int, error) {
	// see if we have anything in the buffer
	if len(c.buf) > 0 {
		n := len(c.buf)
		copy(data, c.buf)
		c.buf = []byte{}
		return n, nil
	}

	c.mu.Lock()
	ctx := c.ctx
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		fmt.Println("====== READ DEADLINE WHILE WAITING FOR DATA")
		return 0, os.ErrDeadlineExceeded
	case d, ok := <-c.data:
		if !ok {
			return 0, c.err
		}
		fmt.Printf("len(data) == %v, cap(data) == %v, len(d) == %v, cap(d) == %v\n", len(data), cap(data), len(d), cap(d))
		if len(d) > len(data) {
			copy(data, d[:len(data)])
			// save the remainder in the buffer
			c.buf = d[len(data):]
			return len(data), nil
		}
		copy(data, d)
		return len(d), nil
	}
}

func (c *ChConn) begin() {
	buf := make([]byte, 2048)
	for {
		n, err := c.Channel.Read(buf)
		if err != nil {
			c.err = err
			close(c.data)
			return
		}
		tmp := make([]byte, n)
		copy(tmp, buf[:n])
		c.data <- tmp
	}
}

// func (c *ChConn) Read(data []byte) (int, error) {
// 	id := uuid.New()
// 	now := time.Now()
// 	fmt.Println("===> HERE 0", c.id, id, time.Since(now))
// 	c.mu.Lock()
// 	ctx := c.ctx
// 	c.mu.Unlock()
// 	// defer fmt.Println("====== READ DONE")
// 	// if c.readDeadline.IsZero() || c.readDeadline.After(time.Now()) {
// 	// 	fmt.Println("====== READING...")
// 	// 	return c.Channel.Read(data)
// 	// }
// 	// fmt.Println("====== READ DEADLINE")
// 	// return 0, trace.BadParameter("deadline")
// 	// res := make(chan readResult, 1)
// 	// buf := make([]byte, len(data))
// 	// go func() {
// 	// 	n, err := c.Channel.Read(buf)
// 	// 	res <- readResult{n, err}
// 	// 	close(res)
// 	// }()

// 	readReq := readRequest{
// 		len:   len(data),
// 		dataC: make(chan []byte, 1),
// 		id:    id,
// 		t:     now,
// 		//ctx:   ctx,
// 	}
// 	fmt.Println("===> HERE 1", c.id, id, time.Since(now))
// 	select {
// 	case <-ctx.Done():
// 		fmt.Println("====== READ DEADLINE WHILE SENDING READ REQ", c.id, id, time.Since(now))
// 		return 0, os.ErrDeadlineExceeded
// 	case c.read <- readReq:
// 		fmt.Println("===> HERE 2", c.id, id, time.Since(now))
// 	}
// 	select {
// 	case <-ctx.Done():
// 		fmt.Println("====== READ DEADLINE WHILE WAITING FOR DATA", c.id, id, time.Since(now))
// 		return 0, os.ErrDeadlineExceeded
// 		// case r := <-res:
// 		// 	fmt.Printf("len(data) == %v, cap(data) == %v, r.n == %v\n", len(data), cap(data), r.n)
// 		// 	copy(data, buf)
// 		// 	return r.n, r.err
// 	case d, ok := <-readReq.dataC:
// 		fmt.Println("===> HERE 3", c.id, id, time.Since(now))
// 		if !ok {
// 			fmt.Println("===> HERE 3 ERROR", c.id, id, time.Since(now), c.err)
// 			return 0, c.err
// 		}
// 		fmt.Printf("len(data) == %v, cap(data) == %v, len(d) == %v, cap(d) == %v %v %v\n", len(data), cap(data), len(d), cap(d), c.id, id)
// 		copy(data, d)
// 		fmt.Println("===> HERE 4 COMPLETED", c.id, id, time.Since(now))
// 		return len(d), nil
// 		// case d, ok := <-c.data:
// 		// 	if !ok {
// 		// 		return 0, c.err
// 		// 	}
// 		// 	fmt.Printf("len(data) == %v, cap(data) == %v, len(d) == %v, cap(d) == %v\n", len(data), cap(data), len(d), cap(d))
// 		// 	copy(data, d)
// 		// 	return len(d), nil
// 	}
// }

// func (c *ChConn) begin() {
// 	for {
// 		fmt.Println("===> READ 1", c.id)
// 		readReq := <-c.read
// 		fmt.Println("===> READ 2", c.id, readReq.id, time.Since(readReq.t))
// 		buf := make([]byte, readReq.len)
// 		n, err := c.Channel.Read(buf)
// 		fmt.Println("===> READ 3", c.id, readReq.id, time.Since(readReq.t))
// 		if err != nil {
// 			fmt.Println("===> READ 4", c.id, readReq.id, time.Since(readReq.t), err)
// 			c.err = err
// 			close(c.data)
// 			return
// 		}
// 		tmp := make([]byte, n)
// 		copy(tmp, buf[:n])
// 		fmt.Println("===> READ 5", c.id, readReq.id, time.Since(readReq.t))
// 		readReq.dataC <- tmp
// 		fmt.Println("===> READ 6", c.id, readReq.id, time.Since(readReq.t))
// 		// select {
// 		// case :
// 		// case <-readReq.ctx.Done():
// 		// 	continue
// 		// }
// 	}
// }

// SetWriteDeadline sets write deadline on a connection
// ignored for the channel connection
func (c *ChConn) SetWriteDeadline(t time.Time) error {
	return nil
}

const (
	// ConnectionTypeRequest is a request sent over a SSH channel that returns a
	// boolean which indicates the connection type (direct or tunnel).
	ConnectionTypeRequest = "x-teleport-connection-type"
)
