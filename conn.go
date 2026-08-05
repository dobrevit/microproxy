package microproxy

import (
	"net"
	"time"
)

// timedConn applies a deadline to every read and write, so that a connection
// whose peer has gone away without saying so is eventually released rather than
// held for as long as the process lives.
//
// A non-positive timeout leaves the corresponding deadline alone.
type timedConn struct {
	net.Conn

	readTimeout  time.Duration
	writeTimeout time.Duration
}

// newTimedConn wraps conn, unless neither timeout is in force.
func newTimedConn(conn net.Conn, readTimeout, writeTimeout time.Duration) net.Conn {
	if readTimeout <= 0 && writeTimeout <= 0 {
		return conn
	}

	return timedConn{Conn: conn, readTimeout: readTimeout, writeTimeout: writeTimeout}
}

func (c timedConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, err
		}
	}

	return c.Conn.Read(b)
}

// CloseWrite forwards the half-close a relayed connection needs to tell its
// peer that it has finished sending without dropping what is still coming back.
func (c timedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}

	return c.Conn.SetWriteDeadline(time.Now())
}

func (c timedConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		if err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return 0, err
		}
	}

	return c.Conn.Write(b)
}
