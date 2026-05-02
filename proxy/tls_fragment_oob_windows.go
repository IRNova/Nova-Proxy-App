//go:build windows

package proxy

import (
	"net"

	"golang.org/x/sys/windows"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}

	var toSend []byte
	if data == nil {
		toSend = []byte{oob}
	} else {
		toSend = make([]byte, len(data)+1)
		copy(toSend, data)
		toSend[len(data)] = oob
	}
	wsabuf := windows.WSABuf{
		Len: uint32(len(toSend)),
		Buf: &toSend[0],
	}
	var n uint32
	var innerErr error
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = windows.WSASend(
			windows.Handle(fd),
			&wsabuf,
			1,
			&n,
			windows.MSG_OOB,
			nil,
			nil,
		)
		return innerErr != windows.WSAEWOULDBLOCK
	})
	if err != nil {
		return wrap("rawConn.Write", err)
	}
	if innerErr != nil && innerErr != windows.NOERROR {
		return wrap("WSASend (MSG_OOB)", innerErr)
	}
	return nil
}
