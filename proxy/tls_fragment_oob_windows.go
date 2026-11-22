// Third-party notice: this file contains material shared with historical
// MIT-licensed SniShaper source. The following grant covers that material,
// without assigning other authors' contributions to SniShaper.
//
// MIT License
//
// Copyright (c) 2026 SniShaper
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
