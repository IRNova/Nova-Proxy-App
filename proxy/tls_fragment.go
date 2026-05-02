package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	tlsRecordHeaderLen       = 5
	tlsHandshakeRecord       = 22
	tlsFragmentReadWait      = 10 * time.Second
	defaultTLSRFNumRecords   = 4
	defaultTLSRFNumSegments  = 1
	defaultTLSRFSendInterval = 50 * time.Millisecond
	defaultTLSRFModMinorVer  = true
	defaultTLSRFOOB          = false
	defaultTLSRFOOBEx        = false
)

func (p *ProxyServer) handleTLSFragment(clientConn, upstreamConn net.Conn, host string, rule Rule) {
	p.tracef("[TLS-RF] Handling %s via upstream %s", host, rule.Upstream)

	record, err := readInitialTLSRecord(clientConn)
	if err != nil {
		p.tracef("[TLS-RF] Failed to read initial TLS record for %s: %v", host, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	_, sniPos, sniLen, _, err := parseClientHello(record)
	if err != nil {
		p.tracef("[TLS-RF] Parse ClientHello failed for %s: %v", host, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	if sniPos <= 0 || sniLen <= 0 {
		if _, err := upstreamConn.Write(record); err != nil {
			p.tracef("[TLS-RF] Initial passthrough write failed for %s: %v", host, err)
			clientConn.Close()
			upstreamConn.Close()
			return
		}
		p.tracef("[TLS-RF] No SNI in ClientHello for %s, forwarded directly", host)
		p.directTunnel(clientConn, upstreamConn)
		return
	}

	// Save original ClientHello for potential fallback (sendRecords modifies in-place)
	hasFallback := rule.FallbackMode != ""
	var savedRecord []byte
	if hasFallback {
		savedRecord = make([]byte, len(record))
		copy(savedRecord, record)
	}

	err = sendRecords(
		upstreamConn,
		record,
		sniPos,
		sniLen,
		defaultTLSRFNumRecords,
		defaultTLSRFNumSegments,
		defaultTLSRFOOB,
		defaultTLSRFOOBEx,
		defaultTLSRFModMinorVer,
		defaultTLSRFSendInterval,
	)
	if err != nil {
		p.tracef("[TLS-RF] Fragmented send failed for %s: %v", host, err)
		upstreamConn.Close()

		if hasFallback {
			p.handleTLSRFFallback(clientConn, host, rule, savedRecord)
			return
		}
		clientConn.Close()
		return
	}

	// If fallback is configured, probe that upstream is alive before tunneling.
	// GFW typically RSTs the connection after seeing fragmented ClientHello.
	if hasFallback {
		_ = upstreamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		probe := make([]byte, 1)
		_, probeErr := upstreamConn.Read(probe)
		_ = upstreamConn.SetReadDeadline(time.Time{})

		if probeErr != nil {
			p.tracef("[TLS-RF] Upstream probe failed for %s: %v; trying fallback %s", host, probeErr, rule.FallbackMode)
			upstreamConn.Close()
			p.handleTLSRFFallback(clientConn, host, rule, savedRecord)
			return
		}
		// Prepend the probed byte back into the read stream
		wrappedUp := &bufferedReadConn{
			Conn:   upstreamConn,
			reader: io.MultiReader(bytes.NewReader(probe), upstreamConn),
		}
		p.tracef("[TLS-RF] ClientHello OK for %s", host)
		p.directTunnel(clientConn, wrappedUp)
		return
	}

	p.tracef("[TLS-RF] ClientHello sent in original-style fragments for %s", host)
	p.directTunnel(clientConn, upstreamConn)
}

// handleTLSRFFallback retries a failed TLS-RF connection through the fallback
// transport (Warp SOCKS5 or Server), sending the original un-fragmented
// ClientHello through the new connection.
func (p *ProxyServer) handleTLSRFFallback(clientConn net.Conn, host string, rule Rule, originalRecord []byte) {
	p.tracef("[TLS-RF] Fallback via %s for %s", rule.FallbackMode, host)

	targetAddr := net.JoinHostPort(host, "443")

	p.mu.RLock()
	warpMgr := p.warpMgr
	rules := p.rules
	p.mu.RUnlock()

	var cfConfig CloudflareConfig
	var serverHost string
	if rules != nil {
		cfConfig = rules.GetCloudflareConfig()
		serverHost = rules.GetServerHost()
	}

	newConn, err := DialFallback(rule.FallbackMode, targetAddr, warpMgr, cfConfig, serverHost)
	if err != nil {
		p.tracef("[TLS-RF] Fallback %s dial failed for %s: %v", rule.FallbackMode, host, err)
		clientConn.Close()
		return
	}

	// Send original ClientHello un-fragmented through the protected transport
	if _, err := newConn.Write(originalRecord); err != nil {
		p.tracef("[TLS-RF] Fallback write ClientHello failed for %s: %v", host, err)
		newConn.Close()
		clientConn.Close()
		return
	}

	p.tracef("[TLS-RF] Fallback %s succeeded for %s", rule.FallbackMode, host)
	p.directTunnel(clientConn, newConn)
}

func readInitialTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, tlsRecordHeaderLen)
	_ = conn.SetReadDeadline(time.Now().Add(tlsFragmentReadWait))
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	record := make([]byte, tlsRecordHeaderLen+recordLen)
	copy(record, header)
	if recordLen > 0 {
		if _, err := io.ReadFull(conn, record[tlsRecordHeaderLen:]); err != nil {
			return nil, err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return record, nil
}

func findLastDot(data []byte, sniPos, sniLen int) (offset int, found bool) {
	for i := sniPos + sniLen; i >= sniPos; i-- {
		if data[i] == '.' {
			return i, true
		}
	}
	return sniLen/2 + sniPos, false
}

func parseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error) {
	const (
		handshakeHeaderLen       = 4
		handshakeTypeClientHello = 0x01
		extTypeSNI               = 0x0000
		extTypeKeyShare          = 0x0033
	)

	prtVer = nil
	sniPos = -1
	sniLen = 0

	if len(data) < tlsRecordHeaderLen {
		return prtVer, sniPos, sniLen, false, errors.New("TLS record too short")
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < tlsRecordHeaderLen+recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("record length exceeds data size")
	}
	offset := tlsRecordHeaderLen

	if recordLen < handshakeHeaderLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake message too short")
	}
	if data[offset] != handshakeTypeClientHello {
		return prtVer, sniPos, sniLen, false, fmt.Errorf("not a ClientHello handshake (type=%d)", data[offset])
	}
	handshakeLen := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	if handshakeLen+handshakeHeaderLen > recordLen {
		return prtVer, sniPos, sniLen, false, errors.New("handshake length exceeds record length")
	}
	offset += handshakeHeaderLen

	if handshakeLen < 2+32+1 {
		return prtVer, sniPos, sniLen, false, errors.New("ClientHello too short for mandatory fields")
	}
	prtVer = data[offset : offset+2]
	offset += 2
	offset += 32
	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("unexpected end after Random")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("session_id length exceeds data")
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cipher_suites exceed data")
	}
	offset += csLen

	if offset >= len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("cannot read compression_methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("compression_methods exceed data")
	}
	offset += compMethodsLen

	if offset+2 > len(data) {
		return prtVer, sniPos, sniLen, false, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extTotalLen > len(data) {
		return prtVer, sniPos, sniLen, false, errors.New("extensions length exceeds data")
	}
	extensionsEnd := offset + extTotalLen

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extDataStart := offset + 4
		extDataEnd := extDataStart + extLen

		if extDataEnd > extensionsEnd {
			return prtVer, sniPos, sniLen, false, errors.New("extension length exceeds extensions block")
		}

		if extType == extTypeKeyShare {
			hasKeyShare = true
			if sniPos != -1 {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}

		if sniPos == -1 && extType == extTypeSNI {
			if extLen < 2 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("malformed SNI extension")
			}
			listLen := int(binary.BigEndian.Uint16(data[extDataStart : extDataStart+2]))
			if listLen+2 != extLen {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI list length field mismatch")
			}
			cursor := extDataStart + 2
			if cursor+3 > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI entry too short")
			}
			if data[cursor] != 0 {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("unsupported SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(data[cursor+1 : cursor+3]))
			nameStart := cursor + 3
			nameEnd := nameStart + nameLen
			if nameEnd > extDataEnd {
				return prtVer, sniPos, sniLen, hasKeyShare, errors.New("SNI name length exceeds extension")
			}
			sniPos = nameStart
			sniLen = nameLen
			if hasKeyShare {
				return prtVer, sniPos, sniLen, hasKeyShare, nil
			}
		}
		offset = extDataEnd
	}
	return prtVer, sniPos, sniLen, hasKeyShare, nil
}

func sendRecords(conn net.Conn, clientHello []byte, offset, length, records, segments int, oob, oobex, modMinorVer bool, interval time.Duration) error {
	if modMinorVer && len(clientHello) >= 3 {
		clientHello[2] = 0x04
	}

	if records == 1 {
		if oobex {
			if err := sendWithOOB(conn, clientHello[:15], clientHello[15]); err != nil {
				return wrap("oob 1", err)
			}
			if err := sendWithOOB(conn, clientHello[16:20], 0x0); err != nil {
				return wrap("oob 2", err)
			}
			if interval > 0 {
				time.Sleep(interval)
			}
			clientHello = clientHello[20:]
		}
		if segments == 1 {
			if _, err := conn.Write(clientHello); err != nil {
				return wrap("send remaining data", err)
			}
			return nil
		}
		leftSegments := segments / 2
		rightSegments := segments - leftSegments
		packets := make([][]byte, 0, segments)
		cut, _ := findLastDot(clientHello, offset-20, length)
		splitAndAppend(clientHello[:cut], nil, leftSegments, &packets)
		splitAndAppend(clientHello[cut:], nil, rightSegments, &packets)
		for i, packet := range packets {
			if i == 0 && oob {
				if err := sendWithOOB(conn, packet, 0x0); err != nil {
					return wrap("oob", err)
				}
			} else {
				if _, err := conn.Write(packet); err != nil {
					return wrap("write packet "+strconv.Itoa(i+1), err)
				}
			}
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		return nil
	}

	leftChunks := records / 2
	rightChunks := records - leftChunks
	chunks := make([][]byte, 0, records)
	cut, _ := findLastDot(clientHello, offset, length)
	header := clientHello[:3]
	splitAndAppend(clientHello[5:cut], header, leftChunks, &chunks)
	splitAndAppend(clientHello[cut:], header, rightChunks, &chunks)

	if segments == -1 {
		for i, chunk := range chunks {
			if i == 0 {
				if oob {
					if err := sendWithOOB(conn, chunk, 0x0); err != nil {
						return wrap("oob", err)
					}
					if interval > 0 {
						time.Sleep(interval)
					}
				} else if oobex {
					l := len(chunk)
					if err := sendWithOOB(conn, chunk[:l-1], chunk[l-1]); err != nil {
						return wrap("oob 1", err)
					}
				}
			} else if i == 1 && oobex {
				if err := sendWithOOB(conn, chunk, 0x0); err != nil {
					return wrap("oob 2", err)
				}
			} else {
				if _, err := conn.Write(chunk); err != nil {
					return wrap("write record "+strconv.Itoa(i+1), err)
				}
				if interval > 0 {
					time.Sleep(interval)
				}
			}
		}
		return nil
	}

	merged := make([]byte, 0, records*5+len(clientHello))
	for _, c := range chunks {
		merged = append(merged, c...)
	}

	if oobex {
		if err := sendWithOOB(conn, merged[:15], merged[15]); err != nil {
			return wrap("oob 1", err)
		}
		if err := sendWithOOB(conn, merged[16:20], 0x0); err != nil {
			return wrap("oob 2", err)
		}
		if interval > 0 {
			time.Sleep(interval)
		}
		merged = merged[20:]
	}
	if segments == 1 || len(merged) <= segments {
		_, err := conn.Write(merged)
		return err
	}

	base := len(merged) / segments
	for i := 0; i < segments; i++ {
		start := i * base
		end := start + base
		if i == segments-1 {
			end = len(merged)
		}
		if i == 0 && oob {
			if err := sendWithOOB(conn, merged[start:end], 0x0); err != nil {
				return wrap("oob", err)
			}
		} else {
			if _, err := conn.Write(merged[start:end]); err != nil {
				return wrap("write segment "+strconv.Itoa(i+1), err)
			}
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func splitAndAppend(data, header []byte, n int, result *[][]byte) {
	if n <= 0 {
		return
	}
	addHeader := header != nil
	if n == 1 || len(data) < n {
		if addHeader {
			*result = append(*result, makeRecord(header, data))
		} else {
			*result = append(*result, data)
		}
		return
	}
	base := len(data) / n
	for i := 0; i < n; i++ {
		var part []byte
		if i == n-1 {
			part = data[i*base:]
		} else {
			part = data[i*base : (i+1)*base]
		}
		if addHeader {
			*result = append(*result, makeRecord(header, part))
		} else {
			*result = append(*result, part)
		}
	}
}

func makeRecord(header, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	copy(rec[:3], header)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

func getRawConn(conn net.Conn) (syscall.RawConn, error) {
	rawConnProvider, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support raw access")
	}
	return rawConnProvider.SyscallConn()
}

type wrappedError struct {
	msg   string
	cause error
}

func (e *wrappedError) Error() string {
	return e.msg + ": " + e.cause.Error()
}

func (e *wrappedError) Unwarp() error {
	return e.cause
}

func wrap(msg string, cause error) error {
	return &wrappedError{
		msg:   msg,
		cause: cause,
	}
}

func isUseOfClosedConn(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed")
}
