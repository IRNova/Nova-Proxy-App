package main

import (
	"sync"
)

// ringLogWriter is a fixed-size ring buffer for log capture.
type ringLogWriter struct {
	mu    sync.Mutex
	buf   []string
	pos   int
	count int
	size  int
}

func newRingLogWriter(size int) *ringLogWriter {
	return &ringLogWriter{
		buf:  make([]string, size),
		size: size,
	}
}

func (w *ringLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf[w.pos] = string(p)
	w.pos = (w.pos + 1) % w.size
	if w.count < w.size {
		w.count++
	}
	return len(p), nil
}

func (w *ringLogWriter) Snapshot(limit int) []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := limit
	if n <= 0 || n > w.count {
		n = w.count
	}
	out := make([]string, n)
	if w.count < w.size {
		// Not wrapped yet
		copy(out, w.buf[:w.count])
		return out
	}
	// Wrapped: read from pos to end, then 0 to pos
	start := w.pos
	for i := 0; i < n; i++ {
		out[i] = w.buf[(start+i)%w.size]
	}
	return out
}

func (w *ringLogWriter) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pos = 0
	w.count = 0
}
