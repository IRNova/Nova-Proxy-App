package main

import (
	"io"
)

// bestEffortMultiWriter writes to all writers, ignoring errors from individual ones.
type bestEffortMultiWriter struct {
	writers []io.Writer
}

func newBestEffortMultiWriter(writers ...io.Writer) *bestEffortMultiWriter {
	return &bestEffortMultiWriter{writers: writers}
}

func (w *bestEffortMultiWriter) Write(p []byte) (int, error) {
	for _, wr := range w.writers {
		wr.Write(p)
	}
	return len(p), nil
}
