package main

import "io"

type bestEffortMultiWriter struct {
	writers []io.Writer
}

func newBestEffortMultiWriter(writers ...io.Writer) io.Writer {
	filtered := make([]io.Writer, 0, len(writers))
	for _, writer := range writers {
		if writer != nil {
			filtered = append(filtered, writer)
		}
	}
	return &bestEffortMultiWriter{writers: filtered}
}

func (w *bestEffortMultiWriter) Write(p []byte) (int, error) {
	for _, writer := range w.writers {
		_, _ = writer.Write(p)
	}
	return len(p), nil
}
