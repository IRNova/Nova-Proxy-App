package main

import (
	"fmt"
)

func writeCoreMarker(execDir, name, detail string) {
	// disabled: avoiding writing markers to disk per user request
}

func markerDetail(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
