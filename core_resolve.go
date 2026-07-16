package main

import (
	"os"
	"path/filepath"
)

// resolveRuntimeFile returns the absolute path, trying several base directories.
func resolveRuntimeFile(execDir, relPath string) string {
	candidates := []string{
		filepath.Join(execDir, relPath),
		filepath.Join(execDir, "..", "data", filepath.Base(filepath.Dir(filepath.Dir(relPath))), filepath.Base(relPath)),
		relPath,
	}

	for _, c := range candidates {
		c = filepath.Clean(c)
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// Default: return first candidate
	return filepath.Clean(filepath.Join(execDir, relPath))
}
