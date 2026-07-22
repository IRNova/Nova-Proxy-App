//go:build !desktop

package main

import (
	"fmt"
	"os"

	"github.com/TheCanniball/CipherGate/src/core"
)

func runDesktop(cfg *core.Config) {
	fmt.Fprintln(os.Stderr, "desktop mode requires build with: go build -tags desktop")
	os.Exit(1)
}
